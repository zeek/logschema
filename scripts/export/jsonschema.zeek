module Log::Schema::JSONSchema;

@load ..

export {
	## Zeek-specific properties that don't fit into the JSON Schema
	## framework. We add these as a "x-zeek" annotation object in each
	## field's properties. For more on annotations, see:
	## https://json-schema.org/blog/posts/custom-annotations-will-continue
	type ZeekAnnotations: record {
		## The native Zeek type (addr, etc).
		_type: string;
		## Record type containing this field (e.g. "Conn::Info", "conn_id").
		record_type: string;
		## Whether the field is optional. This is itself optional since
		## it's not available before Zeek 6.
		is_optional: bool &optional;
		## Script that defines the field, relative to the scripts folder
		## (e.g. "base/init-bare.zeek"). This is optional because it's
		## not available before Zeek 6.0.
		script: string &optional;
		## If part of a Zeek package, the name of the package that provides
		## the field, sans owner ("hello-world", not "zeek/hello-world").
		package: string &optional;
	};

	# A helper type for tables collecting arbitrary values, to be turned
	# into JSON via to_json(). This allows more flexible field naming
	# than what's possible via Zeek records printed via to_json().
	type JSONTable: table[string] of any;

	# The JSON Schema representation of the schema data.
	type Export: record {
		schema: JSONTable &ordered; # The JSON structure of the resulting schema
	};

	# Define common keys for every schema.
	#
	# XXX this currently does not provide a $id URI. Given that the schemas
	# will vary from Zeek version to version and site to site, it's not
	# clear what this would provide, and we're not currently referring to
	# sub-schemas anywhere either.
	#
	# Careful: ordering works only when initializing via table(), not {} (zeek/zeek#4448).
	const schema_template: JSONTable = table(
		["$schema"] = "https://json-schema.org/draft/2020-12/schema",
		["title"] = "",
		["description"] = "",
		["type"] = "object",
		["properties"] = "",
		["required"] = "",
	) &ordered &redef;

	## A filename to write each log's schema to. When this is "-" or empty,
	## the export writes all schemas to stdout, in alphabetical order, with
	## one line per schema. For supported substitutions, see
	## Log::Schema::create_filename().
	const filename = "zeek-{log}-log.schema.json" &redef;

	## Whether to include the x-zeek annotation object in field properties.
	const add_zeek_annotations = T &redef;

	## Whether to include detailed constraints, such as the fact that
	## a count cannot be negative. Might not be required for a JSON schema
	## that's largely descriptive and not used for tight validation.
	const add_detailed_constraints = T &redef;
}

# Tuck each log's resulting schema onto the Log record:
redef record Log::Schema::Log += {
	jsonschema_export: Export &optional;
};

function sorted_enum_names(typ: string): vector of string
	{
	local names: vector of string;

	for ( name in enum_names(typ) )
		names[|names|] = name;

	sort(names, strcmp);
	return names;
	}

# Helper to parse the element type from sets and vectors.
# For example, for "vector of string", returns "string".
# Returns empty string in case of trouble.
function container_element_type(typ: string): string
	{
	local parts: string_vec;

	if ( /^set *\[/ in typ )
		{
		parts = split_string(typ, / *[\[\]] */);
		if ( |parts| < 2 )
			return "";
		return parts[1];
		}

	if ( /^vector / in typ )
		{
		parts = split_string(typ, / +/);
		if ( |parts| < 3 )
			return "";
		return parts[2];
		}

	return "";
	}

# For the given type name, adds the JSON-relevant type, or the full enum type
# description, to the property table. When the type is an enum, this enumerates
# the possible enum values, and omits the type, as per the JSON Schema spec.
# For timestamps, the mapping depends on the LogAscii::json_timestamps setting.
function property_fill_type(prop: JSONTable, typ: string)
	{
	local elem_type: string;
	local helper_table: JSONTable = table() &ordered;

	if ( /^(set *\[|vector )/ in typ )
		{
		prop["type"] = "array";
		elem_type = container_element_type(typ);
		if ( |elem_type| > 0 )
			{
			property_fill_type(helper_table, elem_type);
			prop["items"] = helper_table;
			}
		}
	else if ( typ == "count" )
		{
		prop["type"] = "integer";
		if ( add_detailed_constraints )
			prop["minimum"] = 0;
		}
	else if ( typ == "int" )
		prop["type"] = "integer";
	else if ( typ == "port" )
		{
		prop["type"] ="integer";
		if ( add_detailed_constraints )
			{
			prop["minimum"] = 0;
			prop["maximum"] = 65535;
			}
		}
	else if ( typ == "double" || typ == "interval" )
		prop["type"] ="number";
	else if ( typ == "string" || typ == "addr" || typ == "subnet" || typ == "pattern" )
		# XXX we could add format support here but it looks pretty limited
		# (e.g., distinguish addresses from subnets?):
		# https://www.learnjsonschema.com/2020-12/format-annotation/format/
		prop["type"] ="string";
	else if ( typ == "bool" )
		prop["type"] ="boolean";
	else if ( typ == "time" )
		{
		# This depends on the configured format for JSON timestamps.
		# XXX we should probably get this reflected in the schema.
		switch LogAscii::json_timestamps
			{
			case JSON::TS_EPOCH:
				# This is the default.
				prop["type"] = "number";
				break;
			case JSON::TS_MILLIS:
				prop["type"] = "integer";
				break;
			case JSON::TS_ISO8601:
				prop["type"] = "string";
				break;
			default:
				Reporter::warning(fmt("Unexpected JSON timestamp format: %s",
				    LogAscii::json_timestamps));
				break;
			}
		}
	else if ( /^enum / in typ )
		{
		# In JSON Schema enums list their possible values.
		# "type" is best not used in this case, according to:
		# https://www.learnjsonschema.com/2020-12/validation/enum/
		# "typ" here is "enum <type>", e.g. "enum transport_proto".
		prop["enum"] = sorted_enum_names(split_string1(typ, / /)[1]);
		}
	else
		Reporter::warning(fmt("Unexpected type string for JSON Schema mapping: %s", typ));
	}

function process_log(ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	local schema = copy(schema_template);
	schema["title"] = fmt("Schema for Zeek %s.log", log$name);
	schema["description"] = fmt("JSON Schema for Zeek %s.log", log$name);

	local properties: table[string] of JSONTable = table() &ordered;
	local required: vector of string = vector();

	for ( _, field in log$fields )
		{
		# We can't express the "x-zeek" annotation as a standard
		# Zeek record field name (to_json() would need some sort
		# of substitution logic to do so), so we express the whole
		# property as a table.
		local prop: JSONTable = table() &ordered;

		property_fill_type(prop, field$_type);

		if ( field?$docstring )
			prop["description"] = field$docstring;
		if ( field?$_default )
			prop["default"] = field$_default;
		if ( field?$is_optional && ! field$is_optional )
			required += field$name;

		# There are various keywords in JSON Schema that are
		# hard to cover here, like minItems, uniqueItems, that
		# are not explicitly captured in Zeek's log Info
		# records, so we skip those here. Some might be
		# universally true and we could set them here, for all
		# properties.

		if ( add_zeek_annotations )
			{
			local annos = ZeekAnnotations($_type=field$_type, $record_type=field$record_type);

			if ( field?$is_optional )
				annos$is_optional = field$is_optional;
			if ( field?$script )
				annos$script = field$script;
			if ( field?$package )
				annos$package = field$package;

			prop["x-zeek"] = annos;
			}

		properties[field$name] = prop;
		}

	schema["properties"] = properties;
	schema["required"] = required;

	log$jsonschema_export = Export($schema=schema);
	}

function write_all_schemas(hdl: file, ex: Log::Schema::Exporter, logs: Log::Schema::LogsTable)
	{
	for ( _, log in logs )
		{
		write_file(hdl, to_json(log$jsonschema_export$schema));
		}
	}

function write_single_schema(hdl: file, ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	write_file(hdl, to_json(log$jsonschema_export$schema));
	}

event zeek_init()
	{
	Log::Schema::add_exporter(Log::Schema::Exporter(
	    $name = "jsonschema",
	    $filename = filename,
	    $process_log = process_log,
	    $write_all_schemas = write_all_schemas,
	    $write_single_schema = write_single_schema,
	));
	}
