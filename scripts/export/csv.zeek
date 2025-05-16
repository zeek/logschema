module Log::Schema::CSV;

@load ..

export {
	type Field: record {
		log: string; ##< Name of the log, e.g. "conn"
		field: string; ##< Name of the field, e.g "uid"
		_type: string; ##< Zeek type of the field (e.g. "string", "addr", "bool")
		record_type: string;  ##< Record type containing this field (e.g. "Conn::Info", "conn_id").
		is_optional: bool &optional;  ##< Whether the field is optional.
		_default: any &optional; ##< Default value of the field, if defined.
		docstring: string &optional;  ##< If available, the docstring for the field.
		script: string &optional;  ##< Script that defines the field, relative to the scripts folder (e.g. "base/init-bare.zeek").
		package: string &optional;  ##< If part of a Zeek package, the package's name sans owner ("hello-world", not "zeek/hello-world").
	};

	# Per-log state we keep for CSV-Suitable representation of the schema.
	type Export: record {
		fields: vector of Field;
	};

	## The CSV field separator.
	const separator = "," &redef;

	## String to use for an unset &optional field.
	const unset_field = "-" &redef;

	## Whether to include a header line explaining the fields.
	const add_header = T &redef;

	## A filename to write each log's schema to. When this is "-" or empty,
	## the export writes all schemas to stdout, in alphabetical order, with
	## one line per schema. See Log::Schema::create_filename() for supported
	## substitutions.
	const filename = "zeek-logschema.csv" &redef;
}

redef record Log::Schema::Log += {
	csv_export: Export &optional;
};

function process_log(ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	local csv_export = Export();
	local csv_field: Field;

	for ( _, field in log$fields )
		{
		csv_field = Field(
		    $log=log$name,
		    $field=field$name,
		    $_type=field$_type,
		    $record_type=field$record_type);

		if ( field?$is_optional )
			csv_field$is_optional = field$is_optional;
		if ( field?$_default )
			csv_field$_default = field$_default;
		if ( field?$docstring )
			csv_field$docstring = field$docstring;
		if ( field?$script )
			csv_field$script = field$script;
		if ( field?$package )
			csv_field$package = field$package;

		csv_export$fields += csv_field;
		}

	log$csv_export = csv_export;
	}

function write_header(hdl: file)
	{
	local s: vector of string; # Each CSV row's fields prior to joining.

	if ( ! add_header )
		return;

	for ( _, rfield in Log::Schema::get_record_fields("Log::Schema::CSV::Field", F) )
		s[|s|] = lstrip(rfield$name, "_");

	write_file(hdl, join_string_vec(s, separator));
	write_file(hdl, "\n");
	}

function csv_escape(input: string): string
	{
	# The escape character in CSV is '"', and tools like csvtool complain
	# when they encounter '\"'.
	return gsub(input, /\\\"/, "\"\"");

	# Surely other things will come up here. We currently keep newlines
	# escaped, though CSV recommends verbatim newlines in the output. Might
	# make that an option.
	}

function write_log(hdl: file, log: Log::Schema::Log)
	{
	local s: vector of string; # Each CSV row's fields prior to joining.

	for ( _, field in log$csv_export$fields )
		{
		s = vector();
		s += field$log;
		s += field$field;
		s += field$_type;
		s += field$record_type;
		s += field?$is_optional ? to_json(field$is_optional) : unset_field;

		# The default value is of type "any", which is tricky to deal with here.
		s += field?$_default ? csv_escape(to_json(field$_default)) : unset_field;

		# Also use JSON for the docstring, since it conveniently
		# escapes newlines so the result renders single-line.
		s += field?$docstring ? csv_escape(to_json(field$docstring)) : unset_field;

		s += field?$script ? field$script : unset_field;
		s += field?$package ? field$package : unset_field;

		write_file(hdl, join_string_vec(s, separator));
		write_file(hdl, "\n");
		}
	}

function write_all_schemas(hdl: file, ex: Log::Schema::Exporter, logs: Log::Schema::LogsTable)
	{
	write_header(hdl);

	for ( _, log in logs )
		write_log(hdl, log);
	}

function write_single_schema(hdl: file, ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	write_header(hdl);
	write_log(hdl, log);
	}

event zeek_init()
	{
	Log::Schema::add_exporter(Log::Schema::Exporter(
	    $name = "csv",
	    $filename = filename,
	    $process_log = process_log,
	    $write_all_schemas = write_all_schemas,
	    $write_single_schema = write_single_schema,
	));
	}
