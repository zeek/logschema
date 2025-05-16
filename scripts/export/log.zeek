module Log::Schema::Log;

@load ..

export {
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## A record representing all fields in a log. If this were a "normal"
	## Zeek log, this would be called "Info".
	type Field: record {
		log: string; ##< Name of the log, e.g. "conn"
		field: string; ##< Name of the field, e.g "uid"
		_type: string; ##< Zeek type of the field (e.g. "string", "addr", "bool")
		record_type: string;  ##< Record type containing this field (e.g. "Conn::Info", "conn_id").
		is_optional: bool &optional;  ##< Whether the field is optional.
		_default: string &optional;  ##< Default value of the field, if defined. Stringified since "any" and logging do not get along.
		docstring: string &optional;  ##< If available, the docstring for the field.
		script: string &optional;  ##< Script that defines the field, relative to the scripts folder (e.g. "base/init-bare.zeek").
		package: string &optional;  ##< If part of a Zeek package, the package's name sans owner ("hello-world", not "zeek/hello-world").
	} &log;

	type Export: record {
		fields: vector of Field;
	};

	## Event that can be handled to access the Field
	## record as it is sent on to the logging framework.
	global log_logfield: event(rec: Field);
}

global field_name_map: table[string] of string = table(
	["_type"] = "type",
	["_default"] = "default",
);

redef record Log::Schema::Log += {
	log_export: Export &optional;
};

function process_log(ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	local log_export = Export();
	local log_field: Field;

	for ( _, field in log$fields )
		{
		log_field = Field(
		    $log=log$name,
		    $field=field$name,
		    $_type=field$_type,
		    $record_type=field$record_type);

		if ( field?$is_optional )
			log_field$is_optional = field$is_optional;
		if ( field?$_default )
			log_field$_default = cat(field$_default);
		if ( field?$docstring )
			log_field$docstring = field$docstring;
		if ( field?$script )
			log_field$script = field$script;
		if ( field?$package )
			log_field$package = field$package;

		log_export$fields += log_field;
		}

	log$log_export = log_export;
	}

function custom_export(ex: Log::Schema::Exporter, logs: Log::Schema::LogsTable)
	{
	for ( _, log in logs )
		for ( _, field in log$log_export$fields )
			Log::write(LOG, field);
	}

event zeek_init()
	{
	Log::Schema::add_exporter(Log::Schema::Exporter(
	    $name = "log",
	    $process_log = process_log,
	    $custom_export = custom_export,
	));

	Log::create_stream(LOG, [$columns=Field, $ev=log_logfield, $path="logschema", $policy=log_policy]);
	}
