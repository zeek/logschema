##! A minimal export: this just takes the internal field and log representations
##! this package builds up during processing and writes them as JSON, with minor
##! massaging to avoid keying into tables with log names and field names to
##! avoid potential reordering problems. It's the closest to logging Zeek's
##! internal knowledge of log fields as-is.

module Log::Schema::JSON;

@load ..

export {
	## A light interpretation of Log::Schema::Log to provide fields sequentially:
	type Export: record {
		name: string;  ##< Name of the log in its short form (e.g. "conn").

		id: Log::ID; ##< The log's Log::ID enum.

		## Fields of that log, in order.
		fields: vector of Log::Schema::Field;
	};

	## A filename to write the JSON rendering to. When this is "-" or empty,
	## the export writes to stdout. By default this writes a single JSON
	## object with Log::IDs as keys and log information as values. When
	## using the "{log}" substitution, each log instead gets written to its
	## own file. See Log::Schema::create_filename() for supported
	## substitutions.
	const filename = "zeek-logschema.json" &redef;
}

redef record Log::Schema::Log += {
	json_export: Export &optional;
};

function process_log(ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	local jex = Export($name=log$name, $id=log$id);

	# The log$fields table is ordered, so this is reliable:
	for ( _, field in log$fields )
		{
		jex$fields += field;
		}

	log$json_export = jex;
	}

function write_all_schemas(hdl: file, ex: Log::Schema::Exporter, logs: Log::Schema::LogsTable)
	{
	local exps: vector of Export;

	# Similarly, the logs table passed in here is ordered as well.
	for ( _, log in logs )
		{
		exps += log$json_export;
		}

	write_file(hdl, to_json(exps));
	}

function write_single_schema(hdl: file, ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	write_file(hdl, to_json(log$json_export));
	}

event zeek_init()
	{
	Log::Schema::add_exporter(Log::Schema::Exporter(
	    $name = "json",
	    $filename = filename,
	    $process_log = process_log,
	    $write_all_schemas = write_all_schemas,
	    $write_single_schema = write_single_schema,
	));
	}
