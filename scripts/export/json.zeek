##! A minimal export: this just takes the internal field and log representations
##! this package builds up during processing and writes them directly as
##! JSON. It's the closest to logging Zeek's internal knowledge of log fields
##! as-is.

module Log::Schema::JSON;

@load ..

export {
	## A filename to write the JSON rendering to. When this is "-" or empty,
	## the export writes to stdout. By default this writes a single JSON
	## object with Log::IDs as keys and log information as values. When
	## using the "{log}" substitution, each log instead gets written to its
	## own file. See Log::Schema::create_filename() for supported
	## substitutions.
	const filename = "zeek-logschema.json" &redef;
}

function write_all_schemas(hdl: file, ex: Log::Schema::Exporter, logs: Log::Schema::LogsTable)
	{
	write_file(hdl, to_json(logs));
	}

function write_single_schema(hdl: file, ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	write_file(hdl, to_json(log));
	}

event zeek_init()
	{
	Log::Schema::add_exporter(Log::Schema::Exporter(
	    $name = "json",
	    $filename = filename,
	    $write_all_schemas = write_all_schemas,
	    $write_single_schema = write_single_schema,
	));
	}
