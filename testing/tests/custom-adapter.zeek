# Test log adaptation outside of exporters, via the log_adapter() hook.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-logschema.json

@load ./testlog
@load ./secondlog
@load logschema/export/json

hook Log::Schema::adapt(logs: Log::Schema::LogsTable)
	{
	# Remove everything but the Testlog's "a" field:
	delete logs[Second::LOG];

	local log = logs[Testlog::LOG];
	local todos: vector of string;
	local name: string;

	for ( name, field in log$fields )
		{
		if ( name != "a" )
			todos += name;
		}

	for ( _, name in todos )
		delete log$fields[name];

	# And make up another one:
	log$fields["fake"] = Log::Schema::Field(
	    $name = "fake",
	    $_type = "string",
	    $record_type = "Testlog::Info",
	);
	}
