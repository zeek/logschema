# Verifies custom invocation of export at runtime.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-logschema.json

@load common
@load logschema/export/json

redef Log::Schema::run_at_startup = F;

module Latelog;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## An address.
		a: addr &log;
	};
}

event later()
	{
	# Create a new log at some point at runtime ...
	Log::create_stream(LOG, [$columns=Info, $path="late"]);

	# ... and then trigger the export.
	Log::Schema::run_export();
	}

event zeek_init()
	{
	# Remove any registered log streams. Copy the table to avoid iterator
	# invalidation problems that can lead to remaining entries.
	for ( id in copy(Log::active_streams) )
		Log::disable_stream(id);

	schedule 0 sec { later() };
	}
