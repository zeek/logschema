@load ./common

module Testlog;

export {
	redef enum Log::ID += { LOG };

	# A record we'd use for logging, with a bunch of types.
	type Info: record {
		## A timestamp.
		t: time &log;
	};
}

event zeek_init()
	{
	# Remove any registered log streams. Copy the table to avoid iterator
	# invalidation problems that can lead to remaining entries.
	for ( id in copy(Log::active_streams) )
		Log::disable_stream(id);

	# Testing focuses on a log for the above record, only.
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	}
