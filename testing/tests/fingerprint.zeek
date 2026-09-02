# Test the fingerprinting feature. This uses testlog and secondlog in various
# combinations that do/don't affect the fingerprint.
#
# @TEST-EXEC: zeek -b %INPUT >stdout
# @TEST-EXEC: btest-diff stdout

@load ./testlog
@load ./secondlog
@load logschema/fingerprint


# @TEST-START-NEXT
# Create the logs in a different order: should not matter, same as first test.

@load ./testlog
@load ./secondlog
@load logschema/fingerprint

event zeek_init() &priority=-10
	{
	for ( id in copy(Log::active_streams) )
		Log::disable_stream(id);

	Log::create_stream(Second::LOG, [$columns=Second::Info, $path="second"]);
	Log::create_stream(Testlog::LOG, [$columns=Testlog::Info, $path="test"]);
	}

# @TEST-START-NEXT
# Create the logs with different names: should matter.

@load ./testlog
@load ./secondlog
@load logschema/fingerprint

event zeek_init() &priority=-10
	{
	for ( id in copy(Log::active_streams) )
		Log::disable_stream(id);

	Log::create_stream(Second::LOG, [$columns=Second::Info, $path="notsecond"]);
	Log::create_stream(Testlog::LOG, [$columns=Testlog::Info, $path="test"]);
	}

# @TEST-START-NEXT
# Create the second log with a different docstring and default value:
# should not matter, same as first test.

@load ./testlog
@load logschema/fingerprint

module Second;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## A different docstring.
		a: addr &log &default=127.0.0.1;
	};
}

event zeek_init() &priority=-10
	{
	Log::create_stream(LOG, [$columns=Info, $path="second"]);
	}

# @TEST-START-NEXT
# A two-field log that we're about to fingerprint again below, with swapped fields.

@load ./common
@load logschema/fingerprint

module Testlog;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## An address.
		a: addr &log;

		## A boolean.
		b: bool &log;
	};
}

event zeek_init() &priority=-10
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	}

# @TEST-START-NEXT
# The two-field log with swapped fields: that should matter.

@load ./common
@load logschema/fingerprint

module Testlog;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## A boolean.
		b: bool &log;

		## An address.
		a: addr &log;
	};
}

event zeek_init() &priority=-10
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	}

# @TEST-START-NEXT
# The two-field log with swapped field names but not types: should matter too.

@load ./common
@load logschema/fingerprint

module Testlog;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## An address.
		b: addr &log;

		## A boolean.
		a: bool &log;
	};
}

event zeek_init() &priority=-10
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	}
