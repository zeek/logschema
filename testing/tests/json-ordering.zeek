# Tests the ordering of log fields and logs in the resulting output.
# Logs should be alphabetical, log fields should be as in the
# underlying record.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: jq '.[].name' zeek-logschema.json >logs
# @TEST-EXEC: jq '.[] | select(.name=="test").fields | .[].name' zeek-logschema.json >fields
# @TEST-EXEC: btest-diff logs
# @TEST-EXEC: btest-diff fields

@load ./testlog
@load logschema/export/json

module A;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## An address.
		a: addr &log;
	};
}

module Z;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## An address.
		a: addr &log;
	};
}


event zeek_init() &priority=-1
	{
	# Via the above loads we have defined Testlog::LOG, so
	# with the two following additions we should have the
	# sorting requirement covered:
	Log::create_stream(Z::LOG, [$columns=Z::Info, $path="z"]);
	Log::create_stream(A::LOG, [$columns=A::Info, $path="a"]);
	}
