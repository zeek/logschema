# Test JSON Schema export for a record including a vector of enums.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test-log.schema.json

@load ./common
@load logschema/export/jsonschema

module Test;

export {
	redef enum Log::ID += { LOG };

	type Code: enum { A, B };

	type Info: record {
		as_set: set[Code] &log;
		as_vector: vector of Code &log;
	};
}

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Info, $path="test"]);
	}
