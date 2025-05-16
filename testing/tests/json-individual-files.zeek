# Test the basic JSON exporter's ability to write each log's schema to a
# separate file.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test.json
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-second.json

@load ./testlog
@load ./secondlog
@load logschema/export/json

redef Log::Schema::JSON::filename = "zeek-{log}.json";
