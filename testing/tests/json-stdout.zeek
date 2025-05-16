# Test directing output to stdout.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT >stdout 2>stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff stdout
# @TEST-EXEC: btest-diff stderr

@load ./testlog
@load ./secondlog
@load logschema/export/json

redef Log::Schema::JSON::filename = "-";
