# Test directing output to stdout.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT >stdout 2>stderr
#
# The output should have two lines, one for each log.
# @TEST-EXEC: test $(cat stdout | wc -l) -eq 2
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff stdout
# @TEST-EXEC: btest-diff stderr

@load ./testlog
@load ./secondlog
@load logschema/export/jsonschema

redef Log::Schema::JSONSchema::filename = "-";
