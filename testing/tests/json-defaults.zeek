# Test the basic JSON export of schema information.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-logschema.json

@load ./testlog
@load logschema/export/json
