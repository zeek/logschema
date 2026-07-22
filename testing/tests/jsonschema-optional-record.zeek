# Test that an &optional nested record's unfolded sub-fields are NOT listed as
# required, while a required nested record's sub-fields are. Regression test for
# optionality propagation through record unfolding.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-optrecord-log.schema.json

@load ./optrecordlog
@load logschema/export/jsonschema
