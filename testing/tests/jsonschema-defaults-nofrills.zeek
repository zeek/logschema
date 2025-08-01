# Test the JSON Schema export, with optional features disabled.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test-log.schema.json

@load ./testlog
@load logschema/export/jsonschema

redef Log::Schema::JSONSchema::add_zeek_annotations = F;
redef Log::Schema::JSONSchema::add_detailed_constraints = F;
redef Log::Schema::JSONSchema::add_examples = F;
