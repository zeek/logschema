# Test timestamp properties in the JSON Schema export.
# This tests formats common to all versions.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT Log::Schema::JSONSchema::add_zeek_annotations=F 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test-log.schema.json

@load ./timestamplog
@load logschema/export/jsonschema

redef LogAscii::json_timestamps = JSON::TS_EPOCH;

# @TEST-START-NEXT

@load ./timestamplog
@load logschema/export/jsonschema

redef LogAscii::json_timestamps = JSON::TS_ISO8601;
