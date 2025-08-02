# Test timestamp properties in the JSON Schema export.
# Zeek 8 changed these a bit, so this only tests for pre-8.0.
#
# @TEST-REQUIRES: command -v jq
# @TEST-REQUIRES: ! zeek -b $FILES/8-or-newer.zeek
# @TEST-EXEC: zeek -b %INPUT Log::Schema::JSONSchema::add_zeek_annotations=F 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test-log.schema.json

@load ./timestamplog
@load logschema/export/jsonschema

redef LogAscii::json_timestamps = JSON::TS_MILLIS;
