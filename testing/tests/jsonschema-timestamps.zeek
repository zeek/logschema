# Test timestamp properties in the JSON Schema export.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT Log::Schema::JSONSchema::add_zeek_annotations=F 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test-log.schema.json

@load ./testlog
@load ./timestamp-only
@load logschema/export/jsonschema

redef LogAscii::json_timestamps = JSON::TS_EPOCH;

# @TEST-START-NEXT

@load ./testlog
@load ./timestamp-only
@load logschema/export/jsonschema

redef LogAscii::json_timestamps = JSON::TS_MILLIS;

# @TEST-START-NEXT

@load ./testlog
@load ./timestamp-only
@load logschema/export/jsonschema

redef LogAscii::json_timestamps = JSON::TS_MILLIS_UNSIGNED;

# @TEST-START-NEXT

@load ./testlog
@load ./timestamp-only
@load logschema/export/jsonschema

redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# @TEST-START-FILE timestamp-only.zeek
redef Log::Schema::logfilter = "custom";

event zeek_init()
	{
	Log::add_filter(Testlog::LOG, Log::Filter(
	    $name = "custom",
	    $include = set("t"), # Only report on the timestamp
	));
	}
# @TEST-END_FILE
