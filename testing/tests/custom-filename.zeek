# Test additional substitutions in schema file names.
#
# @TEST-EXEC: FILENAME="zeek-{filter}.json" zeek -b %INPUT >result
# @TEST-EXEC: test -f zeek-$(grep '^filter:' result | cut -d' ' -f2).json
#
# @TEST-EXEC: FILENAME="zeek-{pid}.json" zeek -b %INPUT >result
# @TEST-EXEC: test -f zeek-$(grep '^pid:' result | cut -d' ' -f2).json
#
# @TEST-EXEC: FILENAME="zeek-{version}.json" zeek -b %INPUT >result
# @TEST-EXEC: test -f zeek-$(grep '^version:' result | cut -d' ' -f2).json
#
# @TEST-EXEC: FILENAME="zeek-%F.json" zeek -b %INPUT >result
# @TEST-EXEC: test -f zeek-$(grep '^isodate:' result | cut -d' ' -f2).json

@load testlog
@load logschema/export/json

redef Log::Schema::JSON::filename = getenv("FILENAME");

event zeek_init()
	{
	print fmt("filter: %s", Log::Schema::logfilter);
	print fmt("pid: %s", getpid());
	print fmt("version: %s", zeek_version());
	print strftime("isodate: %F", current_time());
	}
