# Test the export to a Zeek log.
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: btest-diff logschema.log

@load ./testlog
@load logschema/export/log

redef LogAscii::use_json = T;

event zeek_init() &priority=-1
	{
	# Loading testlog.zeek disabled all but our test log.
	# We need to get back the schema log:
	Log::enable_stream(Log::Schema::Log::LOG);
	}
