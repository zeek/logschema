# Test the CSV export. This writes to a single output file by default.
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: btest-diff zeek-test.csv
# @TEST-EXEC: btest-diff zeek-second.csv

@load ./testlog
@load ./secondlog
@load logschema/export/csv

redef Log::Schema::CSV::filename = "zeek-{log}.csv";
