# Test the CSV export. This writes to a single output file by default.
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: btest-diff zeek-logschema.csv

@load ./testlog
@load logschema/export/csv
