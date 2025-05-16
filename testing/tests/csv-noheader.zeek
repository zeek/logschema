# Test the CSV export: disable header line normally written.
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: btest-diff zeek-logschema.csv

@load ./testlog
@load logschema/export/csv

redef Log::Schema::CSV::add_header = F;
