# Test directing output to stdout.
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT >stdout 2>stderr
# @TEST-EXEC: btest-diff stdout
# @TEST-EXEC: btest-diff stderr

@load ./testlog
@load ./secondlog
@load logschema/export/csv

redef Log::Schema::CSV::filename = "-";
