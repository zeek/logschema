# Verify that disabling automatic invocation at startup works.
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: ! test -f zeek-logschema.json

@load testlog
@load logschema/export/json

redef Log::Schema::run_at_startup = F;
