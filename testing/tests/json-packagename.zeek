# @TEST-REQUIRES: command -v jq
#
# Establish some symlinks for additional paths to load this directory's content from:
# @TEST-EXEC: mkdir -p site/packages && ln -s $PWD site/packages/foobar
# @TEST-EXEC: mkdir -p site/otherpackages && ln -s $PWD site/otherpackages/foobar
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-logschema.json
#
# A common script to whittle the testlog down to just a single field.
@TEST-START-FILE shorten-testlog.zeek
redef Log::Schema::logfilter = "custom";

event zeek_init()
	{
	Log::add_filter(Testlog::LOG, Log::Filter(
	    $name = "custom",
	    $include = set("a"),
	));
	}
@TEST-END-FILE

# The first test adjusts nothing and should not produce a package name.
@load testlog
@load shorten-testlog
@load logschema/export/json


# @TEST-START-NEXT
# This test adjusts the load path for the test log so the default prefix
# leads to package name "foobar".

@load site/packages/foobar/testlog
@load shorten-testlog
@load logschema/export/json


# @TEST-START-NEXT
# This test uses a load path that wouldn't normally lead to a package
# name, but we adjust the set of prefixes to still yield "foobar".

@load site/otherpackages/foobar/testlog
@load shorten-testlog

redef Log::Schema::package_prefixes += "site/otherpackages";

@load logschema/export/json


# @TEST-START-NEXT
# Uses custom logic to determine a package name, unrelated to any file names.

@load site/otherpackages/foobar/testlog
@load shorten-testlog

hook Log::Schema::adapt(logs: Log::Schema::LogsTable)
	{
	for ( _, field in logs[Testlog::LOG]$fields )
		field$package = "custompackage";
	}

@load logschema/export/json
