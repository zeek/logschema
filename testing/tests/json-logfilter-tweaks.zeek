# Tests alterations to logging made by a logfilter, along with the selection of
# a different log filter than "default".
#
# @TEST-REQUIRES: command -v jq
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-logschema.json
#
# The first one tests include filters for fields.

@load ./testlog
@load logschema/export/json

redef Log::Schema::logfilter = "custom";

event zeek_init()
	{
	Log::add_filter(Testlog::LOG, Log::Filter(
	    $name = "custom",
	    $include = set("a", "b"),
	));
	}

# @TEST-START-NEXT
# Tests exclude filters for fields.

@load ./testlog
@load logschema/export/json

redef Log::Schema::logfilter = "custom";

event zeek_init()
	{
	Log::add_filter(Testlog::LOG, Log::Filter(
	    $name = "custom",
	    $exclude = set("a", "b", "c", "d", "e", "i"),
	));
	}

# @TEST-START-NEXT
# Tests field-name mapping.

@load ./testlog
@load logschema/export/json

redef Log::Schema::logfilter = "custom";

event zeek_init()
	{
	Log::add_filter(Testlog::LOG, Log::Filter(
	    $name = "custom",
	    $include = set("a", "b"),
	    $field_name_map = table(
	        ["a"] = "a_field",
	        ["b"] = "b_field",
	    ),
	));
	}

# @TEST-START-NEXT
# Tests a log extension function.

@load ./testlog
@load logschema/export/json

redef Log::Schema::logfilter = "custom";

type Extension: record {
	## A string.
	ext_s: string &log;
	## A count.
	ext_c: count &default=42 &log;
};

event zeek_init()
	{
	Log::add_filter(Testlog::LOG, Log::Filter(
	    $name = "custom",
	    $include = set("a", "b"),
	    $ext_func = function(path: string): Extension { return Extension($ext_s="ext"); },
	));
	}

# @TEST-START-NEXT
# Tests an adjusted field scope separator.

@load testlog
@load logschema/export/json

redef Log::default_scope_sep = "_";
redef Log::Schema::logfilter = "custom";

event zeek_init()
	{
	Log::add_filter(Testlog::LOG, Log::Filter(
	    $name = "custom",
	    $include = set("r_orig_h"),
	));
	}
