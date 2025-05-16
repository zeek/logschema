@load ./common

module Testlog;

export {
	redef enum Log::ID += { LOG };

	# A record we'd use for logging, with a bunch of types.
	type Info: record {
		## An address. Also a comment with "quotation marks",
		## to verify escaping.
		a: addr &log;

		## A boolean.
		b: bool &log;

		## A count.
		c: count &log;

		## A double.
		d: double &log;

		## An enum.
		e: transport_proto &log;

		## An integer.
		i: int &log;

		## An interval.
		ival: interval &log;

		## A port.
		p: port &log;

		## A record.
		r: conn_id &log;

		## A set.
		st: set[count] &log;

		## A string.
		s: string &log;

		## A subnet.
		sub: subnet &log;

		## A timestamp.
		t: time &log;

		## A vector.
		v: vector of count &log;

		## A default value.
		sd: string &default="yes" &log;

		## An optional value.
		so: string &optional &log;

		# A logged field with a regular comment, not for Zeekygen,
		# and named such that alphabetical ordering would put it
		# a the top:
		aa_plaincomment: string &log;

		## A field that's not logged.
		notlogged: string;

		# Pattern, table, and any omitted since they can't be logged.
	};
}

event zeek_init()
	{
	# Remove any registered log streams. Copy the table to avoid iterator
	# invalidation problems that can lead to remaining entries.
	for ( id in copy(Log::active_streams) )
		Log::disable_stream(id);

	# Testing focuses on a log for the above record, only.
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	}
