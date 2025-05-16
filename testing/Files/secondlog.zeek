# An additional log, for testing.

module Second;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## An address.
		a: addr &log;
	};
}

event zeek_init() &priority=-1
	{
	Log::create_stream(Second::LOG, [$columns=Second::Info, $path="second"]);
	}
