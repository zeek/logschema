# A log whose record contains both a required and an &optional nested record,
# for testing that optionality propagates to unfolded sub-fields. conn_id is a
# real built-in Zeek record type, so its sub-fields (orig_h, orig_p, resp_h,
# resp_p) get unfolded into dotted field names in the log.

@load ./common

module Optrecordlog;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## A required nested record. Its unfolded sub-fields are required.
		id: conn_id &log;

		## An optional nested record. Its unfolded sub-fields must be
		## reported as optional, since the whole record may be absent.
		id2: conn_id &optional &log;

		## A plain required scalar, for contrast.
		s: string &log;
	};
}

event zeek_init()
	{
	# Remove any registered log streams. Copy the table to avoid iterator
	# invalidation problems that can lead to remaining entries.
	for ( id in copy(Log::active_streams) )
		Log::disable_stream(id);

	Log::create_stream(LOG, [$columns=Info, $path="optrecord"]);
	}
