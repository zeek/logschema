@load logschema

# Ensure that the current working directory gets removed from
# any script locations the schema generator identifies.
redef Log::Schema::script_prefixes += cat(getenv("PWD"), "/");

event zeek_init() &priority=1
	{
	# Remove any registered log streams. Copy the table to avoid iterator
	# invalidation problems that can lead to remaining entries.
	for ( id in copy(Log::active_streams) )
		Log::disable_stream(id);
	}
