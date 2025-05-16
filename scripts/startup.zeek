@load base/misc/version

# This defines when schema export runs, assuming Log::Schema::run_at_startup is
# true (the default). For Zeeks older than 6.0 it always runs after zeek_init().
# For newer Zeek, this only happens in standalone runs, while in clusterized
# setups we rely on Cluster::Experimental::cluster_started().

module Log::Schema;

event trigger_export()
	{
	run_export();
	}

@if ( Version::at_least("6.0") )

# For triggering export in a cluster, once up and running.
@load policy/frameworks/cluster/experimental

event Cluster::Experimental::cluster_started()
	{
	if ( run_at_startup && Cluster::local_node_type() == Cluster::MANAGER )
		{
		schedule 0 sec { trigger_export() };
		}
	}


event zeek_init()
	{
	if ( run_at_startup && ! Cluster::is_enabled() )
		{
		schedule 0 sec { trigger_export() };
		}
	}
@else

# For very old Zeeks we only support running after zeek_init().
event zeek_init()
	{
	if ( run_at_startup )
		{
		schedule 0 sec { trigger_export() };
		}
	}

@endif
