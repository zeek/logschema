##! This script prints the schema fingerprint to stdout after all zeek_init
##! handlers have run to completion and terminates Zeek. If you need fancier
##! logic, create a custom script that invokes Log::Schema::fingerprint() as
##! needed.

module Log::Schema;

@load ./main

event trigger_fingerprint_output()
	{
	print fingerprint();
	terminate();
	}

event zeek_init()
	{
	schedule 0 sec { trigger_fingerprint_output() };
	}
