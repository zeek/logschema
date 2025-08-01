@load base/misc/version

event zeek_init()
	{
	if ( Version::at_least("8.0") )
		exit(0);

	exit(1);
	}
