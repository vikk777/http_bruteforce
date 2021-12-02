
## HTTP bruteforce common performance
module HBF;

export
{
	redef enum Log::ID += { LOG };

	option log_path = "hbf" &redef;

	type Credits: record
	{
		usernames: set[string];
		passwords: set[string];
		brutforser: bool &default=F;
	};

	type Info: record
	{
		uid: string &log;
		id: conn_id &log;
		method: string &log;
		uri: string &log;
		user_agent: string &log;
		auth_type: string &log;
		username: string &log;
		passwords: count &log;
	};

	global hosts: table[addr] of Credits;

	const THRESHOLD: count(3);

	global watch_dog: function(username: string, password: string, info: Info);
}


function watch_dog(username: string, password: string, info: Info)
{
	local src = info$id$orig_h;

	if ([src] !in hosts)
	{
		hosts[src] = Credits();
	}

	local host = hosts[src];

	add host$usernames[username];
	add host$passwords[password];

	if ((!host$brutforser) && (
		|host$usernames| > THRESHOLD ||
		|host$passwords| > THRESHOLD))
	{
		host$brutforser = T;
	}

	if (host$brutforser && (
		|host$usernames| % THRESHOLD == 0 ||
		|host$passwords| % THRESHOLD == 0))
	{
		print fmt("[SECURITY] Bruteforcer detected");

		Log::write(HBF::LOG, [$uid=info$uid, $id=info$id, $method=info$method,
					$uri=info$uri, $user_agent=info$user_agent, $auth_type=info$auth_type,
					$username=username, $passwords=|host$passwords|]);
	}
}


event zeek_init()
{
	Log::create_stream(HBF::LOG, [$columns=Info, $path=HBF::log_path]);
}