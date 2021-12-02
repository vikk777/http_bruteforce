@load ./hbf
@load ./hpbf.cfg
@load ./utils
@load base/bif/plugins/Zeek_HTTP.events.bif

# HTTP POST Bruteforce
module HPBF;

option AUTH_TYPE = "POST";

type User_pass: record
{
	username: string;
	password: string;
};


function extract_credits(data: string): User_pass
{
	local credits: User_pass;
	local pairs = parser(data);

	for (key, val in pairs)
	{
		if (key in CFG::username)
		{
			credits$username = val;
		}

		if (key in CFG::password)
		{
			credits$password = val;
		}

		if (credits?$username && credits?$password)
		{
			break;
		}
	}

	return credits;
}


event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
	if (is_orig)
	{
		local info: HBF::Info;
		local credits = extract_credits(data);
		local username = credits$username;
		local password = credits$password;

		info$uid = c$uid;
		info$id = c$id;
		info$method = c$http$method;
		info$uri = c$http$uri;
		info$user_agent = c$http$user_agent;
		info$auth_type = AUTH_TYPE;

		HBF::watch_dog(username, password, info);
	}
}
