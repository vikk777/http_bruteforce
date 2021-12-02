@load ./hbf
@load base/protocols/http

# HHTP Basic Bruteforce
module HBBF;

redef HTTP::default_capture_password = T;

option AUTH_TYPE = "Basic";


event HTTP::log_http(rec: HTTP::Info)
{
	if (rec?$username && rec?$password)
	{
		local info: HBF::Info;
		local username = rec$username;
		local password = rec$password;

		info$uid = rec$uid;
		info$id = rec$id;
		info$method = rec$method;
		info$uri = rec$uri;
		info$user_agent = rec$user_agent;
		info$auth_type = AUTH_TYPE;

		HBF::watch_dog(username, password, info);
	}
}
