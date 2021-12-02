# Config file for HTTP POST bruteforce detector

module CFG;

export
{
	option username: set[string] = {"user", "username", "login", "email", "identifier", "name"};
	option password: set[string] = {"password", "pass", "passwd"};
}