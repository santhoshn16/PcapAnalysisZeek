##! add this file in zeek directory
@load base/protocols/conn

@load base/frameworks/analyzer

module Credentials;

export{
redef enum Log::ID += { LOG };
type Info: record {
	uid: string &log;
	username: string &log;
	password: string &log;
};
}

redef record connection += {
      credentials: Info &optional;
};

event zeek_init() &priority=5
{
Log::create_stream(Credentials::LOG, [$columns=Info, $path="creds"]);

}

event ftp_request(c:connection, command:string, arg:string)
{
local s = command;
local s1 = arg;
local rec: Credentials::Info;
if (s == "USER")
{ 
#print fmt("%s",s1);
rec = [$uid=c$uid, $username=s1, $password="none"];
c$credentials = rec;
Log::write(Credentials::LOG, rec);
}
if (s == "PASS")
{
#print fmt("%s",s1);
rec = [$uid=c$uid, $username="none", $password=s1];
c$credentials = rec;
Log::write(Credentials::LOG, rec);
}
}

