##! add this file in zeek directory
@load base/protocols/conn

@load base/frameworks/analyzer

module Num;

export{
redef enum Log::ID += { LOG };
type Info: record {
	uid: string &log;
	username: string &log;
	password: string &log;
	message: string &log;
	status: string &log;
};

}
redef record connection += {
      num: Info &optional;
};
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) 
{
local acknum = ack;
local a = c$uid;
local os = c$orig$size;
local rs = c$resp$size;
local orr = is_orig;
local l = len;
local flag = flags;
print fmt("%s %s %d %d %f %s",a,orr,acknum,l,c$duration,flag);
}



event zeek_init() &priority=5
{
Log::create_stream(Num::LOG, [$columns=Info, $path="telnet"]);
local p : port = 23/tcp;

Analyzer::register_for_port(Analyzer::ANALYZER_TELNET,p);
Analyzer::register_for_port(Analyzer::ANALYZER_LOGIN,p);
#print fmt("%s",b);
}



event login_success(c:connection, user:string, client_user:string, password:string, line:string)
{
local rec: Num::Info = [$uid=c$uid, $username=client_user, $password=password, $message=line, $status="none"];
c$num = rec;

Log::write(Num::LOG, rec);

}

event login_confused(c:connection, message:string, line:string)
{
local msg:string  = "none";
local rec: Num::Info = [$uid=c$uid, $username=msg, $password=msg, $message=line, $status=message];
c$num = rec;

Log::write(Num::LOG, rec);

}

event authentication_accepted(name:string, c:connection)
{
local rec: Num::Info = [$uid=c$uid, $username=name, $password="none", $message="none", $status="none"];
c$num = rec;

Log::write(Num::LOG, rec);
}





