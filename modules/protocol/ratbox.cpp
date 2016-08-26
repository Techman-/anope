/* Ratbox IRCD functions
 *
 * (C) 2003-2016 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 */

#include "module.h"

static Anope::string UplinkSID;

class RatboxProto : public IRCDProto
{
	BotInfo *FindIntroduced()
	{
		BotInfo *bi = Config->GetClient("OperServ");
		
		if (bi && bi->introduced)
			return bi;
		
		for (botinfo_map::iterator it = BotListByNick->begin(), it_end = BotListByNick->end(); it != it_end; ++it)
			if (it->second->introduced)
				return it->second;
			
		return NULL;
	}

 public:
	RatboxProto(Module *creator) : IRCDProto(creator, "Ratbox 3.0+")
	{
		DefaultPseudoclientModes = "+oiS";
		CanSVSHold = true;
		CanSNLine = true;
		CanSQLine = true;
		RequiresID = true;
		MaxModes = 4;
	}

	void SendSVSKillInternal(const MessageSource &source, User *u, const Anope::string &buf) anope_override
	{
		IRCDProto::SendSVSKillInternal(source, u, buf);
		u->KillInternal(source, buf);
	}
	
	void SendGlobalNotice(BotInfo *bi, const Server *dest, const Anope::string &msg) anope_override
	{
		UplinkSocket::Message(bi) << "NOTICE $$" << dest->GetName() << " :" << msg;
	}
	
	
	void SendGlobalPrivmsg(BotInfo *bi, const Server *dest, const Anope::string &msg) anope_override
	{
		UplinkSocket::Message(bi) << "PRIVMSG $$" << dest->GetName() << " :" << msg;
	}
	
	void SendSQLine(User *, const XLine *x) anope_override
	{
		/* Calculate the time left before this would expire, capping it at 2 days */
		time_t timeleft = x->expires - Anope::CurTime;
		
		if (timeleft > 172800 || !x->expires)
			timeleft = 172800;
		
		if (FindIntroduced() != NULL)
			UplinkSocket::Message(FindIntroduced()) << "ENCAP * RESV " << timeleft << " " << x->mask << " 0 :" << x->GetReason();
	}
	
	void SendSQLineDel(const XLine *x) anope_override
	{
		UplinkSocket::Message(Config->GetClient("OperServ")) << "ENCAP * UNRESV " << x->mask;
	}
	
	void SendSGLine(User *, const XLine *x) anope_override
	{
		// Calculate the time left before this would expire, capping it at 2 days
		time_t timeleft = x->expires - Anope::CurTime;
		
		if (timeleft > 172800 || !x->expires)
			timeleft = 172800;
		
		UplinkSocket::Message(Config->GetClient("OperServ")) << "ENCAP * XLINE " << timeleft << " " << x->mask << " 2 :" << x->GetReason();
	}
	
	void SendSGLineDel(const XLine *x) anope_override
	{
		UplinkSocket::Message(Config->GetClient("OperServ")) << "ENCAP * UNXLINE " << x->mask;
	}
	
	void SendSVSHold(const Anope::string &nick, time_t t) anope_override
	{
		XLine x(nick, Me->GetName(), Anope::CurTime + t, "Being held for registered user");
		this->SendSQLine(NULL, &x);
	}
	
	void SendSVSHoldDel(const Anope::string &nick) anope_override
	{
		XLine x(nick);
		this->SendSQLineDel(&x);
	}
	
	void SendAkill(User *u, XLine *x) anope_override
	{
		if (x->IsRegex() || x->HasNickOrReal())
		{
			if (!u)
			{
				/*
				 * No user (this akill was just added), and contains nick and/or realname.
				 * Find users that match and ban them.
				 */
				for (user_map::const_iterator it = UserListByNick.begin(); it != UserListByNick.end(); ++it)
					if (x->manager->Check(it->second, x))
						this->SendAkill(it->second, x);
				
				return;
			}
			
			const XLine *old = x;
			
			if (old->manager->HasEntry("*@" + u->host))
				return;
			
			// We can't akill x as it has a nick and/or realname included, so create a new akill for *@host
			XLine *xline = new XLine("*@" + u->host, old->by, old->expires, old->reason, old->id);
			
			old->manager->AddXLine(xline);
			x = xline;
			
			Log(Config->GetClient("OperServ"), "akill") << "AKILL: Added an akill for " << x->mask << " because " << u->GetMask() << "#"
							<< u->realname << " matches " << old->mask;
		}
		
		// Calculate the time left before this would expire, capping it at 2 days
		time_t timeleft = x->expires - Anope::CurTime;
		
		if (timeleft > 172800 || !x->expires)
			timeleft = 172800;
		
		UplinkSocket::Message(Config->GetClient("OperServ")) << "ENCAP * KLINE " << timeleft << " " << x->GetUser() << " " << x->GetHost() << " :" << x->GetReason();
	}
	
	void SendAkillDel(const XLine *x) anope_override
	{
		if (x->IsRegex() || x->HasNickOrReal())
			return;
		
		UplinkSocket::Message(Config->GetClient("OperServ")) << "ENCAP * UNKLINE " << x->GetUser() << " " << x->GetHost();
	}
	
	
	void SendJoin(User *u, Channel *c, const ChannelStatus *status) anope_override
	{
		UplinkSocket::Message(Me) << "SJOIN " << c->creation_time << " " << c->name << " +" << c->GetModes(true, true) << " :"
					<< (status != NULL ? status->BuildModePrefixList() : "") << u->GetUID();

		// Update our internal status for this user since this is not going through our mode handling system
		if (status)
		{
			ChanUserContainer *uc = c->FindUser(u);

			if (uc)
				uc->status = *status;
		}
	}
	
	void SendServer(const Server *server) anope_override
	{
		if (server == Me)
			UplinkSocket::Message() << "SERVER " << server->GetName() << " " << server->GetHops() + 1 << " :" << server->GetDescription();
		else
			UplinkSocket::Message(Me) << "SID " << server->GetName() << " " << server->GetHops() + 1 << " " << server->GetSID() << " :" << server->GetDescription();
	}
	
	void SendChannel(Channel *c) anope_override
	{
		Anope::string modes = c->GetModes(true, true);

		if (modes.empty())
			modes = "+";

		UplinkSocket::Message() << "SJOIN " << c->creation_time << " " << c->name << " " << modes << " :";
	}
	
	bool IsIdentValid(const Anope::string &ident) anope_override
	{
		if (ident.empty() || ident.length() > Config->GetBlock("networkinfo")->Get<unsigned>("userlen"))
			return false;

		Anope::string chars = "~}|{ `_^]\\[ .-$";

		for (unsigned i = 0; i < ident.length(); ++i)
		{
			const char &c = ident[i];

			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
				continue;

			if (chars.find(c) != Anope::string::npos)
				continue;

			return false;
		}

		return true;
	}

	void SendGlobopsInternal(const MessageSource &source, const Anope::string &buf) anope_override
	{
		UplinkSocket::Message(source) << "OPERWALL :" << buf;
	}

	void SendConnect() anope_override
	{
		UplinkSocket::Message() << "PASS " << Config->Uplinks[Anope::CurrentUplink].password << " TS 6 :" << Me->GetSID();
		/*
		  QS     - Can handle quit storm removal
		  EX     - Can do channel +e exemptions
		  CHW    - Can do channel wall @#
		  IE     - Can do invite exceptions
		  GLN    - Can do GLINE message
		  KNOCK  - supports KNOCK
		  TB     - supports topic burst
		  ENCAP  - supports ENCAP
		*/
		UplinkSocket::Message() << "CAPAB :QS EX CHW IE GLN TB ENCAP";
		/* Make myself known to myself in the serverlist */
		SendServer(Me);
		/*
		 * SVINFO
		 *	  parv[0] = sender prefix
		 *	  parv[1] = TS_CURRENT for the server
		 *	  parv[2] = TS_MIN for the server
		 *	  parv[3] = server is standalone or connected to non-TS only
		 *	  parv[4] = server's idea of UTC time
		 */
		UplinkSocket::Message() << "SVINFO 6 3 0 :" << Anope::CurTime;
	}

	void SendClientIntroduction(User *u) anope_override
	{
		Anope::string modes = "+" + u->GetModes();
		UplinkSocket::Message(Me) << "UID " << u->nick << " 1 " << u->timestamp << " " << modes << " " << u->GetIdent() << " " << u->host << " 0 " << u->GetUID() << " :" << u->realname;
	}

	void SendLogin(User *u, NickAlias *na) anope_override
	{
		if (na->nc->HasExt("UNCONFIRMED"))
			return;

		UplinkSocket::Message(Me) << "ENCAP * SU " << u->GetUID() << " " << na->nc->display;
	}

	void SendLogout(User *u) anope_override
	{
		UplinkSocket::Message(Me) << "ENCAP * SU " << u->GetUID();
	}

	void SendTopic(const MessageSource &source, Channel *c) anope_override
	{
		BotInfo *bi = source.GetBot();
		bool needjoin = c->FindUser(bi) == NULL;

		if (needjoin)
		{
			ChannelStatus status;

			status.AddMode('o');
			bi->Join(c, &status);
		}

		IRCDProto::SendTopic(source, c);

		if (needjoin)
			bi->Part(c, "Topic set for "+c->name);
	}
};

struct IRCDMessageBMask : IRCDMessage
{
	IRCDMessageBMask(Module *creator) : IRCDMessage(creator, "BMASK", 4) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	/*            0          1        2  3              */
	/* :0MC BMASK 1350157102 #channel b :*!*@*.test.com */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		Channel *c = Channel::Find(params[1]);
		ChannelMode *mode = ModeManager::FindChannelModeByChar(params[2][0]);

		if (c && mode)
		{
			spacesepstream bans(params[3]);
			Anope::string token;

			while (bans.GetToken(token))
				c->SetModeInternal(source, mode, token);
		}
	}
};

struct IRCDMessageEncap : IRCDMessage
{
	IRCDMessageEncap(Module *creator) : IRCDMessage(creator, "ENCAP", 3) { SetFlag(IRCDMESSAGE_REQUIRE_USER); }

	// Debug: Received: :00BAAAAAB ENCAP * LOGIN Adam
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		if (params[1] == "LOGIN" || params[1] == "SU")
		{
			User *u = source.GetUser();

			NickCore *nc = NickCore::Find(params[2]);
			if (!nc)
				return;
			u->Login(nc);

			/* Sometimes a user connects, we send them the usual "this nickname is registered" mess (if
			 * their server isn't syncing) and then we receive this.. so tell them about it.
			 */
			if (u->server->IsSynced())
				u->SendMessage(Config->GetClient("NickServ"), _("You have been logged in as \002%s\002."), nc->display.c_str());
		}
	}
};

struct IRCDMessageJoin : Message::Join
{
	IRCDMessageJoin(Module *creator) : Message::Join(creator, "JOIN") { }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		if (params.size() == 1 && params[0] == "0")
			return Message::Join::Run(source, params);

		if (params.size() < 2)
			return;

		std::vector<Anope::string> p = params;
		p.erase(p.begin());

		return Message::Join::Run(source, p);
	}
};

struct IRCDMessageNick : IRCDMessage
{
	IRCDMessageNick(Module *creator) : IRCDMessage(creator, "NICK", 2) { SetFlag(IRCDMESSAGE_REQUIRE_USER); }

	/*                 0       1          */
	/* :0MCAAAAAB NICK newnick 1350157102 */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		source.GetUser()->ChangeNick(params[0], convertTo<time_t>(params[1]));
	}
};


struct IRCDMessagePass : IRCDMessage
{
	IRCDMessagePass(Module *creator) : IRCDMessage(creator, "PASS", 4) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		UplinkSID = params[3];
	}
};

struct IRCDMessagePong : IRCDMessage
{
	IRCDMessagePong(Module *creator) : IRCDMessage(creator, "PONG", 0) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		source.GetServer()->Sync(false);
	}
};

struct IRCDMessageServer : IRCDMessage
{
	IRCDMessageServer(Module *creator) : IRCDMessage(creator, "SERVER", 3) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	// SERVER hades.arpa 1 :ircd-ratbox test server
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		// Servers other then our immediate uplink are introduced via SID
		if (params[1] != "1")
			return;
		new Server(source.GetServer() == NULL ? Me : source.GetServer(), params[0], 1, params[2], UplinkSID);
		IRCD->SendPing(Me->GetName(), params[0]);
	}
};

struct IRCDMessageSID : IRCDMessage
{
	IRCDMessageSID(Module *creator) : IRCDMessage(creator, "SID", 4) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	/*          0          1 2    3                       */
	/* :0MC SID hades.arpa 2 4XY :ircd-hybrid test server */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		unsigned int hops = params[1].is_pos_number_only() ? convertTo<unsigned>(params[1]) : 0;
		new Server(source.GetServer() == NULL ? Me : source.GetServer(), params[0], hops, params[3], params[2]);

		IRCD->SendPing(Me->GetName(), params[0]);
	}
};

struct IRCDMessageSJoin : IRCDMessage
{
	IRCDMessageSJoin(Module *creator) : IRCDMessage(creator, "SJOIN", 2) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		Anope::string modes;

		if (params.size() >= 3)
			for (unsigned i = 2; i < params.size() - 1; ++i)
				modes += " " + params[i];

		if (!modes.empty())
			modes.erase(modes.begin());

		std::list<Message::Join::SJoinUser> users;

		spacesepstream sep(params[params.size() - 1]);
		Anope::string buf;

		while (sep.GetToken(buf))
		{
			Message::Join::SJoinUser sju;

			/* Get prefixes from the nick */
			for (char ch; (ch = ModeManager::GetStatusChar(buf[0]));)
			{
				buf.erase(buf.begin());
				sju.first.AddMode(ch);
			}

			sju.second = User::Find(buf);
			if (!sju.second)
			{
				Log(LOG_DEBUG) << "SJOIN for non-existent user " << buf << " on " << params[1];
				continue;
			}

			users.push_back(sju);
		}

		time_t ts = Anope::string(params[0]).is_pos_number_only() ? convertTo<time_t>(params[0]) : Anope::CurTime;
		Message::Join::SJoin(source, params[1], ts, modes, users);
	}
};

struct IRCDMessageTBurst : IRCDMessage
{
	IRCDMessageTBurst(Module *creator) : IRCDMessage(creator, "TB", 3) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	/*
	 * params[0] = channel
	 * params[1] = ts
	 * params[2] = topic OR who set the topic
	 * params[3] = topic if params[2] isn't the topic
	 */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		time_t topic_time = Anope::string(params[1]).is_pos_number_only() ? convertTo<time_t>(params[1]) : Anope::CurTime;
		Channel *c = Channel::Find(params[0]);

		if (!c)
			return;

		const Anope::string &setter = params.size() == 4 ? params[2] : "",
			topic = params.size() == 4 ? params[3] : params[2];

		c->ChangeTopicInternal(NULL, setter, topic, topic_time);
	}
};

struct IRCDMessageTMode : IRCDMessage
{
	IRCDMessageTMode(Module *creator) : IRCDMessage(creator, "TMODE", 3) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		time_t ts = 0;

		try
		{
			ts = convertTo<time_t>(params[0]);
		}
		catch (const ConvertException &) { }

		Channel *c = Channel::Find(params[1]);
		Anope::string modes = params[2];

		for (unsigned i = 3; i < params.size(); ++i)
			modes += " " + params[i];

		if (c)
			c->SetModesInternal(source, modes, ts);
	}
};

struct IRCDMessageUID : IRCDMessage
{
	IRCDMessageUID(Module *creator) : IRCDMessage(creator, "UID", 9) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	// :42X UID Adam 1 1348535644 +aow Adam 192.168.0.5 192.168.0.5 42XAAAAAB :Adam
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		/* Source is always the server */
		User::OnIntroduce(params[0], params[4], params[5], "", params[6], source.GetServer(), params[8], params[2].is_pos_number_only() ? convertTo<time_t>(params[2]) : 0, params[3], params[7], NULL);
	}
};

class ProtoRatbox : public Module
{
	RatboxProto ircd_proto;

	/* Core message handlers */
	Message::Away message_away;
	Message::Capab message_capab;
	Message::Error message_error;
	Message::Invite message_invite;
	Message::Kick message_kick;
	Message::Kill message_kill;
	Message::Mode message_mode;
	Message::MOTD message_motd;
	Message::Notice message_notice;
	Message::Part message_part;
	Message::Ping message_ping;
	Message::Privmsg message_privmsg;
	Message::Quit message_quit;
	Message::SQuit message_squit;
	Message::Stats message_stats;
	Message::Time message_time;
	Message::Topic message_topic;
	Message::Version message_version;
	Message::Whois message_whois;

	/* Our message handlers */
	IRCDMessageBMask message_bmask;
	IRCDMessageEncap message_encap;
	IRCDMessageJoin message_join;
	IRCDMessageNick message_nick;
	IRCDMessagePass message_pass;
	IRCDMessagePong message_pong;
	IRCDMessageServer message_server;
	IRCDMessageSID message_sid;
	IRCDMessageSJoin message_sjoin;
	IRCDMessageTBurst message_tburst;
	IRCDMessageTMode message_tmode;
	IRCDMessageUID message_uid;

	void AddModes()
	{
		/* user modes */
		ModeManager::AddUserMode(new UserModeOperOnly("ADMIN", 'a'));
		ModeManager::AddUserMode(new UserModeOperOnly("BOT", 'b'));
		// c/C = con
		// d = debug?
		ModeManager::AddUserMode(new UserMode("DEAF", 'D'));
		// f = full?
		ModeManager::AddUserMode(new UserMode("CALLERID", 'g'));
		ModeManager::AddUserMode(new UserMode("INVIS", 'i'));
		// k = skill?
		ModeManager::AddUserMode(new UserModeOperOnly("LOCOPS", 'l'));
		// n = nchange
		ModeManager::AddUserMode(new UserModeOperOnly("OPER", 'o'));
		// r = rej
		ModeManager::AddUserMode(new UserModeOperOnly("SNOMASK", 's'));
		ModeManager::AddUserMode(new UserModeNoone("PROTECTED", 'S'));
		// u = unauth?
		ModeManager::AddUserMode(new UserMode("WALLOPS", 'w'));
		// x = external?
		// y = spy?
		ModeManager::AddUserMode(new UserModeOperOnly("OPERWALLS", 'z'));
		// Z = spy?

		/* b/e/I */
		ModeManager::AddChannelMode(new ChannelModeList("BAN", 'b'));
		ModeManager::AddChannelMode(new ChannelModeList("EXCEPT", 'e'));
		ModeManager::AddChannelMode(new ChannelModeList("INVITEOVERRIDE", 'I'));

		/* v/h/o/a/q */
		ModeManager::AddChannelMode(new ChannelModeStatus("VOICE", 'v', '+', 0));
		ModeManager::AddChannelMode(new ChannelModeStatus("OP", 'o', '@', 1));

		/* l/k */
		ModeManager::AddChannelMode(new ChannelModeParam("LIMIT", 'l', true));
		ModeManager::AddChannelMode(new ChannelModeKey('k'));

		/* channel modes */
		ModeManager::AddChannelMode(new ChannelMode("INVITE", 'i'));
		ModeManager::AddChannelMode(new ChannelMode("MODERATED", 'm'));
		ModeManager::AddChannelMode(new ChannelMode("NOEXTERNAL", 'n'));
		ModeManager::AddChannelMode(new ChannelMode("PRIVATE", 'p'));
		ModeManager::AddChannelMode(new ChannelMode("REGISTEREDONLY", 'r'));
		ModeManager::AddChannelMode(new ChannelMode("SECRET", 's'));
		ModeManager::AddChannelMode(new ChannelMode("TOPIC", 't'));
		ModeManager::AddChannelMode(new ChannelMode("SSL", 'S'));
	}

 public:
	ProtoRatbox(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, PROTOCOL | VENDOR),
		ircd_proto(this),
		message_away(this), message_capab(this), message_error(this), message_invite(this), message_kick(this),
		message_kill(this), message_mode(this), message_motd(this), message_notice(this), message_part(this),
		message_ping(this), message_privmsg(this), message_quit(this), message_squit(this), message_stats(this),
		message_time(this), message_topic(this), message_version(this), message_whois(this),

		message_bmask(this), message_encap(this), message_join(this), message_nick(this),
		message_pass(this), message_pong(this), message_server(this), message_sid(this),
		message_sjoin(this), message_tburst(this), message_tmode(this), message_uid(this)

	{
		this->AddModes();
	}

	~ProtoRatbox()
	{
	}
};

MODULE_INIT(ProtoRatbox)
