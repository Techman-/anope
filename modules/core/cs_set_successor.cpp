/* ChanServ core functions
 *
 * (C) 2003-2010 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 */

/*************************************************************************/

#include "module.h"

class CommandCSSetSuccessor : public Command
{
 public:
	CommandCSSetSuccessor(const Anope::string &cpermission = "") : Command("SUCCESSOR", 1, 2, cpermission)
	{
	}

	CommandReturn Execute(User *u, const std::vector<Anope::string> &params)
	{
		ChannelInfo *ci = cs_findchan(params[0]);
		if (!ci)
			throw CoreException("NULL ci in CommandCSSetSuccessor");

		if (this->permission.empty() && ci->HasFlag(CI_SECUREFOUNDER) ? !IsFounder(u, ci) : !check_access(u, ci, CA_FOUNDER))
		{
			u->SendMessage(ChanServ, ACCESS_DENIED);
			return MOD_CONT;
		}

		NickCore *nc;

		if (params.size() > 1)
		{
			NickAlias *na = findnick(params[1]);

			if (!na)
			{
				u->SendMessage(ChanServ, NICK_X_NOT_REGISTERED, params[1].c_str());
				return MOD_CONT;
			}
			if (na->HasFlag(NS_FORBIDDEN))
			{
				u->SendMessage(ChanServ, NICK_X_FORBIDDEN, na->nick.c_str());
				return MOD_CONT;
			}
			if (na->nc == ci->founder)
			{
				u->SendMessage(ChanServ, CHAN_SUCCESSOR_IS_FOUNDER, na->nick.c_str(), ci->name.c_str());
				return MOD_CONT;
			}
			nc = na->nc;
		}
		else
			nc = NULL;

		Log(!this->permission.empty() ? LOG_ADMIN : LOG_COMMAND, u, this, ci) << "to change the successor from " << (ci->successor ? ci->successor->display : "none") << " to " << (nc ? nc->display : "none");

		ci->successor = nc;

		if (nc)
			u->SendMessage(ChanServ, CHAN_SUCCESSOR_CHANGED, ci->name.c_str(), nc->display.c_str());
		else
			u->SendMessage(ChanServ, CHAN_SUCCESSOR_UNSET, ci->name.c_str());

		return MOD_CONT;
	}

	bool OnHelp(User *u, const Anope::string &)
	{
		u->SendMessage(ChanServ, CHAN_HELP_SET_SUCCESSOR, "SET");
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &)
	{
		// XXX
		SyntaxError(ChanServ, u, "SET", CHAN_SET_SYNTAX);
	}

	void OnServHelp(User *u)
	{
		u->SendMessage(ChanServ, CHAN_HELP_CMD_SET_SUCCESSOR);
	}
};

class CommandCSSASetSuccessor : public CommandCSSetSuccessor
{
 public:
	CommandCSSASetSuccessor() : CommandCSSetSuccessor("chanserv/saset/successor")
	{
	}

	bool OnHelp(User *u, const Anope::string &)
	{
		u->SendMessage(ChanServ, CHAN_HELP_SET_SUCCESSOR, "SASET");
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &)
	{
		// XXX
		SyntaxError(ChanServ, u, "SASET", CHAN_SASET_SYNTAX);
	}
};

class CSSetSuccessor : public Module
{
	CommandCSSetSuccessor commandcssetsuccessor;
	CommandCSSASetSuccessor commandcssasetsuccessor;

 public:
	CSSetSuccessor(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetType(CORE);

		Command *c = FindCommand(ChanServ, "SET");
		if (c)
			c->AddSubcommand(&commandcssetsuccessor);

		c = FindCommand(ChanServ, "SASET");
		if (c)
			c->AddSubcommand(&commandcssasetsuccessor);
	}

	~CSSetSuccessor()
	{
		Command *c = FindCommand(ChanServ, "SET");
		if (c)
			c->DelSubcommand(&commandcssetsuccessor);

		c = FindCommand(ChanServ, "SASET");
		if (c)
			c->DelSubcommand(&commandcssasetsuccessor);
	}
};

MODULE_INIT(CSSetSuccessor)
