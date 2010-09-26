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

class CommandCSSetSecureFounder : public Command
{
 public:
	CommandCSSetSecureFounder(const Anope::string &cpermission = "") : Command("SECUREFOUNDER", 2, 2, cpermission)
	{
	}

	CommandReturn Execute(User *u, const std::vector<Anope::string> &params)
	{
		ChannelInfo *ci = cs_findchan(params[0]);
		if (!ci)
			throw CoreException("NULL ci in CommandCSSetSecureFounder");

		if (this->permission.empty() && ci->HasFlag(CI_SECUREFOUNDER) ? !IsFounder(u, ci) : !check_access(u, ci, CA_FOUNDER))
		{
			u->SendMessage(ChanServ, ACCESS_DENIED);
			return MOD_CONT;
		}

		if (params[1].equals_ci("ON"))
		{
			ci->SetFlag(CI_SECUREFOUNDER);
			u->SendMessage(ChanServ, CHAN_SET_SECUREFOUNDER_ON, ci->name.c_str());
		}
		else if (params[1].equals_ci("OFF"))
		{
			ci->UnsetFlag(CI_SECUREFOUNDER);
			u->SendMessage(ChanServ, CHAN_SET_SECUREFOUNDER_OFF, ci->name.c_str());
		}
		else
			this->OnSyntaxError(u, "SECUREFOUNDER");

		return MOD_CONT;
	}

	bool OnHelp(User *u, const Anope::string &)
	{
		u->SendMessage(ChanServ, CHAN_HELP_SET_SECUREFOUNDER, "SET");
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &)
	{
		SyntaxError(ChanServ, u, "SET SECUREFOUNDER", CHAN_SET_SECUREFOUNDER_SYNTAX);
	}

	void OnServHelp(User *u)
	{
		u->SendMessage(ChanServ, CHAN_HELP_CMD_SET_SECUREFOUNDER);
	}
};

class CommandCSSASetSecureFounder : public CommandCSSetSecureFounder
{
 public:
	CommandCSSASetSecureFounder() : CommandCSSetSecureFounder("chanserv/saset/securefounder")
	{
	}

	bool OnHelp(User *u, const Anope::string &)
	{
		u->SendMessage(ChanServ, CHAN_HELP_SET_SECUREFOUNDER, "SASET");
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &)
	{
		SyntaxError(ChanServ, u, "SASET SECUREFOUNDER", CHAN_SASET_SECUREFOUNDER_SYNTAX);
	}
};

class CSSetSecureFounder : public Module
{
	CommandCSSetSecureFounder commandcssetsecurefounder;
	CommandCSSASetSecureFounder commandcssasetsecurefounder;

 public:
	CSSetSecureFounder(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetType(CORE);

		Command *c = FindCommand(ChanServ, "SET");
		if (c)
			c->AddSubcommand(&commandcssetsecurefounder);

		c = FindCommand(ChanServ, "SASET");
		if (c)
			c->AddSubcommand(&commandcssasetsecurefounder);
	}

	~CSSetSecureFounder()
	{
		Command *c = FindCommand(ChanServ, "SET");
		if (c)
			c->DelSubcommand(&commandcssetsecurefounder);

		c = FindCommand(ChanServ, "SASET");
		if (c)
			c->DelSubcommand(&commandcssasetsecurefounder);
	}
};

MODULE_INIT(CSSetSecureFounder)
