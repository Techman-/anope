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

class CommandCSClear : public Command
{
 public:
	CommandCSClear() : Command("CLEAR", 2, 2)
	{
	}

	CommandReturn Execute(User *u, const std::vector<Anope::string> &params)
	{
		Anope::string chan = params[0];
		Anope::string what = params[1];
		Channel *c = findchan(chan);
		ChannelInfo *ci = c ? c->ci : NULL;
		Anope::string modebuf;

		ChannelMode *owner = ModeManager::FindChannelModeByName(CMODE_OWNER);
		ChannelMode *admin = ModeManager::FindChannelModeByName(CMODE_PROTECT);
		ChannelMode *op = ModeManager::FindChannelModeByName(CMODE_OP);
		ChannelMode *halfop = ModeManager::FindChannelModeByName(CMODE_HALFOP);
		ChannelMode *voice = ModeManager::FindChannelModeByName(CMODE_VOICE);

		if (c)
			// XXX
			Log(LOG_COMMAND, u, this, ci) << what;

		if (!c)
			u->SendMessage(ChanServ, CHAN_X_NOT_IN_USE, chan.c_str());
		else if (!check_access(u, ci, CA_CLEAR))
			u->SendMessage(ChanServ, ACCESS_DENIED);
		else if (what.equals_ci("bans"))
		{
			c->ClearBans();

			u->SendMessage(ChanServ, CHAN_CLEARED_BANS, chan.c_str());
		}
		else if (ModeManager::FindChannelModeByName(CMODE_EXCEPT) && what.equals_ci("excepts"))
		{
			c->ClearExcepts();

			u->SendMessage(ChanServ, CHAN_CLEARED_EXCEPTS, chan.c_str());
		}
		else if (ModeManager::FindChannelModeByName(CMODE_INVITE) && what.equals_ci("invites"))
		{
			c->ClearInvites();

			u->SendMessage(ChanServ, CHAN_CLEARED_INVITES, chan.c_str());
		}
		else if (what.equals_ci("modes"))
		{
			c->ClearModes();
			check_modes(c);

			u->SendMessage(ChanServ, CHAN_CLEARED_MODES, chan.c_str());
		}
		else if (what.equals_ci("ops"))
		{
			if (ircd->svsmode_ucmode)
			{
				if (owner)
				{
					modebuf = "-" + owner->ModeChar;

					ircdproto->SendSVSModeChan(c, modebuf, "");
				}
				if (admin)
				{
					modebuf = "-" + admin->ModeChar;

					ircdproto->SendSVSModeChan(c, modebuf, "");
				}
				if (op)
				{
					modebuf = "-" + op->ModeChar;

					ircdproto->SendSVSModeChan(c, modebuf, "");
				}
			}
			else
			{
				for (CUserList::iterator it = c->users.begin(), it_end = c->users.end(); it != it_end; ++it)
				{
					UserContainer *uc = *it;

					if (uc->Status->HasFlag(CMODE_OWNER))
						c->RemoveMode(NULL, owner, uc->user->nick);
					if (uc->Status->HasFlag(CMODE_PROTECT))
						c->RemoveMode(NULL, admin, uc->user->nick);
					if (uc->Status->HasFlag(CMODE_OP))
						c->RemoveMode(NULL, op, uc->user->nick);
				}
			}

			u->SendMessage(ChanServ, CHAN_CLEARED_OPS, chan.c_str());
		}
		else if ((halfop && what.equals_ci("hops")) || (voice && what.equals_ci("voices")))
		{
			ChannelMode *cm = what.equals_ci("hops") ? halfop : voice;

			if (ircd->svsmode_ucmode)
			{
				modebuf = "-" + cm->ModeChar;

				ircdproto->SendSVSModeChan(c, modebuf, "");
			}
			else
			{
				for (CUserList::iterator it = c->users.begin(), it_end = c->users.end(); it != it_end; ++it)
				{
					UserContainer *uc = *it;

					if (uc->Status->HasFlag(cm->Name))
						c->RemoveMode(NULL, cm, uc->user->nick);
				}
			}
		}
		else if (what.equals_ci("users"))
		{
			Anope::string buf = "CLEAR USERS command from " + u->nick;

			for (CUserList::iterator it = c->users.begin(), it_end = c->users.end(); it != it_end; )
			{
				UserContainer *uc = *it++;

				c->Kick(NULL, uc->user, "%s", buf.c_str());
			}

			u->SendMessage(ChanServ, CHAN_CLEARED_USERS, chan.c_str());
		}
		else
			SyntaxError(ChanServ, u, "CLEAR", CHAN_CLEAR_SYNTAX);

		return MOD_CONT;
	}

	bool OnHelp(User *u, const Anope::string &subcommand)
	{
		u->SendMessage(ChanServ, CHAN_HELP_CLEAR);
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &subcommand)
	{
		SyntaxError(ChanServ, u, "CLEAR", CHAN_CLEAR_SYNTAX);
	}

	void OnServHelp(User *u)
	{
		u->SendMessage(ChanServ, CHAN_HELP_CMD_CLEAR);
	}
};

class CSClear : public Module
{
	CommandCSClear commandcsclear;

 public:
	CSClear(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetType(CORE);

		this->AddCommand(ChanServ, &commandcsclear);
	}
};

MODULE_INIT(CSClear)
