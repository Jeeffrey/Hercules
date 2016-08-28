/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2016  Hercules Dev Team
 * Copyright (C)  Athena Dev Teams
 *
 * Hercules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define HERCULES_CORE

#include "ipban.p.h"

#include "login/login.h"
#include "login/loginlog.h"
#include "common/conf.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/sql.h"
#include "common/strlib.h"
#include "common/timer.h"
#include "common/memmgr.h"

#include <stdlib.h>

struct ipban_interface ipban_s;
struct ipban_interface_private ipban_p;
struct ipban_interface *ipban;
struct ipban_config config_s = {0};


// initialize
void ipban_init(void)
{
	ipban->p->inited = true;
	ipban->p->ipban = uidb_alloc(DB_OPT_RELEASE_DATA);

	if (ipban->p->config->cleanup_interval > 0) { // set up periodic cleanup of connection history and active bans
		timer->add_func_list(ipban->p->cleanup, "ipban_cleanup");
		ipban->p->cleanup_timer_id = timer->add_interval(timer->gettick()+10, ipban->p->cleanup, 0, 0, ipban->p->config->cleanup_interval);
	}
}

// finalize
void ipban_final(void)
{
	if (ipban->p->config->cleanup_interval > 0) // release data
		timer->delete(ipban->p->cleanup_timer_id, ipban->p->cleanup);

	db_destroy(ipban->p->ipban);
}

/**
 * Reads login_configuration/account/ipban/dynamic_pass_failure and loads configuration options.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
bool ipban_config_read_dynamic(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/account/ipban/dynamic_pass_failure")) == NULL) {
		if (imported)
			return true;
		ShowError("account_db_sql_set_property: login_configuration/account/ipban/dynamic_pass_failure was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "enabled", &ipban->p->config->dynamic_pass_failure_ban);
	libconfig->setting_lookup_int64(setting, "ban_interval", (long long *)&ipban->p->config->dynamic_pass_failure_ban_interval);
	libconfig->setting_lookup_int64(setting, "ban_limit", (long long *)&ipban->p->config->dynamic_pass_failure_ban_limit);
	libconfig->setting_lookup_int64(setting, "ban_duration", (long long *)&ipban->p->config->dynamic_pass_failure_ban_duration);

	return true;
}

/**
 * Reads login_configuration.account.ipban and loads configuration options.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
bool ipban_config_read(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;
	bool retval = true;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if (ipban->p->inited)
		return false; // settings can only be changed before init

	if ((setting = libconfig->lookup(config, "login_configuration/account/ipban")) == NULL) {
		if (!imported)
			ShowError("login_config_read: login_configuration/log was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "enabled", &ipban->p->config->enabled);
	libconfig->setting_lookup_int(setting, "cleanup_interval", &ipban->p->config->cleanup_interval);

	if (!ipban->p->config_read_dynamic(filename, config, imported))
		retval = false;

	return retval;
}

// check ip against active bans list
bool ipban_check(uint32 ip)
{
	struct ipban_entry *ie = uidb_get(ipban->p->ipban, ip);

	nullpo_retr(false, ie);

	if (ie->end_timestamp >= time(NULL))
		return true;
	else
		return false;
}

// log failed attempt
void ipban_log(uint32 ip)
{
	if (!ipban->p->config->dynamic_pass_failure_ban)
		return;

	if (ipban->get_faildattempts(ip) >= ipban->p->config->dynamic_pass_failure_ban_limit) {
		struct ipban_entry *ie = uidb_ensure(ipban->p->ipban, ip, ipban->p->ensure_entry);
		ie->end_timestamp = time(NULL) + ipban->p->config->dynamic_pass_failure_ban_duration;
	}
}

void ipban_log_faildattempt(uint32 ip)
{
	struct ipban_entry *ie = uidb_ensure(ipban->p->ipban, ip, ipban->p->ensure_entry);

	if (ie->last_failed_attempt_timestamp - ipban->p->config->dynamic_pass_failure_ban_interval <= time(NULL)) {
		++ie->failed_attempts;
	} else {
		ie->failed_attempts = 1;
	}

	ie->last_failed_attempt_timestamp = time(NULL);
}

int ipban_get_faildattempts(uint32 ip)
{
	struct ipban_entry *ie = uidb_ensure(ipban->p->ipban, ip, ipban->p->ensure_entry);

	if (ie->last_failed_attempt_timestamp + ipban->p->config->dynamic_pass_failure_ban_interval >= time(NULL)) {
		return 0;
	} else {
		return ie->failed_attempts;
	}
}

struct DBData ipban_ensure_entry (union DBKey key, va_list args)
{
	struct ipban_entry *ie = NULL;
	CREATE(ie, struct ipban_entry, 1);
	ie->ip = key.ui;
	ie->end_timestamp = 0;
	ie->failed_attempts = 0;
	ie->last_failed_attempt_timestamp = 0;
	return DB->ptr2data(ie);
}

// remove expired bans
int ipban_cleanup(int tid, int64 tick, int id, intptr_t data) {
	struct DBIterator *iter;
	struct ipban_entry *ie;

	iter = db_iterator(ipban->p->ipban);
	for (ie = dbi_first(iter); dbi_exists(iter); ie = dbi_next(iter)) {
		if (ie->end_timestamp <= time(NULL))
			uidb_remove(ipban->p->ipban, ie->ip);
	}

	dbi_destroy(iter);

	return 0;
}

bool ipban_is_enabled(void)
{
	return ipban->p->config->enabled;
}

void ipban_defaults (void)
{
	ipban = &ipban_s;
	ipban->p = &ipban_p;
	ipban->p->config = &config_s;

	ipban->p->config->cleanup_interval = 60;
	ipban->p->config->enabled = true;
	ipban->p->config->dynamic_pass_failure_ban = true;
	ipban->p->config->dynamic_pass_failure_ban_interval = 5;
	ipban->p->config->dynamic_pass_failure_ban_limit = 7;
	ipban->p->config->dynamic_pass_failure_ban_duration = 5;

	ipban->p->ipban = NULL;
	ipban->p->cleanup_timer_id = INVALID_TIMER;
	ipban->p->inited = false;
	ipban->p->cleanup = ipban_cleanup;
	ipban->p->config_read_dynamic = ipban_config_read_dynamic;
	ipban->p->ensure_entry = ipban_ensure_entry;

	ipban->init = ipban_init;
	ipban->final = ipban_final;
	ipban->check = ipban_check;
	ipban->log = ipban_log;
	ipban->config_read = ipban_config_read;
	ipban->is_enabled = ipban_is_enabled;
	ipban->log_faildattempt = ipban_log_faildattempt;
	ipban->get_faildattempts = ipban_get_faildattempts;
}
