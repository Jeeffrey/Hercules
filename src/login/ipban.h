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
#ifndef LOGIN_IPBAN_H
#define LOGIN_IPBAN_H

#include "common/cbasetypes.h"
#include "common/hercules.h"

/* Forward Declarations */
struct config_t; // common/conf.h
struct ipban_interface_private;

// The login ipban automatic ban interface
struct ipban_interface {
	struct ipban_interface_private *p; ///< Private interface
	void (*init) (void);
	void (*final) (void);
	bool (*check) (uint32 ip);
	void (*log) (uint32 ip);
	bool (*config_read) (const char *filename, struct config_t *config, bool imported);
	bool (*is_enabled) (void);
	void (*log_faildattempt) (uint32 ip);
	int  (*get_faildattempts) (uint32 ip);
};

#ifdef HERCULES_CORE
void ipban_defaults(void);
#endif // HERCULES_CORE

HPShared struct ipban_interface *ipban;

#endif /* LOGIN_IPBAN_H */
