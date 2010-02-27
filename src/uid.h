/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __UID_H__
#define __UID_H__

#include "common.h"

/// Init the uid API
int uid_init();

/// Check if a uid is already used
int uid_check(uint32_t uid);

/// Get a new unused uid
uint32_t uid_get_new();

/// Set a known uid or return a new one if it already exists
uint32_t uid_set(uint32_t uid);

/// Release a used uid
int uid_release(uint32_t uid);

/// Lock the uid table
int uid_lock();

/// Unlock the uid table
int uid_unlock();

/// Cleanup the uid API
int uid_cleanup();

#endif
