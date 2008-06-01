/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include "rules.h"
#include "common.h"
#include "timers.h"
#include "helper.h"

#include <jhash.h>

/**
 * @defgroup conntrack_api Conntrack API
 */
/*@{*/

/// One way only conntrack
/**
 * The conntrack modules should set their flags to CT_DIR_ONEWAY.
 * If the conntrack cannot match a reverse direction. 
 * When computing the hash, CT_DIR_ONEWAY must be used to match both the forward direction and the one way direction.
 */
#define CT_DIR_ONEWAY 0

/// The forward direction
/**
 * Used to compute the forward hash. This is the forward direction WITHOUT the one way direction.
 */
#define CT_DIR_FWD 1

/// The reverse direction
/**
 * Used to compute the reverse hash.
 * The conntrack modules with CT_DIR_ONEWAY will be ignored.
 */
#define CT_DIR_REV 2

/// Both directions
/**
 * The conntrack modules should set their flags to CT_DIR_BOTH if they can handle both directions.
 */
#define CT_DIR_BOTH 3

/// Unknown direction flag in conntrack_entry
#define CE_DIR_UNK -1

/// Forward direction flag in conntrack_entry
#define CE_DIR_FWD 0

/// Reverse direction flag in conntrack_entry
#define CE_DIR_REV 1

/*@}*/
/**
 * @defgroup conntrack_core Conntrack core functions
 */
/*@{*/

/// This structure contains all that needs to be known about a connection.
struct conntrack_entry {

	uint32_t full_hash; ///< Hash of this conntrack
	struct conntrack_match_priv *match_privs; ///< Matchs' private data
	struct conntrack_helper_priv *helper_privs; ///< Helpers' private data
	struct conntrack_target_priv *target_privs; ///< Targets' private data
	unsigned int direction; ///< Direction of the packet that matched
	struct conntrack_entry *parent_ce; ///< Parent entry if this matched an expectation

};


/// Structure used to avoid collisions if two connections have the same hash
struct conntrack_list {

	uint32_t hash; ///< Hash of this conntrack
	struct conntrack_entry *ce; ///< Corresponding connection
	struct conntrack_list *next; ///< Next connection in the list
	struct conntrack_list *rev; ///< Reverse connection

};

/*@}*/
/**
 * @ingroup conntrack_api
 */
/*@{*/
/// Structure that holds info about a conntrack parameter
struct conntrack_param {

	char *name; ///< Name of the parameter
	char *defval; ///< Default value
	char *descr; ///< Description
	struct ptype *value; ///< Actual value
	struct conntrack_param *next; ///< Used for linking
};

struct conntrack_reg {

	int type;
	void *dl_handle;
	unsigned int flags;
	unsigned int refcount;
	uint32_t (*get_hash) (struct frame *f, unsigned int start, unsigned int flags);
	int (*doublecheck) (struct frame *f, unsigned int start, void *priv, unsigned int flags);
	void* (*alloc_match_priv) (struct frame *f, unsigned int start, struct conntrack_entry *ce);
	int (*cleanup_match_priv) (void *priv);
	int (*unregister) (struct conntrack_reg *r);
	struct conntrack_param *params;

};

/// Structure which hold usefull data to identify the connection
struct conntrack_match_priv {

	struct conntrack_match_priv *next; ///< Used for linking
	unsigned int priv_type; ///< Type of match
	void *priv; ///< Private data of the match


};

/// Structure which hold private data for a target
struct conntrack_target_priv {

	struct conntrack_target_priv *next; ///< Next private stuff in the list
	struct target *t; ///< Target to which belongs the data
	void *priv; ///< The private data itself
	int (*cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv); ///< Handler used to cleanup the conntrack priv

};

/// Structure which hold private data for an helper
struct conntrack_helper_priv {

	struct conntrack_helper_priv *next; ///< Next private stuff in the list
	unsigned int type; ///< Type of helper
	void *priv; ///< The private data itself
	int (*flush_buffer) (struct conntrack_entry *ce, void *priv); ///< Handler used to flush the remaining packets in the helper if needed
	int (*cleanup_handler) (struct conntrack_entry *ce, void *priv); ///< Handler used to cleanup the conntrack priv

};

/*@}*/

#define MAX_CONNTRACK MAX_MATCH

/// Variable that holds info about all the registered conntracks
struct conntrack_reg *conntracks[MAX_CONNTRACK];

/// Init the conntrack subsystem
int conntrack_init();

/// Register a conntrack module
int conntrack_register(const char *name);

/// Register a parameter for a conntrack
int conntrack_register_param(int conntrack_type, char *name, char *defval, struct ptype *alue, char *descr);

/// Get a parameter from a conntrack
struct conntrack_param *conntrack_get_param(int conntrack_type, char *param_name);

/// Add a target priv to a conntrack
int conntrack_add_target_priv(void *priv, struct target *t,  struct conntrack_entry *ce, int (*cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv));

/// Remove a target priv from a conntrack
int conntrack_remove_target_priv(void* priv, struct conntrack_entry *ce);

/// Add an helper priv to the conntrack
int conntrack_add_helper_priv(void *priv, int type, struct conntrack_entry *ce, int (*flush_buffer) (struct conntrack_entry *ce, void *priv), int (*cleanup_handler) (struct conntrack_entry *ce, void *priv));

/// Get the helper priv for this conntrack
void *conntrack_get_helper_priv(int type, struct conntrack_entry *ce);

/// Remove the helper priv from a conntrack
int conntrack_remove_helper_priv(void *priv, struct conntrack_entry *ce);

/// Get the target priv of a conntrack
void *conntrack_get_target_priv(struct target *t, struct conntrack_entry *ce);

/// Compute the conntrack hash of a packet
uint32_t conntrack_hash(struct frame *f, unsigned int flags);

/// Find a conntrack into a conntrack_list
struct conntrack_entry *conntrack_find(struct conntrack_list *cl, struct frame *f, unsigned int flags);

/// Get the conntrack entry for a packet if any
int conntrack_get_entry(struct frame *f);

/// Create a new conntrack entry for a packet
int conntrack_create_entry(struct frame *f);

/// Cleanup a conntrack entry
int conntrack_cleanup_connection (struct conntrack_entry *ce);

/// Callback function to process the timers
int conntrack_do_timer(void * ce);

/// Allocate a timer for a conntrack
struct timer *conntrack_timer_alloc(struct conntrack_entry *ce, struct input *i);

/// Close a connection
int conntrack_close_connections(struct rule_list *r);

/// Cleanup the conntrack subsystem
int conntrack_cleanup();

/// Unregister a conntrack
int conntrack_unregister(int conntrack_type);

/// Unregister all the conntracks
int conntrack_unregister_all();


#endif
