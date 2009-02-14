/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __HELPER_H__
#define __HELPER_H__


#include "common.h"
#include "rules.h"

/**
 * @defgroup helper_api Helper API
 */
/*@{*/

/// Stores informations about a frame that needs to be processed
struct helper_frame {

	struct frame *f; ///< The frame
	struct helper_frame *next; ///< Next frame in the list

};

/// Stores informations about a frame parameter
struct helper_param {

	char *name; ///< Name of the parameter
	char *defval; ///< Default value of the parameter
	char *descr; ///< Description of the parameter
	struct ptype *value; ///< Value of the parameter
	struct helper_param *next; ///< Used for linking

};

/// This structure hold all the information about the registered helpers
struct helper_reg {

	int type; ///< Unique id of the helper
	void *dl_handle; ///< Handle of the library

	/// Pointer to the need_help function
	/**
	 * @param f The frame to possibly apply helper on
	 * @param start The start of the current layer in the provided frame
	 * @param len Length of this layer in the pcaket
	 * @param l Layer we are currently handling
	 * @return POM_OK if no help is needed, H_NEED_HELP if help is needed and the packet should not be process, or POM_ERR on failure.
	 */
	int (*need_help) (struct frame *f, unsigned int start, unsigned int len, struct layer *l);

	/// Pointer to the resize function
	/**
	 * @param f The frame for which to resize the payload
	 * @param start The start of the current layer in the provided frame
	 * @param new_psize The new payload length for the current layer
	 */
	int (*resize) (struct frame *f, unsigned int start, unsigned int new_psize);

	/// Pointer to the cleanup function
	/**
	 * @return POM_OK on sucess, POM_ERR on error.
	 */
	int (*cleanup) (void);

	struct helper_param *params; ///< Parameters of this helper


};
/*@}*/

/**
 * @defgroup helper_core Helper core functions
 */
/*@{*/

/// Return value if the packet needs to be processed by the helper in helper_need_help
#define H_NEED_HELP 1

/// Maximum number of registered helper
#define MAX_HELPER MAX_MATCH

/// This variable saves info about all the registered helpers
extern struct helper_reg *helpers[MAX_HELPER];

/// This variable keeps track of the changes that occured to the helpers
extern uint32_t helpers_serial;

/*@}*/

/// Init the helper subsystem
int helper_init();

/// Register a new helper
int helper_register(const char *name);

/// Register a parameter for an helper
int helper_register_param(int helper_type, char *name, char *defval, struct ptype *value, char *descr);

/// Get the parameter of a helper
struct helper_param* helper_get_param(int helper_type, char* param_name);

/// Process a packet to see if it needs some help
int helper_need_help(struct frame *f, unsigned int start, unsigned int len, struct layer *l);

/// Queue a frame for processing
int helper_queue_frame(struct frame *f);

/// Process queued frames
int helper_process_queue(struct rule_list *list, pthread_rwlock_t *lock);

/// Unregister a helper
int helper_unregister(int helper_type);

/// Unregister all the helpers
int helper_unregister_all();

/// Update headers when resizing a payload
int helper_resize_payload(struct frame *f, struct layer *l, unsigned int new_psize);

/// Get a read or write lock on the helpers
int helper_lock(int write);

/// Release a read or write lock on the helpers
int helper_unlock();

/// Cleanup the helper subsystem
int helper_cleanup();


#endif
