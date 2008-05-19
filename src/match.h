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



#ifndef __MATCH_H__
#define __MATCH_H__

#include "layer.h"

/**
 * @defgroup match_api Match API
 */
/*@{*/

/// Contains info about the possible fields for this match
struct match_field_reg {
	char *name; ///< Name of the field
	struct ptype *type; ///< Allocated ptype that will show how to allocate subsequent fields
	char *descr; ///< Description of the field

};

/// Contains info about match dependencies
struct match_dep {
	char *name; ///< Name of the dependency
	int id; ///< Type of the match
};
/*@}*/


/**
 * @defgroup match_core Match core functions
 */
/*@{*/
#undef MAX_MATCH

/// Maximum of register matches
#define MAX_MATCH 16

/// Variable that hold info about all the registered matches
struct match_reg *matches[MAX_MATCH];

/*@}*/
/** @defgroup match_api **/
/*@{*/
/// Save infos about a registered match
struct match_reg {

	char *name; ///< Name of the match
	unsigned int type; ///< Type of the match
	struct match_field_reg *fields[MAX_LAYER_FIELDS]; ///< Possible fields for the match
	void *dl_handle; ///< Handle of the library
	unsigned int refcount; ///< Reference count
	struct match_dep match_deps[MAX_MATCH]; ///< Match dependencies

	/// Pointer to the identify function
	/**
	 * Identifies the next layer of a packet.
	 * @param f Frame to identify
	 * @param l The current layer
	 * @param start Offset of this layer in the buffer
	 * @param len Length of this layer
	 * @return POM_OK on success, POM_ERR if there is nothing more to identify or on error.
	 */
	int (*identify) (struct frame *f, struct layer* l, unsigned int start, unsigned int len);

	/// Pointer to the get_expectation function
	/**
	 * This function gives what field should we copy the value to the current field.
	 * @param field_id Field for which we want a value
	 * @param direction Direction of the expectation
	 * @return Field from which we should take the value from or POM_ERR on error.
	 */
	int (*get_expectation) (int field_id, int direction);

	/// Pointer to the unregister function
	/**
	 * Called when unregistering the match.
	 * @param r What match to unregister
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*unregister) (struct match_reg *r);

};

/// save info about a field
struct match_field {
	unsigned int type; ///< Type of the corresponding match
	int id; ///< Id of this field for this match
	struct ptype *value; ///< Value that we should compare with
	int op; ///< Operator on the value

};

/*@}*/


/// Init the match subsystem
int match_init();

/// Register a match
int match_register(const char *match_name);

/// Register a field for this match
int match_register_field(int match_type, char *name, struct ptype *type, char *descr);

/// Add a dependency for a match on another match
struct match_dep *match_add_dependency(int match_type, const char *dep_name);

/// Allocate a match field
struct match_field *match_alloc_field(int match_type, char *field_type);

/// Deallocate a match field
int match_cleanup_field(struct match_field *p);

/// Get the type of the match from its name
int match_get_type(const char *match_name);

/// Get the name of the match from its type
char *match_get_name(int match_type);

/// Get a field of a certain match based on their type
struct match_field_reg *match_get_field(int match_type, int field_id);

/// Identify the next layer
int match_identify(struct frame *f, struct layer *l, unsigned int start, unsigned int len);

/// Get the field id for the epxectation
int match_get_expectation(int match_type, int field_id, int direction);

/// Evalute a match field against a later
int match_eval(struct match_field *mf, struct layer *l);

/// Increase the reference count on a match
int match_refcount_inc(int match_type);

/// Decrease the reference count on a match
int match_refcount_dec(int match_type);

/// Cleanup the match subsystem
int match_cleanup();

/// Unregister a match
int match_unregister(unsigned int match_type);

/// Unregister all the matches
int match_unregister_all();

/// Print the help of all the loaded matches
void match_print_help();


#endif

