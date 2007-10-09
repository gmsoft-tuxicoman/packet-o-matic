/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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



#ifndef __INPUT_H__
#define __INPUT_H__

#undef MAX_INPUT
/// Maximum number of inputs
#define MAX_INPUT 16

/// This structure is used to retreive the capabilities of the current opened input
struct input_caps {

	unsigned int snaplen; ///< Snaplen of the input
	int is_live; ///< Define if the opened input is reading prerecorded pcakets or is capturing live traffic

};

/// This structure retains info about the different parameters for an input
struct input_param {

	char *name; ///< Name of the parameter
	char *defval; ///< Default value
	char *descr; ///< Description 
	struct ptype *value; ///< User modifiable value
	struct input_param *next; ///< Used for linking
};

/// This structure will save the possible modes for the input
struct input_mode {
	char *name; ///< Mode name
	char *descr; ///< Description of what it's used for
	struct input_param *params; ///< Pointer to parameters associated with this mode
	struct input_mode *next; ///< Used for linking
};

/// This structure saves infos about an input instances
struct input {
	int type; ///< Unique number assigned to this type of input
	void *input_priv; ///< Private stuff, place to store a struct used by the input internaly
	struct input_mode *mode; ///< Current input mode
	int running; ///< Set to 1 if the input is running or 0 if not
};



/// This structure saves infos about a registered input
/**
 * When the register function of an input is called, it must fill the following fields :
 * - init
 * - open
 * - read
 * - close
 * - cleanup
 **/
struct input_reg {

	char *name; ///< Name of the input
	int type; ///< Unique ID of the input
	void *dl_handle; ///< Handle of the library

	/// Pointer to the initialization function of the input
	/**
	 * The init function is called when we create the input.
	 * Returns POM_OK on success and POM_ERR on failure.
	 **/
	int (*init) (struct input *i);

	/// Pointer to the open function of the input
	/**
	 * The open function is called when opening the input.
	 * Returns a seclectable file descriptor on success and POM_ERR on failure.
	 **/
	int (*open) (struct input *i);

	/// Pointer to the read function
	/**
	 *  Reads a packet and store it in the buffer present in the frame structure.
	 *  It must populate first_layer, len and buff. Set len to 0 if nothing was read.
	 *  Return POM_OK or POM_ERR in case of fatal error.
	 **/
	int (*read) (struct input *i, struct frame *f);

	/// Pointer to the close fonction
	/**
	 * Close the input.
	 * Returns POM_OK on success and POM_ERR on failure.
	 **/
	int (*close) (struct input *i);

	/// Pointer to the cleanup function
	/**
	 * Cleanup the input once we don't need it anymore.
	 * Returns POM_OK on success and POM_ERR on failure.
	 **/
	int (*cleanup) (struct input *i);

	/// Pointer to the unregister function
	/**
	 * Free the memory allocated at registration time.
	 * Returns POM_OK on success and POM_ERR on failure.
	 **/
	 int (*unregister) (struct input_reg *r);

	/// Pointer to the fonction to provide the capabilities of an input
	/**
	 * Fills the struct input_caps with the capabilities of the input.
	 * The input must be opened or POM_ERR will be returned.
	 * Returns POM_OK on success and POM_ERR on failure.
	 **/

	int (*getcaps) (struct input *i, struct input_caps *ic);

	/// Pointer to the different possible modes.
	struct input_mode *modes;

};

/// This structure provides usefull fonction pointers for the inputs
struct input_functions {
	void (*pom_log) (const char *format, ...); ///< Log something in the console
	int (*match_register) (const char *); ///< Register a match
	struct input_mode *(*register_mode) (int, const char *, const char *); ///< Register a mode for the current input
	int (*register_param) (struct input_mode *, char *, char *, struct ptype*, char *); ///< Register a parameter for a specific mode
	struct ptype* (*ptype_alloc) (const char* , char*); ///< Allocate a struct ptype
	int (*ptype_cleanup) (struct ptype* p); ///< Cleanup the allocated struct
	int (*ptype_snprintf) (struct ptype*, char*, size_t);
};

/// Registers a new input by it's name.
int input_register(const char *input_name);

/// Register a mode for an input
struct input_mode *input_register_mode(int input_type, const char *name, const char *descr);

/// Set the mode of an input
int input_set_mode(struct input *i, char *mode_name);

// Register a parameter for a specific input mode
int input_register_param(struct input_mode *mode, char *name, char *defval, struct ptype *value, char *descr);

/// Give the input name from it's type
char *input_get_name(int input_type);

/// Create a new input and returns its structure.
struct input *input_alloc(int input_type);

/// Open the input.
int input_open(struct input *i);

/// Read a packet from the input.
int input_read(struct input *i, struct frame *f);

/// Close the input.
int input_close(struct input *i);

/// Cleanup the input stuff.
int input_cleanup(struct input *i);

// Unregister an input.
int input_unregister(int input_type);

/// Unregister all the inputs.
int input_unregister_all();

/// Display the help of every input.
void input_print_help();

/// Return current input caps
int input_getcaps(struct input *i, struct input_caps *ic); 


#endif

