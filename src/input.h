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

/// Return value in case of error
#define I_ERR -1

/// Return value on success
#define I_OK 0

/// This structure saves infos about an input instances
struct input {
	int input_type; ///< Unique number assigned to this type of input.
	char **params_value; ///< Values of the parametres.
	void *input_priv; ///< Private stuff, place to store a struct used by the input internaly.
};

/// This structure saves infos about a registered input
/**
 * When the register function of an input is called, it must fill the following fields :
 * - params_name
 * - params_help
 * - init
 * - open
 * - get_first_layer
 * - read
 * - close
 * - cleanup
 **/
struct input_reg {

	char *input_name; ///< Name of the input
	void *dl_handle; ///< Handle of the library
	char **params_name; ///< Parameter names
	char **params_help; ///< Parameter help strings

	/// Pointer to the initialization function of the input
	/**
	 * The init function is called when we create the input.
	 * Returns I_OK on success and I_ERR on failure.
	 **/
	int (*init) (struct input *i);

	/// Pointer to the open function of the input
	/**
	 * The open function is called when opening the input.
	 * Returns a seclectable file descriptor on success and I_ERR on failure.
	 **/
	int (*open) (struct input *i);

	/// Pointer to get_first_layer function
	/**
	 * The get_first_layer function is used by the program to know what type of layer the input provides.
	 * It returns the type of the layer or I_ERR.
	 **/
	int (*get_first_layer) (struct input *i);

	/// Pointer to the read function
	/**
	 *  Reads a packet and store it in the buffer.
	 *  Return the number of bytes copied. Return 0 if nothing was read and I_ERR in case of fatal error.
	 **/
	int (*read) (struct input *i, unsigned char *buffer, unsigned int bufflen);

	/// Pointer to the close fonction
	/**
	 * Close the input.
	 * Returns I_OK on success and I_ERR on failure.
	 **/
	int (*close) (struct input *i);

	/// Pointer to the cleanup function
	/**
	 * Cleanup the input once we don't need it anymore.
	 * Returns I_OK on success and I_ERR on failure.
	 **/
	int (*cleanup) (struct input *i);

};

/// This structure provides usefull fonction pointers for the inputs
struct input_functions {
	int (*match_register) (const char *); ///< Register a match
};

/// Registers a new input by it's name.
int input_register(const char *input_name);

/// Create a new input and returns its structure.
struct input *input_alloc(int input_type);

/// Set a parameter of an input.
int input_set_param(struct input *i, char *name, char* value);

/// Open the input.
int input_open(struct input *i);

/// Gives the layer type of the packets returned by the input.
int input_get_first_layer(struct input *i);

/// Read a packet from the input.
inline int input_read(struct input *i, unsigned char *buffer, unsigned int bufflen);

/// Close the input.
int input_close(struct input *i);

/// Cleanup the input stuff.
int input_cleanup(struct input *i);

/// Unregister all the inputs.
int input_unregister_all();

/// Display the help of every input.
void input_print_help();


#endif

