

#ifndef __INPUT_H__
#define __INPUT_H__

#include "common.h"

struct input {
	int input_type;
	char **params_value;
	void *input_priv;
	int (*match_register) (const char *);
};

struct input_reg {

	char *input_name;
	void *dl_handle;
	char **params_name;
	char **params_help;
	int (*init) (struct input *i);
	int (*open) (struct input *i);
	int (*get_first_layer) (struct input *i);
	int (*read) (struct input *i, unsigned char *buffer, unsigned int bufflen);
	int (*close) (struct input *i);
	int (*cleanup) (struct input *i);

};

int input_register(const char *input_name);
struct input *input_alloc(int input_type);
int input_set_param(struct input *i, char *name, char* value);
int input_open(struct input *i);
int input_get_first_layer(struct input *i);
inline int input_read(struct input *i, unsigned char *buffer, unsigned int bufflen);
int input_close(struct input *i);
int input_cleanup(struct input *i);
int input_unregister_all();
void input_print_help();


#endif

