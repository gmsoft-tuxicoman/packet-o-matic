

#ifndef __INPUT_H__
#define __INPUT_H__

#include "common.h"

struct input {
	int input_type;
	void *input_priv;
};

struct input_reg {

	char *input_name;
	void *dl_handle;
	int (*init) (struct input *i);
	int (*open) (struct input *i, void *params);
	int (*read) (struct input *i, unsigned char *buffer, unsigned int bufflen);
	int (*close) (struct input *i);
	int (*cleanup) (struct input *i);

};

int input_register(const char *input_name);
struct input *input_alloc(int input_type);
int input_open(struct input *i, void *params);
inline int input_read(struct input *i, unsigned char *buffer, unsigned int bufflen);
int input_close(struct input *i);
int input_cleanup(struct input *i);
int input_unregister_all();



#endif

