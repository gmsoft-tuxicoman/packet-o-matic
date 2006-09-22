

#ifndef __MATCH_H__
#define __MATCH_H__

#include "common.h"


struct match {
	unsigned int match_type; // Type of match
	int next_start; // Position of the header for the next match
	int next_layer; // Next layer found
	int next_size; // Length of the packet's content
	void *match_priv;
	struct match *next;
	struct match *prev;
	int (*match_register) (const char *);
};

struct match_reg {

	char *match_name;
	void *dl_handle;
	int (*init) (struct match *m);
	int (*config) (struct match *m, void *params);
	int (*eval) (struct match*, void*, unsigned int, unsigned int);
	int (*cleanup) (struct match *m);

};

int match_register(const char *match_name);
int match_get_type(const char *match_name);
struct match *match_alloc(int match_type);
int match_config(struct match *m, void *params);
int match_eval(struct match* m, void* frame, unsigned int start, unsigned int len);
int match_cleanup(struct match *m);
int match_unregister_all();



#endif

