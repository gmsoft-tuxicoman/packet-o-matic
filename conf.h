

#ifndef __CONF_H__
#define __CONF_H__

#include "common.h"

struct conf {

	struct input* input;
	struct rule_list *rules;

};

struct conf *config_alloc();

int config_parse(struct conf*, char *);

int config_cleanup(struct conf*);


#endif
