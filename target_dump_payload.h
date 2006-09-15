
#ifndef __TARGET_DUMP_PAYLOAD_H__
#define __TARGET_DUMP_PAYLOAD_H__


#include "modules_common.h"
#include "rules.h"

struct target_priv_dump_payload {

	char prefix[NAME_MAX];

};

struct target_conntrack_priv_dump_payload {

	int fd;

};

int target_register_dump_payload();

int target_init_dump_payload(struct target *t);
int target_open_dump_payload(struct target *t, const char *filename);
int target_process_dump_payload(struct target *t, struct rule_node *node, void *frame, unsigned int len);
int target_close_dump_payload(struct target *t);
int target_cleanup_dump_payload(struct target *t);

#endif
