
#include <errno.h>

#include "target_null.h"

// Maximum segment len with ethernet header
#define MAX_SEGMENT_LEN 1518

int match_ethernet_id;

int target_register_null(struct target_reg *r) {

	r->process = target_process_null;

	return 1;

}

int target_process_null(struct target *t, struct rule_node *node, void *frame, unsigned int len) {

	ndprint("Packet processed\n");

	return 1;

}
