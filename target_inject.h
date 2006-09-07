
#ifndef __TARGET_INJECT_H__
#define __TARGET_INJECT_H__

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>


#include "modules_common.h"
#include "target.h"

struct target_priv_inject {

	int socket;
	struct sockaddr_ll sal;
	unsigned int size;
};

int target_init_inject(struct target *t);
int target_open_inject(struct target *t, const char *device);
int target_process_inject(struct target *t, struct rule_node *node, void *frame, unsigned int len);
int target_close_inject(struct target *t);
int target_cleanup_inject(struct target *t);

#endif
