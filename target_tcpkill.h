
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

struct target_priv_tcpkill {

	int routed; // 1 if mode is routed
	int socket;
	int ifindex;
	unsigned int severity;
};

int target_init_tcpkill(struct target *t);
int target_open_tcpkill(struct target *t);
int target_process_tcpkill(struct target *t, struct rule_node *node, void *frame, unsigned int len);
int target_close_tcpkill(struct target *t);
int target_cleanup_tcpkill(struct target *t);

#endif
