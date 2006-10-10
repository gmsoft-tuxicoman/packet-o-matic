
#ifndef __TARGET_TAP_H__
#define __TARGET_TAP_H__

#include <linux/if_tun.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>



#include "modules_common.h"
#include "rules.h"

struct target_priv_tap {

	int fd;

};

int target_register_tap();

int target_init_tap(struct target *t);
int target_open_tap(struct target *t);
int target_process_tap(struct target *t, struct rule_node *node, void *frame, unsigned int len);
int target_close_tap(struct target *t);
int target_cleanup_tap(struct target *t);

#endif
