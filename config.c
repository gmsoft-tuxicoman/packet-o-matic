
#include "common.h"
#include "config.h"

#include "match_ethernet.h"
#include "match_ipv4.h"
#include "match_tcp.h"
#include "match_udp.h"

#include "conntrack.h"

#include "target.h"

struct rule_list *alloc_rule_list() {

	struct rule_list *rules;

	rules = malloc(sizeof(struct rule_list));
	bzero(rules, sizeof(struct rule_list));

	return rules;
}

struct rule_node *alloc_rule_node() {

	struct rule_node *node;

	node = malloc(sizeof(struct rule_node));
	bzero(node,sizeof(struct rule_node));

	return node;
}


struct rule_list* do_config() {

	struct rule_list *rules, *head;
	struct rule_node *node;

	head = alloc_rule_list();

	rules = head;


	int match_ethernet = match_register("ethernet");
	int match_ipv4 = match_register("ipv4");
	int match_tcp = match_register("tcp");
	int match_udp = match_register("udp");
	int match_rtp = match_register("rtp");

	int target_wave = target_register("wave");
	int target_tap = target_register("tap");
	int target_pcap = target_register("pcap");
	int target_inject = target_register("inject");
	//int target_dump_payload = target_register("dump_payload");

	conntrack_init();
	conntrack_register("ipv4");
	conntrack_register("udp");
	conntrack_register("tcp");
	conntrack_register("rtp");

	/***** FIRST RULE *****/


	dprint("Adding rule 1\n");
	
	
	rules->target = target_alloc(target_tap);
	target_open(rules->target, "docsis0");
	
	

	// Adding ethernet as first rule	
	node = alloc_rule_node();
	rules->node = node;
	node->match = match_alloc(match_ethernet);
	

	/***** SECOND RULE *****/

	dprint("Adding rule 2\n");
	
	// Let's reinject port 25 packets !

	rules->next = alloc_rule_list();
	rules = rules->next;
	

	rules->target = target_alloc(target_inject);
	target_open(rules->target, "eth0.4");

	// Adding ethernet as first rule	
	node = alloc_rule_node();
	rules->node = node;
	node->match = match_alloc(match_ethernet);

	// Match my mac address
	struct match_priv_ethernet *me = malloc(sizeof(struct match_priv_ethernet));
	bzero(me, sizeof(struct match_priv_ethernet));
	unsigned char dmac[6] = { 0x00, 0x10, 0xA7, 0x0E, 0x20, 0x67};
	memcpy(me->dmac, dmac, 6);
	memset(me->dmac_mask, 0xFF, 6);
	match_config(node->match, me);

	// Adding ipv4
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_ipv4);

	// Match my ip address
	struct match_priv_ipv4 *mi = malloc(sizeof(struct match_priv_ipv4));
	bzero(mi, sizeof(struct match_priv_ipv4));
	bzero(mi, sizeof(struct match_priv_ipv4));
	inet_aton("85.28.84.48", &mi->daddr);
	inet_aton("255.255.255.255", &mi->dnetmask);
	match_config(node->match, mi);
	

	// Adding tcp
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_tcp);

	// Match port 25
	struct match_priv_tcp *mt = malloc(sizeof(struct match_priv_tcp));
	bzero(mt, sizeof(struct match_priv_tcp));
	mt->sport_min = 0;
	mt->sport_max = 65535;
	mt->dport_min = 25;
	mt->dport_max = 25;
	match_config(node->match, mt);


	/***** SECOND RULE *****/

	dprint("Adding rule 2\n");
	
	// Let's reinject port 25 packets !

	rules->next = alloc_rule_list();
	rules = rules->next;
	

	rules->target = target_alloc(target_wave);
	target_open(rules->target, "/mnt/nfs/temp/rtp/rtp-");

	// Adding ethernet as first rule	
	node = alloc_rule_node();
	rules->node = node;
	node->match = match_alloc(match_ethernet);

	// Adding ipv4
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_ipv4);

	// Match some ipv4
	mi = malloc(sizeof(struct match_priv_ipv4));
	bzero(mi, sizeof(struct match_priv_ipv4));
	bzero(mi, sizeof(struct match_priv_ipv4));
	inet_aton("10.0.0.0", &mi->daddr);
	inet_aton("255.0.0.0", &mi->dnetmask);
	match_config(node->match, mi);
	

	// Adding udp
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_udp);

	// Match port > 3000
	struct match_priv_udp *mu = malloc(sizeof(struct match_priv_udp));
	bzero(mu, sizeof(struct match_priv_udp));
	mu->sport_min = 3000;
	mu->sport_max = 65535;
	mu->dport_min = 3000;
	mu->dport_max = 65535;
	match_config(node->match, mu);


	// Adding rtp
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_rtp);


	return head;

	/***** THIRD RULE *****/

	dprint("Adding rule 3\n");

	// Let's see if there is something on port 110 !

	rules->next = alloc_rule_list();
	rules = rules->next;
	

	rules->target = target_alloc(target_pcap);
	target_open(rules->target, "port110.cap");
	
	

	// Adding ethernet as first rule	
	node = alloc_rule_node();
	rules->node = node;
	node->match = match_alloc(match_ethernet);

	// Adding ipv4
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_ipv4);

	// Adding tcp
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_tcp);

	// Match port 110
	mt = malloc(sizeof(struct match_priv_tcp));
	bzero(mt, sizeof(struct match_priv_tcp));
	mt->sport_min = 110;
	mt->sport_max = 110;
	mt->dport_min = 0;
	mt->dport_max = 65535;
	match_config(node->match, mt);
	
	/***** FOURST RULE *****/

	dprint("Adding rule 4\n");

	// Let's see if there is something on port 6666-6669 !

	rules->next = alloc_rule_list();
	rules = rules->next;
	
	rules->target = target_alloc(target_pcap);
	target_open(rules->target, "port6667.cap");
	
	

	// Adding ethernet as first rule	
	node = alloc_rule_node();
	rules->node = node;
	node->match = match_alloc(match_ethernet);

	// Adding ipv4
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_ipv4);

	struct rule_node *parent = node;

	// Adding tcp
	parent->a = alloc_rule_node();
	node = parent->a;
	node->match = match_alloc(match_tcp);

	// Match source port 6666-6669
	mt = malloc(sizeof(struct match_priv_tcp));
	bzero(mt, sizeof(struct match_priv_tcp));
	mt->sport_min = 6666;
	mt->sport_max = 6669;
	mt->dport_min = 0;
	mt->dport_max = 65535;
	match_config(node->match, mt);
	
	// Adding tcp
	parent->b = alloc_rule_node();
	node = parent->b;
	node->match = match_alloc(match_tcp);

	// Match dest port 6666-6669
	mt = malloc(sizeof(struct match_priv_tcp));
	bzero(mt, sizeof(struct match_priv_tcp));
	mt->sport_min = 0;
	mt->sport_max = 65535;
	mt->dport_min = 6666;
	mt->dport_max = 6669;
	match_config(node->match, mt);


	/***** FIFT RULE *****/

	dprint("Adding rule 5\n");
	

	rules->next = alloc_rule_list();
	rules = rules->next;

	rules->target = target_alloc(target_pcap);
	target_open(rules->target, "rtp.cap");

	// Adding ethernet as first rule	
	node = alloc_rule_node();
	rules->node = node;
	node->match = match_alloc(match_ethernet);

	// Adding ipv4
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_ipv4);

	mi = malloc(sizeof(struct match_priv_ipv4));
	bzero(mi, sizeof(struct match_priv_ipv4));
	inet_aton("10.0.0.0", &mi->saddr);
	inet_aton("255.0.0.0", &mi->snetmask);
	match_config(node->match, mi);
	

	// Adding udp
	node->a = alloc_rule_node();
	node = node->a;
	node->match = match_alloc(match_udp);

	// Match rtp ports
	mu = malloc(sizeof(struct match_priv_udp));
	bzero(mu, sizeof(struct match_priv_udp));
	mu->sport_min = 0;
	mu->sport_max = 65535;
	mu->dport_min = 16384;
	mu->dport_max = 65535;
	match_config(node->match, mu);
	
	dprint("Config done\n");
	
	return head;


}
