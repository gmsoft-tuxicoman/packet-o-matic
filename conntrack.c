/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#include <signal.h>
#include <sys/time.h>

#include "conntrack.h"

#define MAX_CONNTRACK MAX_MATCH

#define CONNTRACK_SIZE 65535

#define INITVAL 0xdf92b6eb

/*
void check_list (struct conntrack_timer_queue *tq) {


	struct conntrack_timer *t;

	t = tq->head;

	if (t->prev != NULL)
		dprint("t->prev != NULL\n");


	while (t) {
		dprint("t\t0x%x (expires %u, conn 0x%u)\n", (unsigned) t, (unsigned) t->expires, (unsigned) t->ce);	
		if (!t->next) {
			if (t != tq->tail)
				dprint("Tail not set correctly\n");
		} else {
			if (t->next->prev != t)
				dprint("Prev not set correctly for 0x%x (0x%x)\n", (unsigned) t->next, (unsigned) t->next->prev);
		}
		t = t->next;

	}
	
} 

void check_queues (struct conntrack_timer_queue *tq) {


	dprint("checking queues\n");
	
	if (tq->prev != NULL)
		dprint("tq->prev != NULL\n");


	while (tq) {
		dprint("q 0x%x (expiry %u, head 0x%x, tail 0x%x)\n", (unsigned)tq, tq->expiry, (unsigned) tq->head, (unsigned) tq->tail);
		
		if (tq->next) {
			if (tq->next->prev != tq)
				dprint("Prev queue not set correctly for 0x%x (0x%x)\n", (unsigned) tq->next, (unsigned) tq->next->prev);
		}
		check_list(tq);

		tq = tq->next;

	}
	
} 
*/
struct conntrack_reg *conntracks[MAX_CONNTRACK];
struct conntrack_entry *ct_table[CONNTRACK_SIZE];
struct conntrack_timer_queue *timer_queues;
struct conntrack_functions *ct_funcs;
struct itimerval conntrack_itimer;

void conntrack_timeout_handler(int signal) {

	ndprint("Looking for timeouts ...\n");

	conntrack_do_timers();

}

int conntrack_init() {

	int i;
	
	for (i = 0; i < CONNTRACK_SIZE; i ++)
		ct_table[i] = NULL;

	// Setup signal handler for the timer

	signal(SIGALRM, conntrack_timeout_handler);

	// Setup the timer
	
	bzero(&conntrack_itimer, sizeof(struct itimerval));
	conntrack_itimer.it_interval.tv_sec = 1;
	conntrack_itimer.it_value.tv_usec = 500000;

	if (setitimer(ITIMER_REAL, &conntrack_itimer, NULL) != 0) {
		dprint("Error while setting up the timer for conntrack timeouts\n");
		return 0;
	}

	timer_queues = NULL;

	ct_funcs = malloc(sizeof(struct conntrack_functions));
	ct_funcs->alloc_timer = conntrack_timer_alloc;
	ct_funcs->cleanup_timer = conntrack_timer_cleanup;
	ct_funcs->queue_timer = conntrack_timer_queue;
	ct_funcs->dequeue_timer = conntrack_timer_dequeue;

	dprint("Conntrack initialized\n");
	
	return 1;

}

int conntrack_register(const char *conntrack_name) {


	int id;
	id = match_get_type(conntrack_name);
	if (id == -1) {
		dprint("Unable to register conntrack %s. Corresponding match not found\n", conntrack_name);
		return -1;
	}

	if (conntracks[id])
		return id;


	void *handle;
	char name[255];
	strcpy(name, "./conntrack_");
	strcat(name, conntrack_name);
	strcat(name, ".so");

	handle = dlopen(name, RTLD_NOW);

	if (!handle) {
		dprint("Unable to load conntrack %s : ", conntrack_name);
		dprint(dlerror());
		dprint("\n");
		return -1;
	}
	dlerror();

	strcpy(name, "conntrack_register_");
	strcat(name, conntrack_name);

	int (*register_my_conntrack) (struct conntrack_reg *, struct conntrack_functions *);

	
	register_my_conntrack = dlsym(handle, name);
	if (!register_my_conntrack) {
		dprint("Error when finding symbol %s. Could not load conntrack !\n", conntrack_name);
		return -1;
	}

	struct conntrack_reg *my_conntrack = malloc(sizeof(struct conntrack_reg));
	bzero(my_conntrack, sizeof(struct conntrack_reg));


	if (!(*register_my_conntrack) (my_conntrack, ct_funcs)) {
		dprint("Error while loading conntrack %s. Could not load conntrack !\n", conntrack_name);
		free(my_conntrack);
		return -1;
	}

	conntracks[id] = my_conntrack;
	conntracks[id]->dl_handle = handle;

	dprint("Conntrack %s registered\n", conntrack_name);


	return id;


}

int conntrack_add_target_priv(struct target *t, void *priv, struct rule_node *n, void* frame) {

	__u32 hash;
	hash = conntrack_hash(n, frame);

	struct conntrack_entry *ce;
	ce = conntrack_get_entry(hash, n, frame);

	struct conntrack_privs *cp;

	if (!ce) {
		ce = malloc(sizeof(struct conntrack_entry));
		bzero(ce, sizeof(struct conntrack_entry));
		ce->next = ct_table[hash];
		ct_table[hash] = ce;
		ce->hash = hash;

		struct match *m = n->match;
		// TODO : add matches in the opposite direction for speed
		while (m) {
			if (conntracks[m->match_type] && conntracks[m->match_type]->alloc_match_priv) {
				int start = 0;
				if (m->prev)
					start = m->prev->next_start;
				void *priv = (*conntracks[m->match_type]->alloc_match_priv) (frame, start, ce);
				cp = malloc(sizeof(struct conntrack_privs));
				cp->priv_type = m->match_type;
				cp->priv = priv;
				cp->next = ce->match_privs;
				ce->match_privs = cp;
			}
			m = m->next;
		}
	}

	// Let's see if that priv_type is already present

	cp = ce->target_privs;

	while (cp) {
		if (cp->priv_type == t->target_type) {
			dprint("Warning. Target priv already added\n");
			return 0;
		}
		cp = cp->next;
	}

	// Ok it's not. Creating a new conntrack_priv for our target

	cp = malloc(sizeof(struct conntrack_privs));
	bzero(cp, sizeof(struct conntrack_privs));

	cp->next = ce->target_privs;
	ce->target_privs = cp;

	cp->priv_type = t->target_type;
	cp->priv = priv;

	
	return 1;
}


void *conntrack_get_target_priv(struct target *t, struct rule_node *n, void *frame) {


	__u32 hash;
	hash = conntrack_hash(n, frame);

	struct conntrack_entry *ce;
	ce = conntrack_get_entry(hash, n, frame);

	if (!ce)
		return NULL;

	struct conntrack_privs *cp;
	cp = ce->target_privs;
	while (cp) {
		if (cp->priv_type == t->target_type) {
			return cp->priv;
		}
		cp = cp->next;
	}

	return NULL;
}


__u32 conntrack_hash(struct rule_node *n, void *frame) {


	struct match *m;
	m = n->match;

	// Compute our hash for each layer
	__u32 hash, res;
	hash = INITVAL;
	while (m) {

		if (conntracks[m->match_type]) {
			int start = node_find_header_start(n, m->match_type);
			res = (*conntracks[m->match_type]->get_hash) (frame, start);
			hash = jhash_2words(hash, res, INITVAL);

		}
		m = m->next;
	}

	hash %= CONNTRACK_SIZE;

	return hash;
}

struct conntrack_entry *conntrack_get_entry(__u32 hash, struct rule_node *n, void *frame) {
	
	// Doublecheck that we are talking about the right thing

	struct conntrack_entry *ce;
	ce = ct_table[hash];

	if (!ce)
		return NULL;
		
	struct conntrack_privs *cp;
	cp = ce->match_privs;

	while (cp) {
		int start = node_find_header_start(n, cp->priv_type);
		if (!(*conntracks[cp->priv_type]->doublecheck) (frame, start, cp->priv, ce)) {
			ce = ce->next; // If it's not the right conntrack entry, go to next one
			if (!ce)
				return NULL; // No entry matched
			cp = ce->match_privs;
			continue;
		}

		cp = cp->next;
	}

	return ce;

}
int conntrack_close_connnection (struct conntrack_entry *ce) {


	struct conntrack_privs *p, *tmp;
	p = ce->target_privs;
	while (p) {
		if (p->priv)
			target_close_connection(p->priv_type, p->priv);
		tmp = p;
		p = p->next;
		free(tmp);

	}

	// Ok this connection is closed. let's remove it

	// Remove the match privs
	p = ce->match_privs;
	while (p) {
		if (conntracks[p->priv_type] && conntracks[p->priv_type]->cleanup_match_priv)
			(*conntracks[p->priv_type]->cleanup_match_priv) (p->priv);

		tmp = p;
		p = p->next;
		free(tmp);
	}

	// Free the conntrack_entry itself
	

	if (ct_table[ce->hash] == ce) {
		ct_table[ce->hash] = ce->next;
	} else {
		struct conntrack_entry *tmpce;
		tmpce = ct_table[ce->hash];
		while (tmpce->next) {
			if (tmpce->next == ce) {
				tmpce->next = ce->next;
				break;
			}
			tmpce = tmpce->next;
		}
	}
	
	free (ce);


	return 1;
}

int conntrack_cleanup() {

	int i;

	// Stop the timers
	
	conntrack_itimer.it_value.tv_sec = 0;
	conntrack_itimer.it_value.tv_usec = 0;


	// Close remaining connections

	for (i = 0; i < CONNTRACK_SIZE; i ++) {
		while (ct_table[i]) {
			conntrack_close_connnection(ct_table[i]);
		}
	}

	free(ct_funcs);



	while (timer_queues) {
		struct conntrack_timer_queue *tmpq;
		tmpq = timer_queues;

		while (tmpq->head) {
			
			struct conntrack_timer *tmp;
			tmp = tmpq->head;

			tmpq->head = tmpq->head->next;

			free(tmp);

		}
		timer_queues = timer_queues->next;

		free(tmpq);
	}

	return 1;

}

int conntrack_unregister_all() {

	int i;

	for (i = 0; i < MAX_CONNTRACK; i++) {
		if (conntracks[i]) {
			dlclose(conntracks[i]->dl_handle);
			free(conntracks[i]);
			conntracks[i] = NULL;
		}

	}

	return 1;

}

int conntrack_do_timers() {


	struct conntrack_timer_queue *tq;
	tq = timer_queues;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	while (tq) {
		while (tq->head && tq->head->expires <= tv.tv_sec) {
				// Should we always close the connection when a timer pops up or should the conntrack handle it ?
				ndprint("Timer 0x%x for 0x%x reached. closing ...\n", (unsigned) tq->head, (unsigned)tq->head->ce);
				conntrack_close_connnection(tq->head->ce);
		}
		tq = tq->next;

	}

	return 1;
}

struct conntrack_timer *conntrack_timer_alloc(struct conntrack_entry *ce) {

	struct conntrack_timer *t;
	t = malloc(sizeof(struct conntrack_timer));
	bzero(t, sizeof(struct conntrack_timer));

	t->ce = ce;

	return t;
}

int conntrack_timer_cleanup(struct conntrack_timer *t) {

	if (t->next || t->prev) {
		dprint("Error timer not dequeued before cleanup\n");
		return 0;
	}

	free(t);
	
	return 1;
}

int conntrack_timer_queue(struct conntrack_timer *t, unsigned int expiry) {

	struct conntrack_timer_queue *tq;
	tq = timer_queues;

	if (t->prev || t->next) {
		dprint("Error, timer not dequeued correctly\n");
		return -1;
	}

	// First find the right queue or create it
	
	if (!tq) {

		// There is no queue yet
		tq = malloc(sizeof(struct conntrack_timer_queue));
		bzero(tq, sizeof(struct conntrack_timer_queue));
		timer_queues = tq;

		tq->expiry = expiry;

	} else {

		while (tq) {
			
			if (tq->expiry == expiry) { // The right queue already exists
				
				break;

			} else if (tq->expiry > expiry) { // The right queue doesn't exists and we are too far in the list

				struct conntrack_timer_queue *tmp;
				tmp = malloc(sizeof(struct conntrack_timer_queue));
				bzero(tmp, sizeof(struct conntrack_timer_queue));

				tmp->prev = tq->prev;
				tmp->next = tq;
				tq->prev = tmp;

				if (tmp->prev)
					tmp->prev->next = tmp;
				else
					timer_queues = tmp;


				tq = tmp;
				tq->expiry = expiry;

				break;
			
			} else if (!tq->next) { // Looks like we are at the end of our list

				struct conntrack_timer_queue *tmp;
				tmp = malloc(sizeof(struct conntrack_timer_queue));
				bzero(tmp, sizeof(struct conntrack_timer_queue));

				tmp->prev = tq;
				
				tq->next = tmp;

				tq = tmp;

				tq->expiry = expiry;
				
				break;
			}

			tq = tq->next;
		}

	}

	// Now we can queue the timer
	
	if (tq->head == NULL) {
		tq->head = t;
		tq->tail = t;
	} else {
		t->prev = tq->tail;
		tq->tail->next = t;
		tq->tail = t;
	}

	// Update the expiry time

	struct timeval tv;
	gettimeofday(&tv, NULL);
	t->expires = tv.tv_sec + expiry;

	return 1;
}


int conntrack_timer_dequeue(struct conntrack_timer *t) {

	
	// First let's check if it's the one at the begining of the queue

	if (t->prev) {
		t->prev->next = t->next;
	} else {
		struct conntrack_timer_queue *tq;
		tq = timer_queues;
		while (tq) {
			//dprint("tq->head = 0x%x, t = 0x%x\n", (unsigned) tq->head, (unsigned) t);
			if (tq->head == t) {
				tq->head = t->next;

				// Let's see if the queue is empty
			
				/* WE SHOULD NOT TRY TO REMOVE QUEUES FROM THE QUEUE LIST
				if (!tq->head) { // If it is, remove that queue from the queue list
					dprint("Removing queue 0x%x from the queue list\n", (unsigned) tq);
					if (tq->prev)
						tq->prev->next = tq->next;
					else
						timer_queues = tq->next;

					if (tq->next)
						tq->next->prev = tq->prev;


					free (tq);
					return 1;
				}*/
				break;
			}
			tq = tq->next;
		}
#ifdef DEBUG
		if (!tq)
			dprint("Warning, timer 0x%x not found in conntrack queues heads\n", (unsigned) t);
#endif
	}

	if (!timer_queues) {
		dprint("WTF\n");
		return 1;
	}

	if (t->next) {
		t->next->prev = t->prev;
	} else {
		struct conntrack_timer_queue *tq;
		tq = timer_queues;
		while (tq) {
			if (tq->tail == t) {
				tq->tail = t->prev;
				break;
			}
			tq = tq->next;
		}
#ifdef DEBUG
		if (!tq) {
			dprint("Warning, timer 0x%x not found in conntrack queues tails\n", (unsigned) t);
		}
#endif
	}


	// Make sure this timer will not reference anything

	t->prev = NULL;
	t->next = NULL;




	return 1;
}
