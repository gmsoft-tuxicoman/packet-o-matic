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

#include "timers.h"
/*
void check_list (struct timer_queue *tq) {


	struct timer *t;

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

void check_queues (struct timer_queue *tq) {


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
struct timer_queue *timer_queues;
struct itimerval itimer;

void timers_handler(int signal) {

	ndprint("Looking at timers ...\n");


	struct timer_queue *tq;
	tq = timer_queues;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	while (tq) {
		while (tq->head && tq->head->expires <= tv.tv_sec) {
				ndprint("Timer 0x%x reached. Starting handler ...\n", (unsigned) tq->head);
				(*tq->head->handler) (tq->head->priv);
		}
		tq = tq->next;

	}
}

int timers_init() {

	// Setup signal handler for the timer

	signal(SIGALRM, timers_handler);

	// Setup the timer
	
	bzero(&itimer, sizeof(struct itimerval));
	itimer.it_interval.tv_sec = 1;
	itimer.it_value.tv_usec = 500000;

	if (setitimer(ITIMER_REAL, &itimer, NULL) != 0) {
		dprint("Error while setting up the timer\n");
		return 0;
	}

	timer_queues = NULL;

	dprint("Timers initialized\n");
	
	return 1;

}


int timers_cleanup() {


	// Stop the timers
	
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = 0;

	
	// Free the timers

	while (timer_queues) {
		struct timer_queue *tmpq;
		tmpq = timer_queues;

		while (tmpq->head) {
			
			struct timer *tmp;
			tmp = tmpq->head;

			tmpq->head = tmpq->head->next;

			free(tmp);

		}
		timer_queues = timer_queues->next;

		free(tmpq);
	}

	return 1;

}


struct timer *timer_alloc(void* priv, int (*handler) (void*)) {

	struct timer *t;
	t = malloc(sizeof(struct timer));
	bzero(t, sizeof(struct timer));

	t->priv = priv;
	t->handler = handler;


	return t;
}

int timer_cleanup(struct timer *t) {

	if (t->next || t->prev) {
		dprint("Error timer not dequeued before cleanup\n");
		return 0;
	}

	free(t);
	
	return 1;
}

int timer_queue(struct timer *t, unsigned int expiry) {

	struct timer_queue *tq;
	tq = timer_queues;

	if (t->prev || t->next) {
		dprint("Error, timer not dequeued correctly\n");
		return -1;
	}

	// First find the right queue or create it
	
	if (!tq) {

		// There is no queue yet
		tq = malloc(sizeof(struct timer_queue));
		bzero(tq, sizeof(struct timer_queue));
		timer_queues = tq;

		tq->expiry = expiry;

	} else {

		while (tq) {
			
			if (tq->expiry == expiry) { // The right queue already exists
				
				break;

			} else if (tq->expiry > expiry) { // The right queue doesn't exists and we are too far in the list

				struct timer_queue *tmp;
				tmp = malloc(sizeof(struct timer_queue));
				bzero(tmp, sizeof(struct timer_queue));

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

				struct timer_queue *tmp;
				tmp = malloc(sizeof(struct timer_queue));
				bzero(tmp, sizeof(struct timer_queue));

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


int timer_dequeue(struct timer *t) {

	
	// First let's check if it's the one at the begining of the queue

	if (t->prev) {
		t->prev->next = t->next;
	} else {
		struct timer_queue *tq;
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
			dprint("Warning, timer 0x%x not found in timers queues heads\n", (unsigned) t);
#endif
	}

	if (!timer_queues) {
		dprint("WTF\n");
		return 1;
	}

	if (t->next) {
		t->next->prev = t->prev;
	} else {
		struct timer_queue *tq;
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
			dprint("Warning, timer 0x%x not found in timers queues tails\n", (unsigned) t);
		}
#endif
	}


	// Make sure this timer will not reference anything

	t->prev = NULL;
	t->next = NULL;




	return 1;
}