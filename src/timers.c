/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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

#include "timers.h"
#include "input.h"


struct timer_queue *timer_queues;
struct timeval next_run;


int timers_process(struct input *i) {

	struct timeval tv;
	input_gettimeof(i, &tv);

	ndprint("Looking at timers ...\n");

	struct timer_queue *tq;
	tq = timer_queues;

	while (tq) {
		while (tq->head && timercmp(&tq->head->expires, &tv, <)) {
				ndprint("Timer 0x%lx reached. Starting handler ...\n", (unsigned long) tq->head);
				(*tq->head->handler) (tq->head->priv);
		}
		tq = tq->next;

	}

	return 1;
}


int timers_cleanup() {


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
	memcpy(&t->expires, &tv, sizeof(struct timeval));
	t->expires.tv_sec += expiry;

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
			if (tq->head == t) {
				tq->head = t->next;

				// Let's see if the queue is empty
			
				/* WE SHOULD NOT TRY TO REMOVE QUEUES FROM THE QUEUE LIST
				if (!tq->head) { // If it is, remove that queue from the queue list
					dprint("Removing queue 0x%lx from the queue list\n", (unsigned long) tq);
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
#if 0
		if (!tq)
			dprint("Warning, timer 0x%lx not found in timers queues heads\n", (unsigned long) t);
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
#if 0
		if (!tq) {
			dprint("Warning, timer 0x%lx not found in timers queues tails\n", (unsigned long) t);
		}
#endif
	}


	// Make sure this timer will not reference anything

	t->prev = NULL;
	t->next = NULL;




	return 1;
}
