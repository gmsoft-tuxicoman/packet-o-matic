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


#ifndef __TIMERS_H__
#define __TIMERS_H__

#include "common.h"
#include "input.h"

#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif


struct timer {

	struct timeval expires;
	void *priv;
	int (*handler) (void *);
	struct input *input;
	struct timer *next;
	struct timer *prev;

};

struct timer_queue {

	unsigned int expiry;
	struct timer_queue *next;
	struct timer_queue *prev;
	struct timer *head;
	struct timer *tail;

};



int timers_process(struct input *i);
int timers_cleanup();
struct timer *timer_alloc();
int timer_cleanup(struct timer *t);
int timer_queue(struct timer *t, unsigned int expiry);
int timer_dequeue(struct timer *t);


#endif
