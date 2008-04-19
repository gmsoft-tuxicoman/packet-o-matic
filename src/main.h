/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __MAIN_H__
#define __MAIN_H__

#include "conf.h"
#include "input.h"

#include <pthread.h>

struct conf *main_config;

struct core_param *core_params;

enum ringbuffer_state {
	rb_state_closed,
	rb_state_open,
	rb_state_opening,
	rb_state_closing,
	rb_state_stopping,

};

struct ringbuffer {

	pthread_mutex_t mutex; ///< Mutex of the circle buffer
	pthread_cond_t underrun_cond; ///< Condition wait of the circle buffer when it's empty
	pthread_cond_t overflow_cond; ///< Condition wait of the circle buffer when it's full and we don't have to drop packets
	unsigned long dropped_packets; ///< Count the dropped packets
	unsigned long total_packets; ///< Count the total number of packet that went trough the buffer


	struct frame** buffer;
	unsigned int read_pos; ///< Where the process thread WILL read the packets
	unsigned int write_pos; ///< Where the input thread is CURRENTLY writing
	unsigned int usage; ///< Number of packet in the buffer waiting to be processed
	struct ptype *size; ///< Number of packets to allocate

	enum ringbuffer_state state; ///< State of the ringbuffer

	struct input *i; ///< Input associated with this ringbuffer
	struct input_caps ic; ///< Capabilities of the input
};

struct core_param {

	char *name; ///< Name of the parameter
	char *defval; ///< Default value
	char *descr; ///< Description
	struct ptype *value; ///< User modifiable value
	int (*can_change) (struct ptype *value, char *msg, size_t size); ///< Function that checks if parameter can be changed
	struct core_param *next;
};

struct ringbuffer *rbuf; ///< The ring buffer

int ringbuffer_init(struct ringbuffer *r);
int ringbuffer_deinit(struct ringbuffer *r);
int ringbuffer_alloc(struct ringbuffer *r, struct input *i);
int ringbuffer_cleanup(struct ringbuffer *r);
int ringbuffer_can_change_size(struct ptype *value, char *msg, size_t size);

int start_input(struct ringbuffer *r);
int stop_input(struct ringbuffer *r);

int get_current_input_time(struct timeval *cur_time);

int reader_process_lock();
int reader_process_unlock();

void *input_thread_func(void *params);

int halt();

int core_register_param(char *name, char *defval, struct ptype *value, char *descr, int (*param_can_change) (struct ptype *value, char *msg, size_t size));
struct ptype* core_get_param_value(char *param);
int core_set_param_value(char *param, char *value, char *msg, size_t size);
int core_param_unregister_all();

#endif
