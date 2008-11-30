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
#include "core_param.h"

#include <pthread.h>

extern struct conf *main_config;

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
	int fd; ///< File descriptor of the input
};

extern struct ringbuffer *rbuf; ///< The ring buffer

int ringbuffer_init(struct ringbuffer *r);
int ringbuffer_deinit(struct ringbuffer *r);
int ringbuffer_alloc(struct ringbuffer *r, struct input *i);
int ringbuffer_cleanup(struct ringbuffer *r);
int ringbuffer_core_param_callback(char *new_value, char *msg, size_t size);

int start_input(struct ringbuffer *r);
int stop_input(struct ringbuffer *r);

int get_current_input_time(struct timeval *cur_time);

int reader_process_lock();
int reader_process_unlock();

void *input_thread_func(void *params);

int halt();

int main_config_rules_lock(int write);
int main_config_rules_unlock();
int main_config_datastores_lock(int write);
int main_config_datastores_unlock();

#endif
