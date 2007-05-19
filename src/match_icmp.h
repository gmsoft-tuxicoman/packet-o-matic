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


#ifndef __MATCH_ICMP_H__
#define __MATCH_ICMP_H__


#include "modules_common.h"
#include "match.h"


int match_register_icmp(struct match_reg *r, struct match_functions *m_funcs);
int match_identify_icmp(struct layer* l, void* frame, unsigned int start, unsigned int len);
int match_layer_info_snprintf_icmp(char *buff, unsigned int len, struct layer_info *inf);


#endif