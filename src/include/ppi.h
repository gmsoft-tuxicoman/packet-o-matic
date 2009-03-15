/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
 *  Copyright (C) 2009 Mike Kershaw <dragorn@kismetwireless.net>
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

#ifndef __PPI_H__
#define __PPI_H__

/* CACE PPI headers */
typedef struct {
	uint8_t pph_version;
	uint8_t pph_flags;
	uint16_t pph_len;
	uint32_t pph_dlt;
} __attribute__((__packed__)) ppi_packet_header;

#define PPI_PH_FLAG_ALIGNED		2

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
} __attribute__((__packed__)) ppi_field_header;

#define PPI_FIELD_11COMMON		2
#define PPI_FIELD_11NMAC		3
#define PPI_FIELD_11NMACPHY		4
#define PPI_FIELD_SPECMAP		5
#define PPI_FIELD_PROCINFO		6
#define PPI_FIELD_CAPINFO		7

#endif
