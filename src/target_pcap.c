/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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

#include "target_pcap.h"
#include "ptype_string.h"
#include "ptype_uint16.h"
#include "ptype_uint64.h"
#include "ptype_bool.h"
#include "ptype_interval.h"

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

static struct target_mode *mode_default, *mode_split, *mode_connection;

int target_register_pcap(struct target_reg *r) {

	r->init = target_init_pcap;
	r->open = target_open_pcap;
	r->process = target_process_pcap;
	r->close = target_close_pcap;
	r->cleanup = target_cleanup_pcap;

	mode_default = target_register_mode(r->type, "default", "Dump all the packets into a PCAP file");
	mode_split = target_register_mode(r->type, "split", "Dump all packets into multiple PCAP files");
	mode_connection = target_register_mode(r->type, "connection", "Dump connections in separate PCAP files");

	if (!mode_default || !mode_split || !mode_connection)
		return POM_ERR;

	target_register_param(mode_default, "filename", "dump.cap", "Filename to save packets to");
	target_register_param(mode_default, "snaplen", "1522", "Maximum size of saved packets");
	target_register_param(mode_default, "layer", "ethernet", "Type of layer to capture. Either ethernet, linux_cooked, docsis, 80211 or ipv4");
	target_register_param(mode_default, "unbuffered", "no", "Write each packet to the output file directly without using a buffer");

	target_register_param(mode_split, "prefix", "dump", "Prefix of output files to save packets to");
	target_register_param(mode_split, "overwrite", "no", "Overwrite existing file in the directory");
	target_register_param(mode_split, "snaplen", "1522", "Maximum size of saved packets");
	target_register_param(mode_split, "layer", "ethernet", "Type of layer to capture. Either ethernet, linux_cooked, docsis, 80211 or ipv4");
	target_register_param(mode_split, "split_size", "0", "Split when reaching this size");
	target_register_param(mode_split, "split_packets", "0", "Split when reaching this number of packets");
	target_register_param(mode_split, "split_interval", "0", "Split when reaching this number of seconds");
	target_register_param(mode_split, "unbuffered", "no", "Write each packet to the output file directly without using a buffer");

	target_register_param(mode_connection, "prefix", "dump", "Prefix of output files to save packets to");
	target_register_param(mode_connection, "snaplen", "1522", "Maximum size of saved packets");
	target_register_param(mode_connection, "layer", "ethernet", "Type of layer to capture. Either ethernet, linux_cooked, docsis, 80211 or ipv4");
	target_register_param(mode_connection, "unbuffered", "no", "Write each packet to the output file directly without using a buffer");


	return POM_OK;

}

static int target_init_pcap(struct target *t) {

	struct target_priv_pcap *priv = malloc(sizeof(struct target_priv_pcap));
	memset(priv, 0, sizeof(struct target_priv_pcap));
	t->target_priv = priv;

	priv->filename = ptype_alloc("string", NULL);
	priv->snaplen = ptype_alloc("uint16", "bytes");
	priv->layer = ptype_alloc("string", NULL);
	priv->unbuffered = ptype_alloc("bool", NULL);

	priv->prefix = ptype_alloc("string", NULL);
	priv->split_overwrite = ptype_alloc("bool", NULL);
	priv->split_size = ptype_alloc("uint64", "bytes");
	priv->split_size->print_mode = PTYPE_UINT64_PRINT_HUMAN_1024;
	priv->split_packets = ptype_alloc("uint64", "packets");
	priv->split_packets->print_mode = PTYPE_UINT64_PRINT_HUMAN;
	priv->split_interval = ptype_alloc("interval", NULL);

	if (!priv->filename ||
		!priv->snaplen ||
		!priv->layer ||
		!priv->unbuffered ||
		!priv->prefix ||
		!priv->split_overwrite ||
		!priv->split_size ||
		!priv->split_packets ||
		!priv->split_interval) {
		target_cleanup_pcap(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "filename", priv->filename);
	target_register_param_value(t, mode_default, "snaplen", priv->snaplen);
	target_register_param_value(t, mode_default, "layer", priv->layer);
	target_register_param_value(t, mode_default, "unbuffered", priv->unbuffered);
	
	target_register_param_value(t, mode_split, "prefix", priv->prefix);
	target_register_param_value(t, mode_split, "overwrite", priv->split_overwrite);
	target_register_param_value(t, mode_split, "snaplen", priv->snaplen);
	target_register_param_value(t, mode_split, "layer", priv->layer);
	target_register_param_value(t, mode_split, "unbuffered", priv->unbuffered);
	target_register_param_value(t, mode_split, "split_size", priv->split_size);
	target_register_param_value(t, mode_split, "split_packets", priv->split_packets);
	target_register_param_value(t, mode_split, "split_interval", priv->split_interval);

	target_register_param_value(t, mode_connection, "prefix", priv->prefix);
	target_register_param_value(t, mode_connection, "snaplen", priv->snaplen);
	target_register_param_value(t, mode_connection, "layer", priv->layer);
	target_register_param_value(t, mode_connection, "unbuffered", priv->unbuffered);
	
	return POM_OK;
}

static int target_cleanup_pcap(struct target *t) {

	struct target_priv_pcap *priv = t->target_priv;

	if (priv) {
		ptype_cleanup(priv->filename);
		ptype_cleanup(priv->snaplen);
		ptype_cleanup(priv->layer);
		ptype_cleanup(priv->unbuffered);

		ptype_cleanup(priv->prefix);
		ptype_cleanup(priv->split_overwrite);
		ptype_cleanup(priv->split_size);
		ptype_cleanup(priv->split_packets);
		ptype_cleanup(priv->split_interval);

		free(priv);
	}

	return POM_OK;
}


static int target_open_pcap(struct target *t) {

	struct target_priv_pcap *priv = t->target_priv;

	priv->last_layer_type = -1;
	int snaplen = PTYPE_UINT16_GETVAL(priv->snaplen);

	if (!strcasecmp("ethernet", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_EN10MB, snaplen);
		priv->last_layer_type = match_register("ethernet");
	} else if (!strcasecmp("linux_cooked", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_LINUX_SLL, snaplen);
		priv->last_layer_type = match_register("linux_cooked");
	} else if (!strcasecmp("ipv4", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_RAW, snaplen);
		priv->last_layer_type = match_register("ipv4");
#ifdef DLT_DOCSIS
	} else if (!strcasecmp("docsis", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_DOCSIS, snaplen);
		priv->last_layer_type = match_register("docsis");
#endif
	} else if (!strcasecmp("80211", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_IEEE802_11, snaplen);
		priv->last_layer_type = match_register("80211");
	} else {
		pom_log(POM_LOG_ERR "Pcap : error: no supported header found.");
		return POM_ERR;
	}

	if (!priv->p) {
		pom_log(POM_LOG_ERR "Unable to open pcap !");
		return POM_ERR;
	}

	char *filename = NULL;

	if (t->mode == mode_split) {
		char my_name[NAME_MAX];
		if (!PTYPE_BOOL_GETVAL(priv->split_overwrite)) {
			do {
				struct stat tmp;
				snprintf(my_name, NAME_MAX - 1, "%s_%05lu.cap", PTYPE_STRING_GETVAL(priv->prefix), priv->split_index);
				if (stat(my_name, &tmp) != 0) {
					break;
				}
				priv->split_index++;
			} while(1);
			
		} else {
			snprintf(my_name, NAME_MAX - 1, "%s_%05lu.cap", PTYPE_STRING_GETVAL(priv->prefix), priv->split_index);
		}
		filename = my_name;
		pom_log("Writing output to file %s", my_name);

		if (PTYPE_INTERVAL_GETVAL(priv->split_interval) > 0)
			priv->split_time = time(NULL) + PTYPE_INTERVAL_GETVAL(priv->split_interval);

	} else if (t->mode == mode_default) {
		filename = PTYPE_STRING_GETVAL(priv->filename);
	}


	if (filename) { // Only not NULL when mode is split or default

		priv->pdump = pcap_dump_open(priv->p, filename);
		if (!priv->pdump) {
			pom_log(POM_LOG_ERR "Unable to open pcap file %s for writing !", filename);
			pcap_close(priv->p);
			return POM_ERR;
		}

	}

	return POM_OK;

	
}


static int target_process_pcap(struct target *t, struct frame *f) {

	struct target_priv_pcap *priv = t->target_priv;
	
	int start = layer_find_start(f->l, priv->last_layer_type);

	if (start == POM_ERR) {

		if (!priv->issued_warning) {
			pom_log(POM_LOG_WARN "Unable to find the start of the packet. You probably need to set the parameter \"layer\" to \"%s\"", match_get_name(f->l->type));
			priv->issued_warning = 1;
		}
		return POM_OK;

	}
	
	struct pcap_pkthdr phdr;
	
	memcpy(&phdr.ts, &f->tv, sizeof(struct timeval));
	
	unsigned int len = f->len - start;
	phdr.len = len;
	
	if (PTYPE_UINT16_GETVAL(priv->snaplen) > len)
		phdr.caplen = len;
	else
		phdr.caplen = PTYPE_UINT16_GETVAL(priv->snaplen);

	pcap_dumper_t *pdump = NULL;


	if (t->mode == mode_default) {
		pdump = priv->pdump;

	} else if (t->mode == mode_split) {
		// Let's see if we have to open the next file

		int next = 0;
		time_t now;
		time(&now);
		if (PTYPE_UINT64_GETVAL(priv->split_size) > 0 && priv->cur_size + sizeof(struct pcap_pkthdr) + phdr.caplen > PTYPE_UINT64_GETVAL(priv->split_size)) {
			next = 1;
		} else if (PTYPE_UINT64_GETVAL(priv->split_packets) > 0 && priv->cur_packets_num >= PTYPE_UINT64_GETVAL(priv->split_packets)) {
			next = 2;
		} else if (PTYPE_INTERVAL_GETVAL(priv->split_interval) > 0 && priv->split_time < now) {
			next = 3;
		}


		if (next) {
			char filename[NAME_MAX];

			pcap_dump_close(priv->pdump);
			priv->split_files_num++;
			priv->split_index++;

			if (!PTYPE_BOOL_GETVAL(priv->split_overwrite)) {
				do {
					struct stat tmp;
					snprintf(filename, NAME_MAX - 1, "%s_%05lu.cap", PTYPE_STRING_GETVAL(priv->prefix), priv->split_index);
					if (stat(filename, &tmp) != 0) {
						break;
					}
					priv->split_index++;
				} while(1);
				
			} else {
				snprintf(filename, NAME_MAX - 1, "%s_%05lu.cap", PTYPE_STRING_GETVAL(priv->prefix), priv->split_index);
			}
			priv->pdump = pcap_dump_open(priv->p, filename);
			if (!priv->pdump) {
				pom_log(POM_LOG_ERR "Unable to open pcap file %s for writing !", filename);
				pcap_close(priv->p);
				priv->p = NULL;
				return POM_ERR;
			}

			priv->split_time = now + PTYPE_INTERVAL_GETVAL(priv->split_interval);
			priv->tot_size += priv->cur_size;
			priv->cur_size = 0;
			priv->tot_packets_num += priv->cur_packets_num;
			priv->cur_packets_num = 0;

			switch (next) {
				case 1:
					pom_log("Size limit reached, continuing with file %s", filename);
					break;
				case 2:
					pom_log("Packet number limit reached, continuing with file %s", filename);
					break;
				case 3:
					pom_log("Elapsed time limit reached, continuing with file %s", filename);
					break;
			}

		}
	
		pdump = priv->pdump;

	} else if (t->mode == mode_connection) {
		// Let's see if this connection already has a file open
		
		if (!f->ce)
			if (conntrack_create_entry(f) == POM_ERR)
				return POM_OK; // This packet can't be tracked

		struct target_conntrack_priv_pcap *cp;
		cp = conntrack_get_target_priv(t, f->ce);

		if (!cp) {
			cp = malloc(sizeof(struct target_conntrack_priv_pcap));
			memset(cp, 0, sizeof(struct target_conntrack_priv_pcap));
		

			char filename[NAME_MAX];
			memset(filename, 0, NAME_MAX);
			char outstr[20];
			memset(outstr, 0, sizeof(outstr));
			// YYYYMMDD-HHMMSS-UUUUUU
			char *format = "%Y%m%d-%H%M%S-";
			struct tm tmp;
			localtime_r((time_t*)&f->tv.tv_sec, &tmp);
		
			strftime(outstr, sizeof(outstr), format, &tmp);
		
			snprintf(filename, NAME_MAX - 1, "%s%s%u.cap", PTYPE_STRING_GETVAL(priv->prefix), outstr, (unsigned int)f->tv.tv_usec);

			char filename_final[NAME_MAX];
			memset(filename_final, 0, NAME_MAX);
			layer_field_parse(f->l, &f->tv, filename, filename_final, NAME_MAX);

			// Since we are not calling target_file_open(), we need to create the missing directories ourselves

			char *slash = filename_final;
			if (*slash == '/') // we assume that the root directory exists :)
				slash++;

			slash = strchr(slash, '/');
			while (slash) {
				*slash = 0;
				struct stat stats;
				if (stat(filename_final, &stats)) {
					switch (errno) {
						case ENOENT:
							mkdir(filename_final, 00777);
							break;
						default:
							pom_log(POM_LOG_ERR "Unable to create directory %s !", filename_final);
							return POM_ERR;
					}
				}
				*slash = '/';
				slash = strchr(slash + 1, '/');
			}

			cp->pdump = pcap_dump_open(priv->p, filename_final);

			if (!cp->pdump) {
				pom_log(POM_LOG_ERR "Unable to open pcap file %s for writing !", filename_final);
				return POM_ERR;
			}

			conntrack_add_target_priv(cp, t, f->ce, target_close_connection_pcap);
			cp->ce = f->ce;
			cp->next = priv->ct_privs;
			if (priv->ct_privs)
				priv->ct_privs->prev = cp;
			priv->ct_privs = cp;
		}

		pdump = cp->pdump;

	}

	if (!pdump) {
		pom_log(POM_LOG_ERR "Error : pdump pointer NULL !");
		return POM_ERR;
	}

	pcap_dump((u_char*)pdump, &phdr, f->buff + start);

	if (PTYPE_BOOL_GETVAL(priv->unbuffered)) 
		pcap_dump_flush(pdump);

	priv->cur_size = pcap_dump_ftell(pdump);
	priv->cur_packets_num++;

	pom_log(POM_LOG_TSHOOT "Packet saved (%lu bytes)!", len);

	return POM_OK;
}

int target_close_connection_pcap(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_pcap *cp;
	cp = conntrack_priv;

	pcap_dump_close(cp->pdump);

	struct target_priv_pcap *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;
	
	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	return POM_OK;

}
static int target_close_pcap(struct target *t) {
	
	struct target_priv_pcap *priv = t->target_priv;

	if (!t->target_priv)
		return POM_ERR;

	priv->tot_packets_num += priv->cur_packets_num;
	priv->cur_packets_num = 0;
	priv->tot_size += priv->cur_size;
	priv->cur_size = 0;
	priv->split_files_num++;
	priv->split_index++;

	if (t->mode == mode_split)
		pom_log("Saved %lu packets and %lu bytes in %lu files", priv->tot_packets_num, priv->tot_size, priv->split_files_num);
	else
		pom_log("Saved %lu packets and %lu bytes", priv->tot_packets_num, priv->tot_size);

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_pcap(t, priv->ct_privs->ce, priv->ct_privs);
	}

	if (priv->pdump) {
		pcap_dump_close(priv->pdump);
		priv->pdump = NULL;
	}

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}

	priv->split_files_num = 0;

	return POM_OK;
}


