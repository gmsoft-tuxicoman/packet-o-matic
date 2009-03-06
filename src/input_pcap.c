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


#include "input_pcap.h"
#include "ptype_string.h"
#include "ptype_bool.h"
#include "ptype_uint16.h"

#include <dirent.h>
#include <errno.h>
#include <stddef.h>

static struct input_mode *mode_interface, *mode_file, *mode_directory;
static struct ptype *p_filename, *p_interface, *p_snaplen, *p_promisc, *p_filter, *p_directory, *p_dir_file_ext;

int input_register_pcap(struct input_reg *r) {

	r->init = input_init_pcap;
	r->open = input_open_pcap;
	r->read = input_read_pcap;
	r->close = input_close_pcap;
	r->cleanup = input_cleanup_pcap;
	r->getcaps = input_getcaps_pcap;
	r->unregister = input_unregister_pcap;
	r->interrupt = input_interrupt_pcap;

	mode_interface = input_register_mode(r->type, "interface", "Read packets from an interface");
	mode_file = input_register_mode(r->type, "file", "Read packets from a pcap file");
	mode_directory = input_register_mode(r->type, "directory", "Read packets from multiple files in a directory");

	if (!mode_interface || !mode_file || !mode_directory)
		return POM_ERR;
	
	p_filename = ptype_alloc("string", NULL);
	p_interface = ptype_alloc("string", NULL);
	p_snaplen = ptype_alloc("uint16", "bytes");
	p_promisc = ptype_alloc("bool", NULL);
	p_filter = ptype_alloc("string", NULL);
	p_directory = ptype_alloc("string", NULL);
	p_dir_file_ext = ptype_alloc("string", NULL);

	if (!p_filename || !p_interface || !p_snaplen || !p_promisc || !p_filter || !p_directory || !p_dir_file_ext) {
		input_unregister_pcap(r);
		return POM_ERR;
	}

	char err[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(err);
	if (!dev)
		dev = "none";

	input_register_param(mode_interface, "interface", dev, p_interface, "Interface to listen from");
	input_register_param(mode_interface, "snaplen", "1522", p_snaplen, "Snaplen");
	input_register_param(mode_interface, "promisc", "no", p_promisc, "Promiscuous");
	input_register_param(mode_interface, "filter", "", p_filter, "BFP filter");

	input_register_param(mode_file, "file", "dump.cap", p_filename, "PCAP file");
	input_register_param(mode_file, "filter", "", p_filter, "BFP filter");

	input_register_param(mode_directory, "path", "/tmp", p_directory, "Directory to read files from");
	input_register_param(mode_directory, "file_extension", ".cap", p_dir_file_ext, "File extension to process");
	input_register_param(mode_directory, "filter", "", p_filter, "BFP filter");

	return POM_OK;
}


static int input_init_pcap(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_pcap));
	memset(i->input_priv, 0, sizeof(struct input_priv_pcap));

	return POM_OK;

}

static int input_cleanup_pcap(struct input *i) {

	if (i->input_priv)
		free(i->input_priv);

	return POM_OK;

}

static int input_unregister_pcap(struct input_reg *r) {

	ptype_cleanup(p_interface);
	ptype_cleanup(p_snaplen);
	ptype_cleanup(p_promisc);
	ptype_cleanup(p_filename);
	ptype_cleanup(p_filter);
	ptype_cleanup(p_directory);
	ptype_cleanup(p_dir_file_ext);
	return POM_OK;
}

static int input_open_pcap(struct input *i) {


	struct input_priv_pcap *p = i->input_priv;
	
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	errbuf[0] = 0;

	if (i->mode == mode_file) {
		char *filename = PTYPE_STRING_GETVAL(p_filename);
		p->p = pcap_open_offline(filename, errbuf);
		if (!p->p) {
			pom_log(POM_LOG_ERR "Error opening file %s for reading", filename);
			return POM_ERR;
		}
		pom_log("Opened file %s", filename);
	} else if (i->mode == mode_interface) {
		char *interface = PTYPE_STRING_GETVAL(p_interface);
		int snaplen = PTYPE_UINT16_GETVAL(p_snaplen);
		int promisc = PTYPE_BOOL_GETVAL(p_promisc);
		if (snaplen < 64)
			snaplen = 64;
		p->p = pcap_open_live(interface, snaplen, promisc, 0, errbuf);
		if (!p->p) {
			pom_log(POM_LOG_ERR "Error when opening interface %s : %s", interface, errbuf);
			return POM_ERR;
		}
		pom_log("Reading from Interface %s with a snaplen of %u", interface, snaplen);
	} else if (i->mode == mode_directory) {
	
		if (input_browse_dir_pcap(p) == POM_ERR)
			return POM_ERR;
		p->dir_cur_file = p->dir_files;

		// Skip files which could not be read
		while (p->dir_cur_file && !p->dir_cur_file->first_pkt.tv_sec)
			p->dir_cur_file = p->dir_cur_file->next;

		if (!p->dir_cur_file) { // No file found
			pom_log(POM_LOG_WARN "No useable file could be found");
			input_close(i);
			return POM_OK;
		}

		char *dir = PTYPE_STRING_GETVAL(p_directory);

		char *filename = malloc(strlen(dir) + strlen(p->dir_cur_file->filename) + 2);
		strcpy(filename, dir);
		if (*filename && filename[strlen(filename) - 1] != '/')
			strcat(filename, "/");
		strcat(filename, p->dir_cur_file->filename);

		p->p = pcap_open_offline(filename, errbuf);
		if (!p->p) {
			pom_log(POM_LOG_ERR "Error opening file %s for reading", filename);
			return POM_ERR;
		}

		pom_log("Processing file %s", filename);
		free(filename);

	} else {
		pom_log(POM_LOG_ERR "Invalid input mode");
		return POM_ERR;
	}

	p->datalink = pcap_datalink(p->p);

	switch (p->datalink) {
		case DLT_EN10MB:
			pom_log("PCAP output type is ethernet");
			p->output_layer = match_register("ethernet");
			p->align_offset = 2;
			break;
#ifdef DLT_DOCSIS // this doesn't exits in all libpcap version
		case DLT_DOCSIS:
			pom_log("PCAP output type is docsis");
			p->output_layer = match_register("docsis");
			break;
#endif
		case DLT_LINUX_SLL:
			pom_log("PCAP output type is linux_cooked");
			p->output_layer = match_register("linux_cooked");
			break;

		case DLT_RAW:
			pom_log("PCAP output type is ipv4");
			p->output_layer = match_register("ipv4");
			break;

		case DLT_IEEE802_11:
			pom_log("PCAP output type ie ieee80211");
			p->output_layer = match_register("80211");
			break;

		default:
			pom_log("PCAP output type is undefined");
			p->output_layer = match_register("undefined");

	}

	if (strlen(errbuf) > 0)
		pom_log(POM_LOG_WARN "PCAP warning : %s", errbuf);
	


	if (strlen(PTYPE_STRING_GETVAL(p_filter)) > 0) {
	
		if (pcap_compile(p->p, &p->fp, PTYPE_STRING_GETVAL(p_filter), 1, 0) == -1) {

			pom_log(POM_LOG_ERR "Unable to compile BFP filter \"%s\"", PTYPE_STRING_GETVAL(p_filter));
			pcap_close(p->p);
			p->p = NULL;
			return POM_ERR;
		
		}

		if (pcap_setfilter(p->p, &p->fp) == -1) {
			pom_log(POM_LOG_ERR "Unable to set the BFP filter \"%s\"", PTYPE_STRING_GETVAL(p_filter));
			pcap_freecode(&p->fp);
			pcap_close(p->p);
			p->p = NULL;
			return POM_ERR;
		}

	}

	p->packets_read = 0;

	return POM_OK;
}

static int input_read_pcap(struct input *i, struct frame *f) {

	struct input_priv_pcap *p = i->input_priv;
	const u_char *next_pkt;

	struct pcap_pkthdr *phdr;

	int result;
	result = pcap_next_ex(p->p, &phdr, &next_pkt);

	if (result == -2) { // End of file

		if (i->mode == mode_directory) {
			pcap_close(p->p);
			p->p = NULL;

			// Rescan the directory for possible new files
			if (input_browse_dir_pcap(p) == POM_ERR)
				return POM_ERR;

			if (input_open_next_file_pcap(p) == POM_ERR)
				return POM_ERR;

			if (!p->dir_cur_file) { // No more file
				input_close(i);
				return POM_OK;
			}

			// Read the first packet
			result = pcap_next_ex(p->p, &phdr, &next_pkt);

		} else {
			input_close(i);
			return POM_OK;
		}
	}

	if (result < 0) { // Error
		pom_log(POM_LOG_ERR "Error while reading packet.");
		return POM_ERR;
	}

	if (result == 0) { // Timeout
		f->len = 0;
		return POM_OK;
	}

	if (f->bufflen < phdr->caplen) {
		pom_log(POM_LOG_WARN "Please increase your read buffer. Provided %u, needed %u", f->bufflen, phdr->caplen);
		phdr->caplen = f->bufflen;
		
	}
	memcpy(f->buff, next_pkt, phdr->caplen);
	memcpy(&f->tv, &phdr->ts, sizeof(struct timeval));

	f->len = phdr->caplen;
	f->first_layer = p->output_layer;
	f->align_offset = 2;

	p->packets_read++;

	return POM_OK;
}

static int input_close_pcap(struct input *i) {

	struct input_priv_pcap *p = i->input_priv;
	if (!p)
		return POM_ERR;


	struct pcap_stat ps;
	if (i->mode != mode_directory && !pcap_stats(p->p, &ps)) 
		pom_log("Total packet read %u, dropped %u (%.1f%%)", ps.ps_recv, ps.ps_drop, 100.0 / (ps.ps_recv + ps.ps_drop)  * (float)ps.ps_drop);
	else
		pom_log("Total packet read %lu", p->packets_read);

	if (strlen(PTYPE_STRING_GETVAL(p_filter)) > 0)
		pcap_freecode(&p->fp);

	if (p->p) {
		pcap_close(p->p);
		p->p = NULL;
	}

	while (p->dir_files) {
		struct input_priv_file_pcap *tmp = p->dir_files;
		p->dir_files = tmp->next;
		free(tmp->filename);
		free(tmp);
	}

	return POM_OK;

}

static int input_getcaps_pcap(struct input *i, struct input_caps *ic) {

	struct input_priv_pcap *p = i->input_priv;

	if (!p->p)
		return POM_ERR;

	ic->snaplen = pcap_snapshot(p->p);
	if (i->mode == mode_interface) 
		ic->is_live = 1;
	else
		ic->is_live = 0;

	switch (pcap_datalink(p->p)) {
		case DLT_EN10MB: // ethernet is 14 bytes long
			ic->buff_align_offset = 2;
			break;
		default: 
			ic->buff_align_offset = 0;
	}

	return POM_OK;

}

static int input_interrupt_pcap(struct input *i) {

	struct input_priv_pcap *p = i->input_priv;

	if (!p || !p->p)
		return POM_ERR;

	pcap_breakloop(p->p);
	return POM_OK;

}

static int input_browse_dir_pcap(struct input_priv_pcap *priv) {

	char *path = PTYPE_STRING_GETVAL(p_directory);

	char errbuf[PCAP_ERRBUF_SIZE + 1];
	errbuf[0] = 0;

	DIR *dir = opendir(path);
	if (!dir) {
		strerror_r(errno, errbuf, PCAP_ERRBUF_SIZE);
		pom_log(POM_LOG_ERR "Error while opening directory %s : %s", path, errbuf);
		return POM_ERR;
	}

	struct dirent *buf, *de;
	size_t len = offsetof(struct dirent, d_name) + pathconf(path, _PC_NAME_MAX) + 1;
	buf = malloc(len);

	do {
		int res = readdir_r(dir, buf, &de);
		if (res) {
			strerror_r(errno, errbuf, PCAP_ERRBUF_SIZE);
			pom_log(POM_LOG_ERR "Error while reading directory entry : %s", errbuf);
			free(buf);
			closedir(dir);
			return POM_ERR;
		}

		if (!de)
			break;

		char *ext = PTYPE_STRING_GETVAL(p_dir_file_ext);
		int ext_len = strlen(ext);
		int fname_len = strlen(buf->d_name);
		if (ext_len < fname_len && memcmp(buf->d_name + fname_len - ext_len, ext, ext_len) == 0) {
			struct input_priv_file_pcap *tmp = priv->dir_files;
			int found = 0;
			while (tmp) {
				if (!strcmp(tmp->filename, buf->d_name)) {
					found = 1;
					break;
				}
				tmp = tmp->next;
			}
			if (!found) {
				char errbuf[PCAP_ERRBUF_SIZE + 1];

				char *fname = malloc(strlen(path) + strlen(buf->d_name) + 2);
				strcpy(fname, path);
				if (*fname && fname[strlen(fname) - 1] != '/')
					strcat(fname, "/");
				strcat(fname, buf->d_name);

				// Alloc the new file
				struct input_priv_file_pcap *cur = malloc(sizeof(struct input_priv_file_pcap));
				memset(cur, 0, sizeof(struct input_priv_file_pcap));
				cur->filename = malloc(strlen(buf->d_name) + 1);
				strcpy(cur->filename, buf->d_name);


				// Get the time of the first packet
				pcap_t *p = pcap_open_offline(fname, errbuf);
				if (!p) {
					cur->next = priv->dir_files;
					priv->dir_files = cur; // Add at the begning in order not to process it again
					pom_log(POM_LOG_WARN "Unable to open file %s : %s", fname, errbuf);
					free(fname);
					continue;
				}
				
				const u_char *next_pkt;
				struct pcap_pkthdr *phdr;

				int result = pcap_next_ex(p, &phdr, &next_pkt);

				if (result <= 0 ) {
					cur->next = priv->dir_files;
					priv->dir_files = cur; // Add at the begning in order not to process it again
					pom_log(POM_LOG_WARN "Could not read first packet from file %s", fname);
					free(fname);
					pcap_close(p);
					continue;
				}

				

				memcpy(&cur->first_pkt, &phdr->ts, sizeof(struct timeval));
				pcap_close(p);

				tmp = priv->dir_files;

				if (!tmp || (tmp && timercmp(&cur->first_pkt, &tmp->first_pkt, <))) {
					// Add at the begining
					cur->next = priv->dir_files;
					priv->dir_files = cur;

				} else {
					while (tmp->next) {
						if (timercmp(&cur->first_pkt, &tmp->next->first_pkt, <)) {
							// Add in the middle
							cur->next = tmp->next;
							tmp->next = cur;
							break;
						}
						tmp = tmp->next;
					}

					if (!tmp->next) {
						// Add at the end
						tmp->next = cur;
					}
				}


				pom_log(POM_LOG_DEBUG "Added file %s to the list", fname);

				free(fname);

			}
		}
	} while (de);

	free(buf);

	closedir(dir);

	return POM_OK;

}

static int input_open_next_file_pcap(struct input_priv_pcap *p) {

	char *filename = NULL;

	do {
		// Open the next file if any
		p->dir_cur_file = p->dir_cur_file->next;

		if (!p->dir_cur_file) { // No more file
			if (filename)
				free(filename);
			return POM_OK;
		}

		char *dir = PTYPE_STRING_GETVAL(p_directory);

		filename = realloc(filename, strlen(dir) + strlen(p->dir_cur_file->filename) + 2);
		strcpy(filename, dir);
		if (*filename && filename[strlen(filename) - 1] != '/')
			strcat(filename, "/");
		strcat(filename, p->dir_cur_file->filename);

		char errbuf[PCAP_ERRBUF_SIZE + 1];
		errbuf[0] = 0;
		p->p = pcap_open_offline(filename, errbuf);
		if (!p->p) {
			pom_log(POM_LOG_ERR "Error opening file %s for reading. Skipping", filename);
			continue;
		}

		if (pcap_datalink(p->p) == p->datalink)
			break;
		pcap_close(p->p);
		p->p = NULL;
		pom_log(POM_LOG_WARN "Skipping file %s since it's not the same datalink as the previous ones");

	} while(1);

	if (filename) {
		pom_log("Processing file %s", filename);
		free(filename);
	}

	if (strlen(PTYPE_STRING_GETVAL(p_filter)) > 0) {
	
		if (pcap_setfilter(p->p, &p->fp) == -1) {
			pom_log(POM_LOG_ERR "Unable to set the BFP filter \"%s\"", PTYPE_STRING_GETVAL(p_filter));
			pcap_freecode(&p->fp);
			pcap_close(p->p);
			p->p = NULL;
			return POM_ERR;
		}

	}

	return POM_OK;
}
