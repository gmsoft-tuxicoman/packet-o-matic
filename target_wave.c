
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "target_wave.h"
#include "match_rtp.h"

unsigned int match_rtp_id;

int target_register_wave(struct target_reg *r) {

	r->init = target_init_wave;
	r->open = target_open_wave;
	r->process = target_process_wave;
	r->close_connection = target_close_connection_wave;
	r->close = target_close_wave;
	r->cleanup = target_cleanup_wave;


	return 1;

}

int target_cleanup_wave(struct target *t) {

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_wave(struct target *t) {


	struct target_priv_wave *priv = malloc(sizeof(struct target_priv_wave));
	bzero(priv, sizeof(struct target_priv_wave));

	t->target_priv = priv;
	
	match_rtp_id = (*t->match_register) ("rtp");

	return 1;
}


int target_open_wave(struct target *t, const char *prefix) {

	struct target_priv_wave *priv = t->target_priv;
	strncpy(priv->prefix, prefix, NAME_MAX);

	return 1;	
}


int target_process_wave(struct target *t, struct rule_node *node, void *frame, unsigned int len) {

	struct target_priv_wave *priv = t->target_priv;
	struct target_conntrack_priv_wave *cp;

	cp = (*t->conntrack_get_priv) (t, node, frame);

	unsigned int start = node_find_payload_start(node);
	unsigned int size = node_find_payload_size(node);

	int rtp_start = node_find_header_start(node, match_rtp_id);
	struct rtphdr *rtphdr;
	rtphdr = frame + rtp_start;

	if (!cp) {

		// Do not create a file is there is nothing to save
		if (start >= len)
			return 1;

		// Allocate the audio header
		struct au_hdr *auhdr;
		auhdr = malloc(sizeof(struct au_hdr));
		bzero(auhdr, sizeof(struct au_hdr));
		memcpy(auhdr->magic, ".snd", 4);
		auhdr->hdr_size = htonl(24);
		auhdr->data_size = 0;
		switch (rtphdr->payload_type) {
			case 1: // G.711U
				auhdr->encoding = htonl(1);
				break;
			case 8: // G.711A
				auhdr->encoding = htonl(27);
				break;
			case 9: // G.722
				auhdr->encoding = htonl(24);
				break;
			default:
				ndprint("WAVE: Payload type %u not supported\n", rtphdr->payload_type);
				free(auhdr);
				return 0;

		}
		auhdr->sample_rate = htonl(8000);
		auhdr->channels = htonl(1);

		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_wave));
		bzero(cp, sizeof(struct target_conntrack_priv_wave));

		char filename[NAME_MAX];

		char outstr[20];
		bzero(outstr, 20);
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "%Y%m%d-%H%M%S-";
		struct timeval tv;
		struct tm *tmp;
		gettimeofday(&tv, NULL);
		tmp = localtime(&tv.tv_sec);
		strftime(outstr, 20, format, tmp);

		strcpy(filename, priv->prefix);
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)tv.tv_usec);
		strcat(filename, outstr);
		strcat(filename, ".au");
		cp->fd = open(filename, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			free(cp);
			dprint("Unable to open file %s for writing : %s\n", filename, strerror(errno));
			return -1;
		}

		ndprint("%s opened\n", filename);

		(*t->conntrack_add_priv) (t, cp, node, frame);



		cp->last_seq = ntohs(rtphdr->seq_num) - 1;

		write(cp->fd, auhdr, sizeof(struct au_hdr));

		free(auhdr);

	}



	__u16 cur_seq = ntohs(rtphdr->seq_num);
	
	cp->last_seq++;

	if (cp->last_seq != cur_seq) {
		char *buffer = malloc(size);
		switch (rtphdr->payload_type) {
			case 1: // G.711U
			case 8: // G.711A
				memset(buffer, 0x55, size);
				break;
			default: 
				memset(buffer, 0x0, size);
		}

		while (cp->last_seq != cur_seq) { // Fill with 0
			write(cp->fd, buffer, size);
			cp->last_seq++;
		}
	}

	cp->total_size += size;

	write(cp->fd, frame + start, size);

	return 1;
};

int target_close_connection_wave(void *conntrack_priv) {

	ndprint("Closing connection 0x%x\n", (unsigned) conntrack_priv);

	struct target_conntrack_priv_wave *cp;
	cp = conntrack_priv;

	lseek(cp->fd, 8, SEEK_SET);
	__u32 size = htonl(cp->total_size);
	write(cp->fd, &size , 4);


	close(cp->fd);

	free(cp);
	
	return 1;

}

int target_close_wave(struct target *t) {
	
	return 1;
};



