
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "target_udp.h"
#include "target_rtp.h"

int match_udp_id;

int target_register_rtp() {

	struct target_reg t;
	t.target_name = "rtp";
	t.init = target_init_rtp;
	t.process = target_process_rtp;
	t.close = target_close_rtp;

	match_udp_id = match_register("udp");
	
	return target_register(&t);
	

}

int target_init_rtp(struct rule_target *t) {

	struct target_priv_rtp *priv = malloc(sizeof(struct target_priv_rtp));
	bzero(priv, sizeof(struct target_priv_rtp));


	struct target_priv_rtp_wave_hdr *wh = &priv->wavehdr;

	memcpy(wh->chunk_id, "RIFF", 4);
	memcpy(wh->chunk_format, "WAVE", 4);;
	memcpy(wh->subchunk1_id, "fmt ", 4);
	wh->subchunk1_size = 16; // for PCM
	wh->audio_format = 1; // for PCM
	wh->channels = 1; // Mono
	wh->sample_rate = 8000;
	wh->bits_per_sample = 8;
	wh->byte_rate = wh->sample_rate * wh->channels * wh->bits_per_sample / 8;
	wh->block_align = wh->channels * wh->bits_per_sample / 8;
	memcpy(wh->subchunk2_id, "data", 4);


	
	t->target_priv = priv;
	

	return 1;
}


int target_open_rtp(struct rule_target *t, char *filename) {

	struct target_priv_rtp *priv = t->target_priv;
	priv->fd = open(filename, O_RDWR | O_CREAT);

	if (priv->fd == -1)
		return 0;

	write(priv->fd, &priv->wavehdr, sizeof(struct target_priv_rtp_wave_hdr));
	
	return 1;	

}


int target_process_rtp(struct rule_target *t, struct rule_node *node, void *frame, unsigned int len) {

	struct target_priv_rtp*priv = t->target_priv;
	
	int start = match_find_header_start(node, match_udp_id);

	if (start == -1) {
		dprint("Unable to find the start of the packet\n");
		return 0;

	}
	
	frame += start;
	len -= start;
	

	return 1;
};

int target_close_rtp(struct rule_target *t) {
	
	struct target_priv_rtp *priv = t->target_priv;
	
	close(priv->fd);
	free(priv);
	t->target_priv = NULL;
	return 1;
};


