#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

// don't know how to give parameter to cb function.
// set global variable
string host;

void usage(){
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

int hostcheck(unsigned char* buf){
	printf("%s", host.c_str());
	// return 0 if host is not same as buf
	for(int i = 0; i < host.size(); i++){
		if(host[i] != buf[i]){
			return 1;
		}
	}
	return 0;
}

bool filter(unsigned char* buf, int size){
	int ip_header_len = (buf[0] & 0xf )* 4;
	buf += ip_header_len;
	size -= ip_header_len;
	printf("\nremove ip header\n");
	printf("ip header len %d", ip_header_len);
	printf("\n");

	// check tcp port
	int tcp_dst_port = buf[2] * 256 + buf[3];
	
	printf("\ntcp dst port is %d\n", tcp_dst_port);

	if(tcp_dst_port == 80) {
		printf("http checked\n");
		int tcp_header_len = 20;
		buf += tcp_header_len;
		size -= tcp_header_len;

		char H = 0x48;
		char o = 0x6f;
		char s = 0x73;
		char t = 0x74;
		char _ = 0x3a;

		int check = 0;
		printf("http protocol packet\n");
		for(int j=0;j<size;j++){
			if(j%16 == 0){
				printf("\n");
			}
			printf("%02x ", buf[j]);
		}
		for (int i = 0; i < size; i++) {

			if(check == 0 && buf[i] == H){
				// printf("HHHHHHH\n");
				if(buf[i+1] == o){
					// printf("ooooooo\n");
					if(buf[i+2] == s){
						// printf("ssssss\n");
						if(buf[i+3] == t){
							// printf("tttttt\n");
							if(buf[i+4] == _){
								buf += (i+6);
								size -= (i+6);

								int host_equal = hostcheck(buf);
								if(!host_equal){
									printf("\n\n-----------------------\nthis is bad host!!\n");
									return true;
								}
								else return false;
							}
						}
					}
				}
			}
		}
	}
	return false;
}
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	return id;
}

static bool filter_pkt (struct nfq_data *tb){
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
        printf("\n");
        // dump(data, ret);
		bool is_filtered = filter(data, ret);
		printf("payload_len=%d\n", ret);
	return is_filtered;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	int is_filtered = filter_pkt(nfa);
	printf("entering callback\n");
	if(is_filtered){
		printf("fbi warning. pls go out.\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char** argv)
{
    if(argc != 2){
        usage();
    }
    host = argv[1];

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
