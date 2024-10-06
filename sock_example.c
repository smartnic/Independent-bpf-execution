/* eBPF example program:
 * - creates arraymap in kernel with key 4 bytes and value 8 bytes
 * 
 * - updates map in kernel with key 255 mapping to the value "%lld"
 *
 * - loads eBPF program:
 *   r0 = 255;
 *   *(u32*)(fp-4) = r0;
 *   value = bpf_map_lookup_elem(map_fd, fp-4);
 *   if(value)
 *   	bpf_trace_printk(value, 8, bpf_ktime_get_ns());
 *   r0 = skb->data[ETH_HLEN + offsetof(struct iphdr, protocol)];
 *   *(u32*)(fp - 8) = r0;
 *   // assuming packet is IPv4, lookup ip->proto in a map
 *   value = bpf_map_lookup_elem(map_fd, fp - 8);
 *   if (value)
 *        (*(u64*)value) += 1;
 *
 * - attaches this program to loopback interface "lo" raw socket
 *
 * - every second user space reads map[tcp], map[udp], map[icmp] to see
 *   how many packets of given protocol were seen on "lo"
 */
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include "bpf/bpf.h"
#include "bpf_insn.h"
#include "sock_example.h"

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int test_sock(void)
{
	int sock = -1, map_fd, prog_fd, i, key;
	long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;
	int keys = 0xff;
	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
				256, 0);
	char inputString[4] = "%lld";
	int a = bpf_map_update_elem(map_fd, &keys, &inputString, BPF_ANY);
	/*
	char outputString[4]
	bpf_map_lookup_elem(map_fd, &keys, outputString);
	printf("%d %s\n",keys, outputString);
	perror("Errors: \n");
	printf("%d\n",a);
	*/
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	struct bpf_insn prog[] = {
		#include "Input.txt"
	};

	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	prog_fd = bpf_load_program(BPF_PROG_TYPE_SOCKET_FILTER, prog, insns_cnt,
				   "GPL", 0, bpf_log_buf, BPF_LOG_BUF_SIZE);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		//printf("%s \n", bpf_log_buf);
		goto cleanup;
	}

	sock = open_raw_sock("lo");

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
		       sizeof(prog_fd)) < 0) {
		printf("setsockopt %s\n", strerror(errno));
		goto cleanup;
	}

	for (i = 0; i < 10; i++) {
		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %lld UDP %lld ICMP %lld packets\n",
		       tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
	}

cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */
	return 0;
}

int main(void)
{
	FILE *f;

	f = popen("ping -4 -c5 localhost", "r");
	(void)f;

	return test_sock();
}
