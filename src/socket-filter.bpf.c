//+build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "socket-filter.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_HLEN                                                               \
  14 /* Total octets in header (copied from linux/if_ether.h).	 */

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 256);
  __type(key, int);
  __type(value, int);
} countmap SEC(".maps");

SEC("socket")
int socket_prog(struct __sk_buff *skb) {
  __u8 proto;
  if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
                         &proto, sizeof(proto)) < 0) {
    return 0;
  }
  int key = (int)proto;
  int one = 1;
  int *value = bpf_map_lookup_elem(&countmap, &key);
  if (value) {
    (*value)++;
  } else {
    value = &one;
  }
  bpf_map_update_elem(&countmap, &key, value, BPF_ANY);
  return 0;
}
