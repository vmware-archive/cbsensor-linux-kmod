/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS DS_NET
#include "priv.h"
#include <linux/skbuff.h>
#undef __KERNEL__
#include <linux/netfilter.h>
#define __KERNEL__
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <net/ip.h>

#include "cb-isolation.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define cb_ipv6_skip_exthdr(skb, ptr, pProtocol)             \
	do {                                                 \
		ptr = ipv6_skip_exthdr(skb, ptr, pProtocol); \
	} while (0)
#else
#define cb_ipv6_skip_exthdr(skb, ptr, pProtocol)                        \
	do {                                                            \
		__be16 frag_off;                                        \
		ptr = ipv6_skip_exthdr(skb, ptr, pProtocol, &frag_off); \
	} while (0)
#endif

#define NUM_HOOKS 2
static struct nf_hook_ops nfho_local_out[NUM_HOOKS];

int find_char_offset(const struct sk_buff *skb, int offset, char target);
int web_proxy_request_check(struct sk_buff *skb);

extern uint32_t g_enableHooks;

static unsigned int hook_func_local_out(
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	unsigned int hooknum,
#else
	const struct nf_hook_ops *ops,
#endif
	struct sk_buff *skb, const struct net_device *in,
	const struct net_device *out,
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)
	const struct nf_hook_state *state
#else
	int (*okfn)(struct sk_buff *)
#endif
)
{
	unsigned int xcode = NF_ACCEPT;
	void *daddr = NULL;
	int family;
	uint8_t protocol;
	struct udphdr *udp_header;

	struct CB_ISOLATION_INTERCEPT_RESULT isolation_result;
	MODULE_GET();

	TRY(skb);
	TRY(skb->sk);

	family = skb->sk->sk_family;
	TRY(family == AF_INET || family == AF_INET6);

	if (family == AF_INET) {
		struct iphdr *ip_header =
			(struct iphdr *)skb_network_header(skb);
		TRY(ip_header);

		protocol = ip_header->protocol;
		daddr = &ip_header->daddr;
	} else {
		struct ipv6hdr *ip_header = ipv6_hdr(skb);
		int ptr = (u8 *)(ip_header + 1) - skb->data;

		TRY(ip_header);
		protocol = ip_header->nexthdr;
		daddr = &ip_header->daddr.s6_addr32[0];

		// Use the ipv6_skip_exthdr function to skip past any extended
		// headers that may be present. We dont actually care about the
		// returned pointer, just the protocol for the next header
		cb_ipv6_skip_exthdr(skb, ptr, &protocol);
	}

	if (g_cbIsolationStats.isolationEnabled) {
		if (protocol == IPPROTO_UDP) {
			udp_header = (struct udphdr *)skb_transport_header(skb);

			CbIsolationInterceptByAddrProtoPort(
				ntohl(*(uint32_t *)daddr), true, protocol,
				udp_header->dest, &isolation_result);
			if (isolation_result.isolationAction ==
			    IsolationActionBlock) {
				xcode = NF_DROP;
				goto CATCH_DEFAULT;
			}
		}
	}

	if (protocol == IPPROTO_TCP) {
		web_proxy_request_check(skb);
	}

CATCH_DEFAULT:
	MODULE_PUT();
	return xcode;
}

int web_proxy_request_check(struct sk_buff *skb)
{
	char tmp[10];
	char url[CB_PROXY_SERVER_MAX_LEN];

	const char *HTTP_METHODS[] = { "GET", "PUT", "POST", "DELETE",
				       "CONNECT" };
	const int HTTP_METHODS_LEN[] = { 3, 3, 4, 6, 7 };
	const int HTTP_METHOD_MAX_LEN = 7;
	const char *HTTP_VERSION[] = { "HTTP/1.1", "HTTP/1.0" };
	const int HTTP_VERSION_LEN = 8;
	int family;

	int i;
	int space_offset;
	int url_len;
	int payload_offset;
	struct tcphdr *tcp_header;
	struct CB_EVENT *event;

	TRY(skb);
	TRY(skb->sk);

	family = skb->sk->sk_family;

	// The skb_transport_offset will give me offset of the transport header,
	// skipping any IPv6 extended headers.
	payload_offset = skb_transport_offset(skb) + tcp_hdrlen(skb);

	if (skb_copy_bits(skb, payload_offset, tmp, HTTP_METHOD_MAX_LEN + 2) !=
	    0) {
		goto CATCH_DEFAULT;
	}

	for (i = 0; i < 5; i++) {
		if (strncmp(HTTP_METHODS[i], tmp, HTTP_METHODS_LEN[i]) != 0) {
			continue;
		}

		if (tmp[HTTP_METHODS_LEN[i] + 1] == '/') {
			goto CATCH_DEFAULT;
		}

		space_offset = find_char_offset(
			skb, payload_offset + HTTP_METHODS_LEN[i] + 2, ' ');
		if (space_offset == -1) {
			goto CATCH_DEFAULT;
		}

		if (skb_copy_bits(skb, space_offset + 1, tmp,
				  HTTP_VERSION_LEN) != 0) {
			goto CATCH_DEFAULT;
		}

		if (strncmp(HTTP_VERSION[0], tmp, HTTP_VERSION_LEN) != 0 &&
		    strncmp(HTTP_VERSION[1], tmp, HTTP_VERSION_LEN) != 0) {
			goto CATCH_DEFAULT;
		}

		url_len = space_offset -
			  (payload_offset + HTTP_METHODS_LEN[i] + 1);
		if (url_len >= CB_PROXY_SERVER_MAX_LEN) {
			url_len = CB_PROXY_SERVER_MAX_LEN - 1;
		}

		if (skb_copy_bits(skb, payload_offset + HTTP_METHODS_LEN[i] + 1,
				  url, url_len) != 0) {
			goto CATCH_DEFAULT;
		}

		url[url_len] = 0;

		PR_DEBUG("will send proxy event for pid %lld to %s",
			 (uint64_t)getpid(current), url);

		event = logger_alloc_event_atomic(CB_EVENT_TYPE_WEB_PROXY,
						  current);
		if (event) {
			// The url buffer is the same size as the actual_server
			// buffer.
			memcpy(event->netConnect.actual_server, url,
			       url_len + 1); // include null-terminator.
			// actual_port will be obtained at cbdaemon based on
			// actual_server url.

			event->netConnect.localAddr.sa_addr.sa_family = family;
			event->netConnect.remoteAddr.sa_addr.sa_family = family;

			tcp_header = (struct tcphdr *)skb_transport_header(skb);

			if (family == AF_INET) {
				struct iphdr *ip_header =
					(struct iphdr *)skb_network_header(skb);

				event->netConnect.remoteAddr.as_in4.sin_addr
					.s_addr = ip_header->daddr;
				event->netConnect.localAddr.as_in4.sin_addr
					.s_addr = ip_header->saddr;

				event->netConnect.remoteAddr.as_in4.sin_port =
					tcp_header->dest;
				event->netConnect.localAddr.as_in4.sin_port =
					tcp_header->source;
			} else {
				struct ipv6hdr *ip_header =
					(struct ipv6hdr *)skb_network_header(
						skb);
				event->netConnect.remoteAddr.as_in6.sin6_addr =
					ip_header->daddr;
				event->netConnect.localAddr.as_in6.sin6_addr =
					ip_header->saddr;

				event->netConnect.remoteAddr.as_in6.sin6_port =
					tcp_header->dest;
				event->netConnect.localAddr.as_in6.sin6_port =
					tcp_header->source;
			}

			printAddress(NULL, __FUNCTION__, skb->sk,
				     &event->netConnect.localAddr.sa_addr,
				     &event->netConnect.remoteAddr.sa_addr);
			logger_submit_event(event);
		}

		goto CATCH_DEFAULT;
	}

CATCH_DEFAULT:
	return 0;
}

int find_char_offset(const struct sk_buff *skb, int offset, char target)
{
	char *ptr;
	char *frag_addr;
	int frag_len;
	int current_offset;
	int i;

	// There is data inside skb, so search the remaining data before search
	// fragments.
	if (skb->len - skb->data_len > offset) {
		current_offset = offset;
		for (ptr = (char *)skb->data + offset;
		     ptr < (char *)skb_tail_pointer(skb); ptr++) {
			if (*ptr == target) {
				return current_offset;
			}
			current_offset++;
		}
	} else {
		current_offset = skb->len - skb->data_len;
	}

	for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0; i--) {
		frag_addr = skb_frag_address_safe(&skb_shinfo(skb)->frags[i]);
		frag_len = skb_frag_size(&skb_shinfo(skb)->frags[i]);
		for (ptr = frag_addr; ptr <= frag_addr + frag_len; ptr++) {
			if (current_offset >= offset && *ptr == target) {
				return current_offset;
			}
			current_offset++;
		}
	}
	return -1;
}

bool netfilter_initialize(uint32_t enableHooks)
{
	nfho_local_out[0].hook = hook_func_local_out;
	nfho_local_out[0].hooknum = NF_INET_LOCAL_OUT;
	nfho_local_out[0].pf = PF_INET;
	nfho_local_out[0].priority = NF_IP_PRI_FIRST;

	nfho_local_out[1].hook = hook_func_local_out;
	nfho_local_out[1].hooknum = NF_INET_LOCAL_OUT;
	nfho_local_out[1].pf = PF_INET6;
	nfho_local_out[1].priority = NF_IP_PRI_FIRST;

	if (enableHooks & CB__NF_local_out)
		nf_register_hooks(nfho_local_out, NUM_HOOKS);

	PRINTK(KERN_INFO, "Netfilter hook has been inserted");

	return true;
}

void netfilter_cleanup(uint32_t enableHooks)
{
	PRINTK(KERN_INFO, "Netfilter hook has been unregistered");
	if (enableHooks & CB__NF_local_out)
		nf_unregister_hooks(nfho_local_out, NUM_HOOKS);
}

#ifdef HOOK_SELECTOR
static void setNetfilter(const char *buf, const char *name, uint32_t call,
			 void *cb_hook, int cb_hook_nr)
{
	if (0 == strncmp("1", buf, sizeof(char))) {
		PR_DEBUG("Adding %s", name);
		g_enableHooks |= call;
		nf_register_hooks(cb_hook, cb_hook_nr);
	} else if (0 == strncmp("0", buf, sizeof(char))) {
		PR_DEBUG("Removing %s", name);
		g_enableHooks &= ~call;
		nf_unregister_hooks(cb_hook, cb_hook_nr);
	} else {
		PR_DEBUG("Error adding %s to %s", buf, name);
		return;
	}
}

static int getNetfilter(uint32_t call, struct seq_file *m)
{
	seq_printf(m, (g_enableHooks & call ? "1\n" : "0\n"));
	return 0;
}

int cb_netfilter_local_out_get(struct seq_file *m, void *v)
{
	return getNetfilter(CB__NF_local_out, m);
}

ssize_t cb_netfilter_local_out_set(struct file *file, const char *buf,
				   size_t size, loff_t *ppos)
{
	setNetfilter(buf, "local_out", CB__NF_local_out, nfho_local_out,
		     NUM_HOOKS);
	return size;
}
#endif
