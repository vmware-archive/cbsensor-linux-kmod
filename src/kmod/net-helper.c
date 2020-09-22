/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_NET)
#include "priv.h"

#define IPV6_SCOPE_DELIMITER '%'
#define IPV6_SCOPE_ID_LEN sizeof("%nnnnnnnnnn")
static size_t rpc_ntop6_noscopeid(const struct sockaddr *sap, char *buf,
				  const int buflen)
{
	const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sap;
	const struct in6_addr *addr = &sin6->sin6_addr;

	/*
	 * RFC 4291, Section 2.2.2
	 *
	 * Shorthanded ANY address
	 */
	if (ipv6_addr_any(addr))
		return snprintf(buf, buflen, "::");

	/*
	 * RFC 4291, Section 2.2.2
	 *
	 * Shorthanded loopback address
	 */
	if (ipv6_addr_loopback(addr))
		return snprintf(buf, buflen, "::1");

	/*
	 * RFC 4291, Section 2.2.3
	 *
	 * Special presentation address format for mapped v4 addresses.
	 */
	if (ipv6_addr_v4mapped(addr))
		return snprintf(buf, buflen, "::ffff:%pI4",
				&addr->s6_addr32[3]);

	/*
	 * RFC 4291, Section 2.2.1
	 */
	return snprintf(buf, buflen, "%pI6c", addr);
}

static size_t rpc_ntop6(const struct sockaddr *sap, char *buf,
			const size_t buflen)
{
	const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sap;
	char scopebuf[IPV6_SCOPE_ID_LEN];
	size_t len;
	int rc;

	len = rpc_ntop6_noscopeid(sap, buf, buflen);
	if (unlikely(len == 0))
		return len;

	if (!(ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL))
		return len;
	if (sin6->sin6_scope_id == 0)
		return len;

	rc = snprintf(scopebuf, sizeof(scopebuf), "%c%u", IPV6_SCOPE_DELIMITER,
		      sin6->sin6_scope_id);
	if (unlikely((size_t)rc > sizeof(scopebuf)))
		return 0;

	len += rc;
	if (unlikely(len > buflen))
		return 0;

	strcat(buf, scopebuf);
	return len;
}

static int rpc_ntop4(const struct sockaddr *sap, char *buf, const size_t buflen)
{
	const struct sockaddr_in *sin = (struct sockaddr_in *)sap;

	return snprintf(buf, buflen, "%pI4", &sin->sin_addr);
}

/**
 * rpc_ntop - construct a presentation address in @buf
 * @sap: socket address
 * @buf: construction area
 * @buflen: size of @buf, in bytes
 *
 * Plants a %NUL-terminated string in @buf and returns the length
 * of the string, excluding the %NUL.  Otherwise zero is returned.
 */
size_t cb_ntop(const struct sockaddr *sap, char *buf, const size_t buflen,
	       uint16_t *port)
{
	switch (sap->sa_family) {
	case AF_INET:
		*port = ((struct sockaddr_in *)sap)->sin_port;
		return rpc_ntop4(sap, buf, buflen);
	case AF_INET6:
		*port = ((struct sockaddr_in6 *)sap)->sin6_port;
		return rpc_ntop6(sap, buf, buflen);
	}

	memset(buf, 0, buflen);
	*port = 0;
	return 0;
}
