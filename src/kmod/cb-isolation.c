/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS DS_ISOLATE
#include "priv.h"
#include <linux/hash.h>
#include <linux/inet.h>
#include <linux/list.h>

#include "cb-isolation.h"

#define DHCP_CLIENT_PORT_V6 (htons((u16)546))
#define DHCP_SERVER_PORT_V6 (htons((u16)547))

#define DHCP_CLIENT_PORT_V4 (htons((u16)67))
#define DHCP_SERVER_PORT_V4 (htons((u16)68))
#define DNS_SERVER_PORT \
	(htons((u16)53)) // DNS over IPV4 or IPV6 will use port 53

struct CB_ISOLATION_STATS g_cbIsolationStats;

static enum CB_ISOLATION_MODE CBIsolationMode = IsolationModeOff;
static struct CB_ISOLATION_MODE_CONTROL *pCurrentCbIsolationModeControl = NULL;
uint64_t pControlLock;
static volatile bool isInitialized = false;

int CbInitializeNetworkIsolation(void)
{
	cb_initspinlock(&pControlLock);
	atomic_set((atomic_t *)&CBIsolationMode, IsolationModeOff);
	atomic_set((atomic_t *)&isInitialized, true);
	return 0;
}

void CbDestroyNetworkIsolation(void)
{
	if (!isInitialized) {
		return;
	}

	atomic_set((atomic_t *)&isInitialized, false);
	atomic_set((atomic_t *)&CBIsolationMode, IsolationModeOff);

	cb_spinlock(&pControlLock);
	if (pCurrentCbIsolationModeControl) {
		kfree(pCurrentCbIsolationModeControl);
		pCurrentCbIsolationModeControl = NULL;
	}
	cb_spinunlock(&pControlLock);
	cb_destroyspinlock(&pControlLock);
}

void CbSetNetworkIsolationMode(enum CB_ISOLATION_MODE isolationMode)
{
	atomic_set((atomic_t *)&CBIsolationMode, isolationMode);
	g_cbIsolationStats.isolationEnabled = isolationMode == IsolationModeOn;
	PRINTK(KERN_INFO, "CB ISOLATION MODE: %s",
	       isolationMode == IsolationModeOff ? "DISABLED" : "ENABLED");
}

int CbProcessIsolationSetMode(void *pBuf, uint32_t InputBufLen)
{
	struct CB_ISOLATION_MODE_CONTROL *tmpIsolationModeControl;
	uint32_t ExpectedBufLen;

	if (!isInitialized) {
		return -1;
	}

	tmpIsolationModeControl = (struct CB_ISOLATION_MODE_CONTROL *)kmalloc(
		InputBufLen, GFP_KERNEL);
	if (!tmpIsolationModeControl) {
		PRINTK(KERN_ERR,
		       "Failed to allocate buffer of isolation mode control");
		return -1;
	}
	if (copy_from_user(tmpIsolationModeControl, pBuf, InputBufLen)) {
		PRINTK(KERN_ERR, "Failed copy from userspace");
		kfree(tmpIsolationModeControl);
		return -1;
	}

	// Calculate the size of the buffer we should have hold the number of
	// addresses that user space claims is present.
	// This prevents us from reading past the buffer later. (CB-8236)
	ExpectedBufLen =
		sizeof(struct CB_ISOLATION_MODE_CONTROL) +
		(sizeof(uint32_t) *
		 (tmpIsolationModeControl->numberOfAllowedIpAddresses - 1));
	if (ExpectedBufLen > InputBufLen) {
		PRINTK(KERN_ERR,
		       "Expected buffer is larger than what we received. (%d > %d)",
		       ExpectedBufLen, InputBufLen);
		kfree(tmpIsolationModeControl);
		return -1;
	}

	cb_spinlock(&pControlLock);
	// Move the temp isolation mode control struct to global state.
	if (pCurrentCbIsolationModeControl) {
		kfree(pCurrentCbIsolationModeControl);
		pCurrentCbIsolationModeControl = NULL;
	}
	pCurrentCbIsolationModeControl = tmpIsolationModeControl;

	CbSetNetworkIsolationMode(
		pCurrentCbIsolationModeControl->isolationMode);

	if (pCurrentCbIsolationModeControl->isolationMode == IsolationModeOff) {
		PRINTK(KERN_INFO, "isolation OFF");
	} else {
		char str[INET_ADDRSTRLEN];
		unsigned char *addr;
		int i;
		for (i = 0;
		     i <
		     pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses;
		     ++i) {
			addr = (unsigned char *)&pCurrentCbIsolationModeControl
				       ->allowedIpAddresses[i];
			snprintf(str, INET_ADDRSTRLEN, "%d.%d.%d.%d", addr[3],
				 addr[2], addr[1], addr[0]);
			PRINTK(KERN_INFO, "isolation ON IP: %s", str);
		}
	}
	cb_spinunlock(&pControlLock);

	return 0;
}

void CbIsolationInterceptByAddrProtoPort(
	uint32_t remoteIpAddress, bool isIpV4, uint32_t protocol, uint16_t port,
	struct CB_ISOLATION_INTERCEPT_RESULT *isolationResult)
{
	if (!isInitialized) {
		return;
	}

	// Immediately allow if isolation mode is not on
	if (atomic_read((atomic_t *)&CBIsolationMode) == IsolationModeOff) {
		isolationResult->isolationAction = IsolationActionDisabled;
		return;
	}

	if (protocol == IPPROTO_UDP &&
	    (((isIpV4 == true) &&
	      (port == DHCP_CLIENT_PORT_V4 || port == DHCP_SERVER_PORT_V4)) ||
	     ((isIpV4 == false) &&
	      (port == DHCP_CLIENT_PORT_V6 || port == DHCP_SERVER_PORT_V6)) ||
	     port == DNS_SERVER_PORT)) {
		PR_DEBUG(
			"ISOLATION ALLOWED:: %s ADDR: 0x%08x PROTO: %s PORT: %u",
			(isIpV4 ? "IPv4" : "IPv6"), remoteIpAddress,
			(protocol == IPPROTO_UDP ? "UDP" : "TCP"), ntohs(port));
		isolationResult->isolationAction = IsolationActionAllow;
		return;
	}

	if (!pCurrentCbIsolationModeControl) {
		return;
	}

	// Our allowed list of addresses is IPv4, so just block IPv6 addresses
	// acquire shared resource
	if (isIpV4) {
		int i;
		cb_spinlock(&pControlLock);
		for (i = 0;
		     i <
		     pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses;
		     i++) {
			uint32_t allowedIpAddress =
				pCurrentCbIsolationModeControl
					->allowedIpAddresses[i];
			if (allowedIpAddress &&
			    remoteIpAddress == allowedIpAddress) {
				PR_DEBUG(
					"ISOLATION ALLOWED: By %s ADDR: 0x%08x PROTO: %s PORT: %u",
					(isIpV4 ? "IPv4" : "IPv6"),
					remoteIpAddress,
					(protocol == IPPROTO_UDP ? "UDP" :
								   "TCP"),
					ntohs(port));
				isolationResult->isolationAction =
					IsolationActionAllow;
				cb_spinunlock(&pControlLock);
				return;
			}
		}
		cb_spinunlock(&pControlLock);
	}

	PR_DEBUG("ISOLATION BLOCKED: %s ADDR: 0x%08x PROTO: %s PORT: %u",
		 (isIpV4 ? "IPv4" : "IPv6"), remoteIpAddress,
		 (protocol == IPPROTO_UDP ? "UDP" : "TCP"), ntohs(port));
	isolationResult->isolationAction = IsolationActionBlock;
}
