/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "file-write-cache.h"
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct fwc_bkt {
	spinlock_t lock;
	u32 size;
	struct list_head list;
};

struct fwc_key {
	pid_t tgid;
	ino_t inode;
	dev_t dev;
	u64 time;
};

struct fwc_entry {
	u32 hash;
	struct fwc_key key;
	struct list_head list;
	u32 hits;
};

struct fwc_cache {
	struct fwc_bkt *bkt;
};

#define FWC_MAX_BKT_SZ 10
#define FWC_BUCKET_BITS 7
#define FWC_BUCKETS BIT(FWC_BUCKET_BITS)

static struct fwc_cache *fwc_cache = NULL;

int fwc_cache_enabled = 0;

static inline u32 fwc_hash(struct fwc_key *key)
{
	return jhash(key, sizeof(*key), 0);
}
static int fwc_bucket_index(u32 hash)
{
	return hash & (FWC_BUCKETS - 1);
}

int fwc_register(void)
{
	u32 i;

	fwc_cache = kzalloc(sizeof(struct fwc_cache), GFP_KERNEL);
	if (!fwc_cache) {
		return -ENOMEM;
	}

	fwc_cache->bkt =
		kcalloc(FWC_BUCKETS, sizeof(struct fwc_bkt), GFP_KERNEL);
	if (!fwc_cache->bkt) {
		kfree(fwc_cache);
		return -ENOMEM;
	}

	for (i = 0; i < FWC_BUCKETS; i++) {
		spin_lock_init(&fwc_cache->bkt[i].lock);
		fwc_cache->bkt[i].size = 0;
		INIT_LIST_HEAD(&fwc_cache->bkt[i].list);
	}
	fwc_cache_enabled = 1;
	return 0;
}
static void fwc_free_entries(void);
void fwc_shutdown(void)
{
	if (fwc_cache) {
		// Shutdown Cache
		fwc_cache_enabled = 0;
		fwc_free_entries();

		// Iterate through entries and free
		kfree(fwc_cache);
		fwc_cache = NULL;
	}
}

static void fwc_free_entries(void)
{
	struct fwc_entry *entry, *tmp;
	int i;
	unsigned long flags;

	for (i = 0; i < FWC_BUCKETS; i++) {
		spin_lock_irqsave(&fwc_cache->bkt[i].lock, flags);
		list_for_each_entry_safe (entry, tmp, &fwc_cache->bkt[i].list,
					  list) {
			list_del_init(&entry->list);
			kfree(entry);
		}
		fwc_cache->bkt[i].size = 0;
		spin_unlock_irqrestore(&fwc_cache->bkt[i].lock, flags);
	}
}

static struct fwc_entry *__lookup_entry_safe(u32 hash, struct fwc_key *key,
					     struct list_head *head)
{
	struct fwc_entry *entry;
	struct fwc_entry *tmp;
	list_for_each_entry_safe (entry, tmp, head, list) {
		if (entry->hash == hash && entry->key.tgid == key->tgid &&
		    entry->key.inode == key->inode &&
		    entry->key.dev == key->dev &&
		    entry->key.time == key->time) {
			return entry;
		}
	}
	return NULL;
}

// Add Entry if Does not Exist
// Return 0 and increment hit When Entry Exists
int fwc_entry_exists(pid_t tgid, ino_t inode, dev_t dev, u64 time, gfp_t mode)
{
	u32 hash;
	unsigned long flags;
	struct fwc_entry *entry;
	struct fwc_bkt *bkt;
	int bkt_index;
	struct fwc_key key = {
		.tgid = tgid, .inode = inode, .dev = dev, .time = time
	};
	if (!fwc_cache_enabled) {
		return 0;
	}

	hash = fwc_hash(&key);
	bkt_index = fwc_bucket_index(hash);
	bkt = &(fwc_cache->bkt[bkt_index]);

	// Lookup Entry
	spin_lock_irqsave(&bkt->lock, flags);
	entry = __lookup_entry_safe(hash, &key, &bkt->list);
	if (entry) {
		entry->hits += 1;
		spin_unlock_irqrestore(&bkt->lock, flags);
		return 0;
	}
	spin_unlock_irqrestore(&bkt->lock, flags);

	// Create New Entry
	entry = kzalloc(sizeof(*entry), mode);
	if (!entry) {
		return -ENOMEM;
	}
	entry->hash = hash;
	memcpy(&entry->key, &key, sizeof(key));

	// Insert New Entry
	spin_lock_irqsave(&bkt->lock, flags);
	if (bkt->size >= FWC_MAX_BKT_SZ) {
		// Remove oldest entry as needed
		struct fwc_entry *old;
		old = list_entry(bkt->list.prev, struct fwc_entry, list);
		list_del_init(&old->list);
		list_add(&entry->list, &bkt->list);

		kfree(old);
	} else {
		list_add(&entry->list, &bkt->list);
		bkt->size += 1;
	}
	spin_unlock_irqrestore(&bkt->lock, flags);
	return -ENOENT;
}
