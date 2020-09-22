/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/seq_file.h>

#define ACTION_CONTINUE 0
#define ACTION_STOP 1
#define ACTION_DELETE 4

// hash-table-generic provides interfaces for hash tables. It supports arbitrary
// key length. In order to use this hash table, you need to create a struct that
// contains a struct hlist_node called 'link'. Then you can add one, or more
// fields as the key. Last, add fields as value. The order does matter here,
// because the implementation will use the address of link plus the offset to
// get the key. So you need to make sure 'link' is before the key, and the key
// is before the value. Also be careful of struct alignment here. Memset to 0 is
// recommended after creating a key. See hash_table_test for usage.
//

struct HashTbl {
	struct hashtbl_bkt *tablePtr;
	struct list_head genTables;
	uint64_t numberOfBuckets;
	uint32_t secret;
	atomic64_t tableInstance;
	atomic64_t tableAllocs;
	atomic64_t tableShutdown; // shutting down = 1 running = 0
	int key_len;
	struct kmem_cache *hash_cache;
	uint8_t name[20];
	int key_offset;
	int node_offset;
	int cmp_len;
	bool (*cmp_key)(const void *a, const void *b, int len);
	size_t base_size;
};

struct hashtbl_bkt {
	spinlock_t lock;
	struct hlist_head head;
};

struct HashTableNode {
	struct hlist_node link;
	uint32_t hash;
};

extern uint64_t g_hashtbl_generic_lock;
extern struct list_head g_hashtbl_generic;

typedef int (*hashtbl_for_each_generic_cb)(struct HashTbl *tblp,
					   struct HashTableNode *datap,
					   void *priv);

struct HashTbl *hashtbl_init_generic(uint64_t numberOfBuckets,
				     uint64_t datasize, uint64_t sizehint,
				     const char *hashtble_name, int key_len,
				     int key_offset, int node_offset);
void *hashtbl_alloc_generic(struct HashTbl *tblp, int alloc_type);
int hashtbl_add_generic(struct HashTbl *tblp, void *datap);
void *hashtbl_del_by_key_generic(struct HashTbl *tblp, void *key);
void hashtbl_del_generic(struct HashTbl *tblp, void *datap);
void *hashtbl_get_generic(struct HashTbl *tblp, void *key);
void hashtbl_free_generic(struct HashTbl *tblp, void *datap);
void hashtbl_shutdown_generic(struct HashTbl *tblp);
void hashtbl_clear_generic(struct HashTbl *tblp);
void hashtbl_for_each_generic(struct HashTbl *tblp,
			      hashtbl_for_each_generic_cb callback, void *priv);
int hashtbl_show_proc_cache(struct seq_file *m, void *v);
size_t hashtbl_get_memory(void);
void hash_table_test(void);

// Use these when you want to more safely
// access entry data.
bool hashtbl_getlocked_bucket(struct HashTbl *hashTblp, void *key, void **datap,
			      struct hashtbl_bkt **bkt, unsigned long *flags);
void hashtbl_unlock_bucket(struct hashtbl_bkt *bkt, unsigned long flags);
int hashtbl_add_safe_generic(struct HashTbl *hashTblp, void *datap);
