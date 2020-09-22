/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_HASH)
#include "hash-table-generic.h"
#include "priv.h"

static inline void *get_datap(const struct HashTbl *hashTblp,
			      const struct HashTableNode *node)
{
	return (void *)(node - hashTblp->node_offset);
}

static inline struct HashTableNode *get_nodep(const struct HashTbl *hashTblp,
					      const void *data)
{
	return (struct HashTableNode *)(data + hashTblp->node_offset);
}

static inline void *get_key_ptr(struct HashTbl *hashTblp, void *datap)
{
	return (void *)datap + hashTblp->key_offset;
}

static inline unsigned long lock_bucket(struct hashtbl_bkt *bkt)
{
	unsigned long flags;
	spin_lock_irqsave(&bkt->lock, flags);
	return flags;
}

static inline void unlock_bucket(struct hashtbl_bkt *bkt, unsigned long flags)
{
	spin_unlock_irqrestore(&bkt->lock, flags);
}

// TODO - Optimize 32bit aligned keys to use jhash2 when >= 16 bytes
static inline u32 hashtbl_hash_key(const struct HashTbl *hashTblp,
				   unsigned char *key)
{
	return jhash(key, hashTblp->key_len, hashTblp->secret);
}
static inline int hashtbl_bkt_index(const struct HashTbl *hashTblp, u32 hash)
{
	return hash & (hashTblp->numberOfBuckets - 1);
}

// Assumed to be locked
// If the key wasn't contained within the object itself
// we could more easily decouple from HashTbl struct.
static struct HashTableNode *__lookup_entry_safe(struct HashTbl *hashTblp,
						 struct hlist_head *head,
						 u32 hash, const void *key)
{
	struct HashTableNode *node;
	struct hlist_node *tmp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	struct hlist_node *_node;
	hlist_for_each_entry_safe (node, _node, tmp, head, link) {
#else
	hlist_for_each_entry_safe (node, tmp, head, link) {
#endif
		if (hash == node->hash &&
		    hashTblp->cmp_key(key,
				      get_key_ptr(hashTblp,
						  get_datap(hashTblp, node)),
				      hashTblp->cmp_len)) {
			return node;
		}
	}
	return NULL;
}

static bool cmp_key_u8(const void *a, const void *b, int key_len)
{
	return memcmp(a, b, key_len) == 0;
}
static bool cmp_key_u32(const void *a, const void *b, int indices)
{
	int i;
	const uint32_t *a32 = (const uint32_t *)a;
	const uint32_t *b32 = (const uint32_t *)b;

	for (i = 0; i < indices; i++, a32++, b32++) {
		if (*a32 != *b32) {
			return false;
		}
	}
	return true;
}

static int debug = 0;

uint64_t g_hashtbl_generic_lock = 0;
LIST_HEAD(g_hashtbl_generic);

#define HASHTBL_PRINT(fmt, ...)                            \
	if (debug) {                                       \
		PR_DEBUG("hash-tbl: " fmt, ##__VA_ARGS__); \
	}

static void __hashtbl_for_each_generic(struct HashTbl *,
				       hashtbl_for_each_generic_cb, void *);

struct HashTbl *hashtbl_init_generic(uint64_t numberOfBuckets,
				     uint64_t datasize, uint64_t sizehint,
				     const char *hashtble_name, int key_len,
				     int key_offset, int node_offset)
{
	int i;
	uint64_t cache_elem_size;
	size_t tableSize;
	struct HashTbl *hashTblp = NULL;
	struct hashtbl_bkt *tbl_storage_p = NULL;

	if (!is_power_of_2(numberOfBuckets)) {
		numberOfBuckets = roundup_pow_of_two(numberOfBuckets);
	}
	printk(KERN_INFO "%s: %s bkts:%llu bits:%u", __func__, hashtble_name,
	       numberOfBuckets, ilog2(numberOfBuckets));

	hashTblp = kzalloc(sizeof(*hashTblp), GFP_KERNEL);
	if (!hashTblp) {
		return NULL;
	}

	tableSize = (numberOfBuckets * sizeof(struct hashtbl_bkt));

	tbl_storage_p = vmalloc(tableSize);

	if (!tbl_storage_p) {
		kfree(hashTblp);
		HASHTBL_PRINT("Failed to allocate %luB at %s:%d.", tableSize,
			      __FUNCTION__, __LINE__);
		return NULL;
	}

	// With kzalloc we get zeroing for free, with vmalloc we need to do it
	// ourself
	memset(tbl_storage_p, 0, tableSize);

	if (sizehint > datasize) {
		cache_elem_size = sizehint;
	} else {
		cache_elem_size = datasize;
	}

	HASHTBL_PRINT("Cache=%s elemsize=%llu hint=%llu\n", hashtble_name,
		      cache_elem_size, sizehint);

	hashTblp->tablePtr = tbl_storage_p;
	hashTblp->numberOfBuckets = numberOfBuckets;
	hashTblp->key_len = key_len;
	hashTblp->key_offset = key_offset;
	hashTblp->node_offset = node_offset;
	hashTblp->hash_cache = NULL;
	hashTblp->base_size = tableSize + sizeof(*hashTblp);
	strncpy((char *)hashTblp->name, hashtble_name,
		sizeof(hashTblp->name) - 1);
	if (!debug) {
		// Make hash more random
		get_random_bytes(&hashTblp->secret, sizeof(hashTblp->secret));
	}
	// Use 32 bit aligned key comparison when possible.
	hashTblp->cmp_key = cmp_key_u8;
	hashTblp->cmp_len = key_len;
	if ((hashTblp->cmp_len % sizeof(uint32_t)) == 0) {
		hashTblp->cmp_len = hashTblp->cmp_len / sizeof(uint32_t);
		hashTblp->cmp_key = cmp_key_u32;
		PR_DEBUG("%s: %s using cmp_key_u32: %d %d\n", __func__,
			 hashTblp->name, hashTblp->key_len, hashTblp->cmp_len);
	}

	if (cache_elem_size) {
		hashTblp->hash_cache = kmem_cache_create(
			hashtble_name, cache_elem_size, 0, 0, NULL);
		if (!hashTblp->hash_cache) {
			vfree(hashTblp->tablePtr);
			hashTblp->tablePtr = NULL;
			kfree(hashTblp);
			hashTblp = NULL;
			return NULL;
		}
	}

	// Init per bucket spinlocks
	for (i = 0; i < hashTblp->numberOfBuckets; i++) {
		spin_lock_init(&hashTblp->tablePtr[i].lock);
		INIT_HLIST_HEAD(&hashTblp->tablePtr[i].head);
	}

	if (!g_hashtbl_generic_lock) {
		// Init the spinlock for the first time
		cb_initspinlock(&g_hashtbl_generic_lock);
	}

	cb_spinlock(&g_hashtbl_generic_lock);
	list_add(&(hashTblp->genTables), &g_hashtbl_generic);
	cb_spinunlock(&g_hashtbl_generic_lock);

	HASHTBL_PRINT("Size=%lu NumberOfBuckets=%llu\n", tableSize,
		      numberOfBuckets);
	HASHTBL_PRINT("ADDR=%p TADDR=%p OFFSET=%lu\n", hashTblp,
		      hashTblp->tablePtr, sizeof(struct HashTbl));
	return hashTblp;
}

static int _hashtbl_delete_callback(struct HashTbl *hashTblp,
				    struct HashTableNode *nodep, void *priv)
{
	return ACTION_DELETE;
}

void hashtbl_shutdown_generic(struct HashTbl *hashTblp)
{
	atomic64_set(&(hashTblp->tableShutdown), 1);

	cb_spinlock(&g_hashtbl_generic_lock);
	list_del(&(hashTblp->genTables));
	cb_spinunlock(&g_hashtbl_generic_lock);

	// Ensures we are last to iterate through entries
	__hashtbl_for_each_generic(hashTblp, _hashtbl_delete_callback, NULL);

	HASHTBL_PRINT("hash shutdown inst=%ld alloc=%ld\n",
		      atomic64_read(&(hashTblp->tableInstance)),
		      atomic64_read(&(hashTblp->tableAllocs)));

	if (hashTblp->tablePtr) {
		vfree(hashTblp->tablePtr);
		hashTblp->tablePtr = NULL;
	}

	if (hashTblp->hash_cache) {
		kmem_cache_destroy(hashTblp->hash_cache);
		hashTblp->hash_cache = NULL;
	}
	kfree(hashTblp);
	hashTblp = NULL;
}

void hashtbl_clear_generic(struct HashTbl *hashTblp)
{
	hashtbl_for_each_generic(hashTblp, _hashtbl_delete_callback, NULL);
}

void hashtbl_for_each_generic(struct HashTbl *hashTblp,
			      hashtbl_for_each_generic_cb callback, void *priv)
{
	if (!hashTblp) {
		return;
	}

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		return;
	}

	__hashtbl_for_each_generic(hashTblp, callback, priv);
}

static void __hashtbl_for_each_generic(struct HashTbl *hashTblp,
				       hashtbl_for_each_generic_cb callback,
				       void *priv)
{
	int i;
	uint64_t numberOfBuckets;
	struct hashtbl_bkt *hashtbl_tbl = NULL;
	unsigned long flags;

	if (!hashTblp)
		return;

	hashtbl_tbl = hashTblp->tablePtr;
	numberOfBuckets = hashTblp->numberOfBuckets;

	// May need to walk the lists too
	for (i = 0; i < numberOfBuckets; ++i) {
		struct hashtbl_bkt *bucketp = &hashtbl_tbl[i];
		struct HashTableNode *nodep = NULL;
		struct hlist_node *tmp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
		struct hlist_node *_nodep;
#endif

		flags = lock_bucket(bucketp);
		if (!hlist_empty(&bucketp->head)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
			hlist_for_each_entry_safe (nodep, tmp, &bucketp->head,
						   link)
#else
			hlist_for_each_entry_safe (nodep, _nodep, tmp,
						   &bucketp->head, link)
#endif
			{

				switch ((*callback)(hashTblp,
						    get_datap(hashTblp, nodep),
						    priv)) {
				case ACTION_DELETE:
					hlist_del_init(&nodep->link);
					if (hashTblp->hash_cache) {
						kmem_cache_free(
							hashTblp->hash_cache,
							get_datap(hashTblp,
								  nodep));
						atomic64_dec(&(
							hashTblp->tableAllocs));
					}
					atomic64_dec(
						&(hashTblp->tableInstance));
					break;
				case ACTION_STOP:
					unlock_bucket(bucketp, flags);
					return;
				case ACTION_CONTINUE:
				default:
					break;
				}
			}
		}
		unlock_bucket(bucketp, flags);
	}
}

// Does not handle existing entry or handle racing
int hashtbl_add_generic(struct HashTbl *hashTblp, void *datap)
{
	u32 hash;
	int bucket_indx;
	struct hashtbl_bkt *bucketp;
	unsigned long flags;
	int ret = 0;
	struct HashTableNode *node;

	if (!hashTblp || !datap) {
		return -EINVAL;
	}

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		return -1;
	}

	hash = hashtbl_hash_key(hashTblp, get_key_ptr(hashTblp, datap));
	node = get_nodep(hashTblp, datap);
	node->hash = hash;

	bucket_indx = hashtbl_bkt_index(hashTblp, hash);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	flags = lock_bucket(bucketp);
	hlist_add_head(&node->link, &bucketp->head);
	atomic64_inc(&(hashTblp->tableInstance));
	unlock_bucket(bucketp, flags);

	return ret;
}

void *hashtbl_get_generic(struct HashTbl *hashTblp, void *key)
{
	u32 hash;
	int bucket_indx;
	struct hashtbl_bkt *bucketp;
	struct HashTableNode *nodep = NULL;
	unsigned long flags;
	void *datap = NULL;

	if (!hashTblp || !key) {
		goto ng_exit;
	}

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		goto ng_exit;
	}

	hash = hashtbl_hash_key(hashTblp, key);
	bucket_indx = hashtbl_bkt_index(hashTblp, hash);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	flags = lock_bucket(bucketp);

	nodep = __lookup_entry_safe(hashTblp, &bucketp->head, hash, key);
	if (nodep) {
		datap = get_datap(hashTblp, nodep);
	}
	unlock_bucket(bucketp, flags);

ng_exit:
	return datap;
}

// Assumes entry exists once
void *hashtbl_del_by_key_generic(struct HashTbl *hashTblp, void *key)
{
	u32 hash;
	int bucket_indx;
	struct hashtbl_bkt *bucketp;
	struct HashTableNode *nodep;
	unsigned long flags;
	void *datap = NULL;

	if (!hashTblp || !key) {
		goto ndbk_exit;
	}

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		goto ndbk_exit;
	}

	hash = hashtbl_hash_key(hashTblp, key);
	bucket_indx = hashtbl_bkt_index(hashTblp, hash);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	flags = lock_bucket(bucketp);
	nodep = __lookup_entry_safe(hashTblp, &bucketp->head, hash, key);
	if (nodep && likely((&nodep->link)->pprev != NULL)) {
		datap = get_datap(hashTblp, nodep);
		hlist_del_init(&nodep->link);
		if (atomic64_read(&(hashTblp->tableInstance)) == 0) {
			HASHTBL_PRINT("hashtbl_del: underflow!!\n");
		} else {
			atomic64_dec(&(hashTblp->tableInstance));
		}
	}
	unlock_bucket(bucketp, flags);

ndbk_exit:
	return datap;
}

// Insert only if it doesn't exist yet. Prevent's duplicates
// and allows us to know when there is racing.
int hashtbl_add_safe_generic(struct HashTbl *hashTblp, void *datap)
{
	u32 hash;
	int bucket_indx;
	struct hashtbl_bkt *bucketp;
	unsigned long flags;
	int ret = 0;
	struct HashTableNode *node;
	struct HashTableNode *old_node;
	void *key;

	if (!hashTblp || !datap) {
		return -EINVAL;
	}

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		return -1;
	}

	key = get_key_ptr(hashTblp, datap);
	hash = hashtbl_hash_key(hashTblp, key);
	node = get_nodep(hashTblp, datap);
	node->hash = hash;

	bucket_indx = hashtbl_bkt_index(hashTblp, hash);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	flags = lock_bucket(bucketp);
	old_node = __lookup_entry_safe(hashTblp, &bucketp->head, hash, key);

	if (old_node) {
		ret = -EEXIST;
	} else {
		hlist_add_head(&node->link, &bucketp->head);
		atomic64_inc(&(hashTblp->tableInstance));
	}
	unlock_bucket(bucketp, flags);

	return ret;
}

// On success must be paired with a hashtbl_unlock_bucket
bool hashtbl_getlocked_bucket(struct HashTbl *hashTblp, void *key, void **datap,
			      struct hashtbl_bkt **bkt, unsigned long *flags)
{
	u32 hash;
	int bucket_indx;
	struct hashtbl_bkt *bucketp;
	struct HashTableNode *nodep = NULL;
	unsigned long local_flags;

	if (!hashTblp || !key || !datap || !bkt || !flags) {
		return false;
	}
	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		return false;
	}

	hash = hashtbl_hash_key(hashTblp, key);
	bucket_indx = hashtbl_bkt_index(hashTblp, hash);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	local_flags = lock_bucket(bucketp);

	nodep = __lookup_entry_safe(hashTblp, &bucketp->head, hash, key);
	if (!nodep) {
		unlock_bucket(bucketp, local_flags);
		return false;
	}

	*datap = get_datap(hashTblp, nodep);
	*bkt = bucketp;
	*flags = local_flags;
	return true;
}
void hashtbl_unlock_bucket(struct hashtbl_bkt *bkt, unsigned long flags)
{
	if (!bkt) {
		return;
	}
	unlock_bucket(bkt, flags);
}

// Assumes key has not been modified
void hashtbl_del_generic(struct HashTbl *hashTblp, void *datap)
{
	int bucket_indx;
	struct HashTableNode *nodep;
	struct hashtbl_bkt *bucketp;
	unsigned long flags;

	if (!datap || !hashTblp) {
		return;
	}
	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		return;
	}

	nodep = get_nodep(hashTblp, datap);
	bucket_indx = hashtbl_bkt_index(hashTblp, nodep->hash);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	flags = lock_bucket(bucketp);
	if (likely((&nodep->link)->pprev != NULL)) {
		hlist_del_init(&nodep->link);
		if (atomic64_read(&(hashTblp->tableInstance)) == 0) {
			HASHTBL_PRINT("hashtbl_del: underflow!!\n");
		} else {
			atomic64_dec(&(hashTblp->tableInstance));
		}
	}
	unlock_bucket(bucketp, flags);
}

void *hashtbl_alloc_generic(struct HashTbl *hashTblp, int alloc_type)
{
	void *datap;

	if (!hashTblp) {
		return NULL;
	}

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		return NULL;
	}

	if (!hashTblp->hash_cache) {
		return NULL;
	}

	datap = cb_kmem_cache_alloc(hashTblp->hash_cache, alloc_type);
	if (!datap) {
		return NULL;
	}

	INIT_HLIST_NODE(&get_nodep(hashTblp, datap)->link);
	atomic64_inc(&(hashTblp->tableAllocs));
	return datap;
}

void hashtbl_free_generic(struct HashTbl *hashTblp, void *datap)
{
	if (!hashTblp || !datap) {
		return;
	}
	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		HASHTBL_PRINT("Shutting Down: %s Blocking: %s\n",
			      hashTblp->name, __func__);
		return;
	}
	if (hashTblp->hash_cache) {
		kmem_cache_free(hashTblp->hash_cache, datap);
		atomic64_dec(&(hashTblp->tableAllocs));
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define CACHE_SIZE(a) a->object_size
#else
#define CACHE_SIZE(a) a->buffer_size
#endif

// Loop over each hash table and calculate the memory used
size_t hashtbl_get_memory(void)
{
	struct HashTbl *hashTblp;
	size_t size = 0;

	cb_spinlock(&g_hashtbl_generic_lock);
	list_for_each_entry (hashTblp, &g_hashtbl_generic, genTables) {
		int cache_size = 0;
		if (hashTblp->hash_cache) {
			cache_size = CACHE_SIZE(hashTblp->hash_cache);
		}
		size += cache_size * atomic64_read(&(hashTblp->tableAllocs)) +
			hashTblp->base_size;
	}
	cb_spinunlock(&g_hashtbl_generic_lock);

	return size;
}

// Print Cache Data
int hashtbl_show_proc_cache(struct seq_file *m, void *v)
{
	struct HashTbl *hashTblp;

	seq_printf(m, "%22s | %6s | %5s | %15s | %9s |\n", "Name", "Alloc",
		   "Used", "Cache Name", "Obj. Size");

	cb_spinlock(&g_hashtbl_generic_lock);
	list_for_each_entry (hashTblp, &g_hashtbl_generic, genTables) {
		const char *cache_name = "";
		int cache_size = 0;
		if (hashTblp->hash_cache) {
			cache_name = hashTblp->hash_cache->name;
			cache_size = CACHE_SIZE(hashTblp->hash_cache);
		}
		seq_printf(m, "%22s | %6ld | %5ld | %15s | %9d |\n",
			   hashTblp->name,
			   atomic64_read(&(hashTblp->tableAllocs)),
			   atomic64_read(&(hashTblp->tableInstance)),
			   cache_name, cache_size);
	}
	cb_spinunlock(&g_hashtbl_generic_lock);

	seq_printf(m, "%22s | %6ld | %5s | %15s | %9d |\n", "cb_event_cache",
		   atomic64_read(&(cb_event_data.eventAllocs)), "-",
		   cb_event_data.cb_event_cache->name,
		   CACHE_SIZE(cb_event_data.cb_event_cache));
	return 0;
}

struct table_key {
	char a[16];
};

struct table_value {
	char a[16];
};

struct entry {
	struct HashTableNode link;
	struct table_key key;
	struct table_value value;
};

void hash_table_test(void)
{
	struct HashTbl *table = hashtbl_init_generic(
		1024, sizeof(struct entry), sizeof(struct entry),
		"hash_table_testing", sizeof(struct table_key),
		offsetof(struct entry, key), offsetof(struct entry, link));
	int size = 102400;
	int i, result;
	struct table_key *keys = (struct table_key *)kmalloc(
		sizeof(struct table_key) * size, GFP_KERNEL);
	struct table_value *values = (struct table_value *)kmalloc(
		sizeof(struct table_key) * size, GFP_KERNEL);
	struct entry *entry_ptr;
	// Test hashtbl_alloc and hashtbl_add
	for (i = 0; i < size; i++) {
		get_random_bytes(&keys[i], sizeof(struct table_key));
		get_random_bytes(&values[i], sizeof(struct table_value));
		entry_ptr = (struct entry *)hashtbl_alloc_generic(table,
								  GFP_KERNEL);
		if (entry_ptr == NULL) {
			PRINTK(KERN_WARNING, "Failed to alloc %d", i);
			goto test_exit;
		}
		memcpy(&entry_ptr->key, &keys[i], sizeof(struct table_key));
		memcpy(&entry_ptr->value, &values[i],
		       sizeof(struct table_value));
		result = hashtbl_add_generic(table, entry_ptr);
		if (result != 0) {
			hashtbl_free_generic(table, entry_ptr);
			PRINTK(KERN_WARNING, "Add fails %d", i);
			goto test_exit;
		}
	}
	// Add repeative key
	for (i = 0; i < size; i++) {
		entry_ptr = (struct entry *)hashtbl_alloc_generic(table,
								  GFP_KERNEL);
		memcpy(&entry_ptr->key, &keys[i], sizeof(struct table_key));
		memcpy(&entry_ptr->value, &values[i],
		       sizeof(struct table_value));
		result = hashtbl_add_generic(table, entry_ptr);

		if (result == 0) {
			PRINTK(KERN_WARNING, "Fail to detect repeative key %d",
			       i);
			goto test_exit;
		} else {
			hashtbl_free_generic(table, entry_ptr);
		}
	}
	// Test hashtbl_get
	for (i = 0; i < size; i++) {
		entry_ptr = hashtbl_get_generic(table, &keys[i]);
		if (memcmp(&entry_ptr->value, &values[i],
			   sizeof(struct table_key)) != 0) {
			PRINTK(KERN_WARNING, "Get fails %d", i);
			goto test_exit;
		}
	}

	// Test hastbl_del and hashtbl_free
	for (i = 0; i < size; i++) {
		entry_ptr = hashtbl_del_by_key_generic(table, &keys[i]);
		if (entry_ptr == NULL) {
			PRINTK(KERN_WARNING,
			       "Fail to find the element to be deleted");
			goto test_exit;
		}

		hashtbl_free_generic(table, entry_ptr);

		entry_ptr = hashtbl_get_generic(table, &keys[i]);
		if (entry_ptr != NULL) {
			PRINTK(KERN_WARNING, "Delete fails %d", i);
			goto test_exit;
		}
	}

	PRINTK(KERN_WARNING, "Hash table tests all passed.");
test_exit:
	kfree(keys);
	kfree(values);
	hashtbl_shutdown_generic(table);
}
