/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_HASH)
#include "hash-table-generic.h"
#include "priv.h"

#define get_datap(hashTblp, ptr) ((void *)((ptr) - (hashTblp)->node_offset))
#define get_nodep(hashTblp, ptr) \
	((struct HashTableNode *)((ptr) + (hashTblp)->node_offset))

static int debug = 0;

uint64_t g_hashtbl_generic_lock = 0;
LIST_HEAD(g_hashtbl_generic);

#define HASHTBL_PRINT(fmt, ...)                            \
	if (debug) {                                       \
		PR_DEBUG("hash-tbl: " fmt, ##__VA_ARGS__); \
	}

static void hashtbl_del_generic_lockheld(struct HashTbl *hashTblp, void *datap);
static int  hashtbl_add_generic_lockheld(struct HashTbl *hashTblp, void *datap);

char *key_in_hex(unsigned char *key, int key_len)
{
	int   i;
	char *str = (char *)kmalloc(key_len * 3, GFP_KERNEL);
	for (i = 0; i < key_len; i++) {
		sprintf(str + i * 3, "%02x ", key[i]);
	}
	str[key_len * 3 - 1] = '\0';
	return str;
}

inline void *get_key_ptr(struct HashTbl *hashTblp, void *datap)
{
	return (void *)datap + hashTblp->key_offset;
}

struct HashTbl *hashtbl_init_generic(uint64_t numberOfBuckets,
				     uint64_t datasize, uint64_t sizehint,
				     const char *hashtble_name, int key_len,
				     int key_offset, int node_offset)
{
	struct HashTbl *hashTblp = NULL;
	int tableSize = ((numberOfBuckets * sizeof(struct hlist_head)) +
			 sizeof(struct HashTbl));
	unsigned char *tbl_storage_p = NULL;
	uint64_t       cache_elem_size;

	// Since we're not in an atomic context (see GFP_KERNEL flag above) this
	// is an acceptable alternative to kmalloc however, it should be noted
	// that this is a little less efficient. The reason for this is
	// fragmentation that can occur on systems. We noticed this happening in
	// the field, and if highly fragmented, our driver will fail to load
	// with a normal kmalloc
	tbl_storage_p = vmalloc(tableSize);

	if (tbl_storage_p == NULL) {
		HASHTBL_PRINT("Failed to allocate %lluB at %s:%d.",
			      (numberOfBuckets * sizeof(struct hlist_head)) +
				      sizeof(struct HashTbl),
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

	hashTblp = (struct HashTbl *)tbl_storage_p;
	hashTblp->tablePtr =
		(struct hlist_head *)(tbl_storage_p + sizeof(struct HashTbl));
	hashTblp->numberOfBuckets = numberOfBuckets;
	cb_initspinlock(&(hashTblp->tableSpinlock));
	hashTblp->key_len     = key_len;
	hashTblp->key_offset  = key_offset;
	hashTblp->node_offset = node_offset;
	hashTblp->hash_cache  = NULL;
	hashTblp->base_size   = tableSize + sizeof(struct HashTbl);
	strncpy((char *)hashTblp->name, hashtble_name, sizeof(hashTblp->name));

	if (cache_elem_size) {
		hashTblp->hash_cache =
			kmem_cache_create(hashtble_name, cache_elem_size, 0,
					  SLAB_HWCACHE_ALIGN, NULL);
		if (!hashTblp->hash_cache) {
			vfree(hashTblp);
			return 0;
		}
	}

	if (!g_hashtbl_generic_lock) {
		// Init the spinlock for the first time
		cb_initspinlock(&g_hashtbl_generic_lock);
	}

	cb_spinlock(&g_hashtbl_generic_lock);
	list_add(&(hashTblp->genTables), &g_hashtbl_generic);
	cb_spinunlock(&g_hashtbl_generic_lock);

	HASHTBL_PRINT("Size=%d NumberOfBuckets=%llu\n", tableSize,
		      numberOfBuckets);
	HASHTBL_PRINT("ADDR=%p TADDR=%p OFFSET=%lu\n", hashTblp,
		      hashTblp->tablePtr, sizeof(struct HashTbl));
	return hashTblp;
}

void hashtbl_shutdown_generic(struct HashTbl *hashTblp)
{
	atomic64_set(&(hashTblp->tableShutdown), 1);

	cb_spinlock(&g_hashtbl_generic_lock);
	list_del(&(hashTblp->genTables));
	cb_spinunlock(&g_hashtbl_generic_lock);

	hashtbl_clear_generic(hashTblp);

	HASHTBL_PRINT("hash shutdown inst=%ld alloc=%ld\n",
		      atomic64_read(&(hashTblp->tableInstance)),
		      atomic64_read(&(hashTblp->tableAllocs)));

	cb_destroyspinlock(&(hashTblp->tableSpinlock));
	if (hashTblp->hash_cache) {
		kmem_cache_destroy(hashTblp->hash_cache);
	}
	vfree(hashTblp);
}

static int _hashtbl_delete_callback(struct HashTbl *	  hashTblp,
				    struct HashTableNode *nodep, void *priv)
{
	return ACTION_DELETE;
}

void hashtbl_clear_generic(struct HashTbl *hashTblp)
{
	HASHTBL_PRINT("ADDR=%p TADDR=%p OFFSET=%lu\n", hashTblp,
		      hashTblp->tablePtr, sizeof(struct HashTbl));

	hashtbl_for_each_generic(hashTblp, _hashtbl_delete_callback, NULL);
}

void hashtbl_for_each_generic(struct HashTbl *		  hashTblp,
			      hashtbl_for_each_generic_cb callback, void *priv)
{
	int		   i;
	uint64_t	   numberOfBuckets;
	struct hlist_head *hashtbl_tbl = NULL;

	if (!hashTblp) return;

	hashtbl_tbl	= hashTblp->tablePtr;
	numberOfBuckets = hashTblp->numberOfBuckets;

	cb_spinlock(&(hashTblp->tableSpinlock));

	// May need to walk the lists too
	for (i = 0; i < numberOfBuckets; ++i) {
		struct hlist_head *   bucketp = &hashtbl_tbl[i];
		struct HashTableNode *nodep   = 0;
		struct hlist_node *   tmp;
		if (!hlist_empty(bucketp)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
			hlist_for_each_entry_safe (nodep, tmp, bucketp, link)
#else
			struct hlist_node *_nodep;
			hlist_for_each_entry_safe (nodep, _nodep, tmp, bucketp,
						   link)
#endif
			{

				switch ((*callback)(hashTblp,
						    get_datap(hashTblp, nodep),
						    priv)) {
				case ACTION_DELETE:
					hlist_del(&nodep->link);
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
					goto Exit;
					break;
				case ACTION_CONTINUE:
				default:
					break;
				}
			}
		}
	}

Exit:
	cb_spinunlock(&(hashTblp->tableSpinlock));
}

static int hash_key(void *key, int len, int bucket_num)
{
	int	     i;
	char *	     data = (char *)key;
	unsigned int hash = 5381;
	for (i = 0; i < len; i++) {
		hash = ((hash << 5) + hash) + data[i]; // hash * 33 + data[i]
	}
	return hash % bucket_num;
}

static int hashtbl_add_generic_lockheld(struct HashTbl *hashTblp, void *datap)
{
	uint64_t	   bucket_indx;
	struct hlist_head *bucketp = NULL;
	char *		   key_str;
	if (NULL == datap) {
		return -1;
	}

	bucket_indx = hash_key(get_key_ptr(hashTblp, datap), hashTblp->key_len,
			       hashTblp->numberOfBuckets);
	bucketp	    = &(hashTblp->tablePtr[bucket_indx]);

	hlist_add_head(&get_nodep(hashTblp, datap)->link, bucketp);
	if (debug) {
		key_str = key_in_hex(get_key_ptr(hashTblp, datap),
				     hashTblp->key_len);
		HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __FUNCTION__,
			      bucket_indx, key_str);
		kfree(key_str);
	}

	atomic64_inc(&(hashTblp->tableInstance));
	return 0;
}

int hashtbl_add_generic(struct HashTbl *hashTblp, void *datap)
{
	int ret = 0;
	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		return -1;
	}

	cb_spinlock(&(hashTblp->tableSpinlock));
	ret = hashtbl_add_generic_lockheld(hashTblp, datap);
	cb_spinunlock(&(hashTblp->tableSpinlock));

	return ret;
}

void *hashtbl_get_generic(struct HashTbl *hashTblp, void *key)
{
	uint64_t	   bucket_indx;
	struct hlist_head *bucketp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	struct hlist_node *_nodep = NULL;
#endif
	struct HashTableNode *nodep = NULL;
	char *		      key_str;

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		goto ng_exit;
	}

	bucket_indx =
		hash_key(key, hashTblp->key_len, hashTblp->numberOfBuckets);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	if (debug) {
		key_str = key_in_hex(key, hashTblp->key_len);
		HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __FUNCTION__,
			      bucket_indx, key_str);
		kfree(key_str);
	}

	cb_spinlock(&(hashTblp->tableSpinlock));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	hlist_for_each_entry (nodep, bucketp, link)
#else
	hlist_for_each_entry (nodep, _nodep, bucketp, link)
#endif
	{
		if (memcmp(key,
			   get_key_ptr(hashTblp, get_datap(hashTblp, nodep)),
			   hashTblp->key_len) == 0) {
			cb_spinunlock(&(hashTblp->tableSpinlock));
			return get_datap(hashTblp, nodep);
		}
	}
	cb_spinunlock(&(hashTblp->tableSpinlock));

ng_exit:
	return NULL;
}

static void hashtbl_del_generic_lockheld(struct HashTbl *hashTblp, void *datap)
{
	struct HashTableNode *nodep = get_nodep(hashTblp, datap);

	// We saw some problems with this pointer being NULL.  I want to check
	// it just in case.
	if ((&nodep->link)->pprev != NULL) {
		hlist_del(&nodep->link);

		if (atomic64_read(&(hashTblp->tableInstance)) == 0) {
			HASHTBL_PRINT("hashtbl_del: underflow!!\n");
		} else {
			atomic64_dec(&(hashTblp->tableInstance));
		}
	} else {
		PRINTK(KERN_WARNING,
		       "Attempt to delete a NULL object from the hash table");
	}
}

void *hashtbl_del_by_key_generic(struct HashTbl *hashTblp, void *key)
{
	uint64_t	   bucket_indx;
	struct hlist_head *bucketp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	struct hlist_node *_nodep;
#endif
	struct HashTableNode *nodep;
	struct hlist_node *   tmp;
	char *		      key_str;

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		goto ndbk_exit;
	}

	bucket_indx =
		hash_key(key, hashTblp->key_len, hashTblp->numberOfBuckets);
	bucketp = &(hashTblp->tablePtr[bucket_indx]);

	if (debug) {
		key_str = key_in_hex(key, hashTblp->key_len);
		HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __FUNCTION__,
			      bucket_indx, key_str);
		kfree(key_str);
	}

	cb_spinlock(&(hashTblp->tableSpinlock));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	hlist_for_each_entry_safe (nodep, tmp, bucketp, link)
#else
	hlist_for_each_entry_safe (nodep, _nodep, tmp, bucketp, link)
#endif
	{
		void *datap = get_datap(hashTblp, nodep);
		if (memcmp(key, get_key_ptr(hashTblp, datap),
			   hashTblp->key_len) == 0) {
			hashtbl_del_generic_lockheld(hashTblp, datap);
			cb_spinunlock(&(hashTblp->tableSpinlock));
			return datap;
		}
	}
	cb_spinunlock(&(hashTblp->tableSpinlock));

ndbk_exit:
	return NULL;
}

void hashtbl_del_generic(struct HashTbl *hashTblp, void *datap)
{
	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
		return;
	}

	cb_spinlock(&(hashTblp->tableSpinlock));
	hashtbl_del_generic_lockheld(hashTblp, datap);
	cb_spinunlock(&(hashTblp->tableSpinlock));
}

void *hashtbl_alloc_generic(struct HashTbl *hashTblp, int alloc_type)
{
	void *datap;

	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
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
	if (atomic64_read(&(hashTblp->tableShutdown)) == 1) {
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
	size_t		size = 0;

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
		int	    cache_size = 0;
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
	struct hlist_node  link;
	struct table_key   key;
	struct table_value value;
};

void hash_table_test(void)
{
	struct HashTbl *table = hashtbl_init_generic(
		1024, sizeof(struct entry), sizeof(struct entry),
		"hash_table_testing", sizeof(struct table_key),
		offsetof(struct entry, key), offsetof(struct entry, link));
	int		  size = 102400;
	int		  i, result;
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
