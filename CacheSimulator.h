#ifndef CACHE_SIMULATOR_H_
#define CACHE_SIMULATOR_H_

#define DEBUG_CACHE_SIMULATOR

#define INVALID_BLOCK (~(0UL))

#define INVALID_SUB_BLOCK_DIS 65

#define MEM_READ 1
#define MEM_WRITE 0

#define MAX_NUM_THREAD 256

#define MEM_TRACE_BUF_THREAD

/// use binary file read/write operations to compress the trace file size 
#define TRACE_BINARY_FILE

#ifdef TRACE_BINARY_FILE

#define NON_MEM_BITS 9
#define MEM_ADDR_BITS 48
#define RW_BITS 1
#define SUB_BLOCK_BITS 4
#define CACHE_ACCESS_TYPE_BITS 2


#define CAT_ENTRY_BITS 0
#define SB_ENTRY_BITS 2       //(CAT_ENTRY_BITS + CACHE_ACCESS_TYPE_BITS)
#define RW_ENTRY_BITS 6       //(SB_ENTRY_BITS + SUB_BLOCK_BITS)
#define ADDR_ENTRY_BITS 7     //(RW_ENTRY_BITS + RW_BITS)
#define NONMEM_ENTRY_BITS 55    //(ADDR_ENTRY_BITS + MEM_ADDR_BITS)

unsigned long make_trace_binary(struct mem_trace_granularity *p_mem_trace);

#endif


/* memory request cache hit type */
enum CacheAccessType
{
    L1_CACHE_HIT = 0,
    L2_CACHE_HIT,
    L3_CACHE_HIT,
    ALL_CACHE_MISS,
    CACHE_ACCESS_TYPE_COUNT
};


typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

/*!
 *  @brief Computes floor(log2(n))
 *  Works by finding position of MSB set.
 *  @returns -1 if n == 0.
 */
static inline uint32_t FloorLog2(uint32_t n)
{
    uint32_t p = 0;
    
    if (n == 0) return 0;

    if (n & 0xffff0000) { p += 16; n >>= 16; }
    if (n & 0x0000ff00) { p +=  8; n >>=  8; }
    if (n & 0x000000f0) { p +=  4; n >>=  4; }
    if (n & 0x0000000c) { p +=  2; n >>=  2; }
    if (n & 0x00000002) { p +=  1; }

    return p;
}


class CacheBlock
{
public:
	enum CacheBlockConfig{MAX_SUB_BLOCK=64};

	uint32_t m_block_size; //it is usual 64B
	uint64_t m_block_addr; //it is full addr, do not filter for it
	uint64_t m_block_tag;  //filter the inner-set addr and the set index
	uint32_t m_min_granularity; //set it to 8B or some others
	uint32_t m_sub_block_count;
	uint32_t m_block_in_upper_cache;

	uint32_t m_block_access_distribution[MAX_SUB_BLOCK];

	uint32_t m_accessed_sub_block_num;

	uint64_t m_mem_trace_buf_index;
	uint32_t m_mem_trace_buf_skipped;

	uint32_t m_dirty; //to mark if this block is written
public:
	class CacheBlock* m_next_lru;
	class CacheBlock* m_prev_lru;

	//Add this to quick find its parent block in the lower level cache, Inclusive
	class CacheBlock *m_parent_block_in_lower;

    int m_threadid;

public:
	CacheBlock(uint32_t block_size, uint32_t min_granularity);
	~CacheBlock();

	void Replaced(uint32_t block_addr);  //Note: this only for lru cache block
	
	void hit_access(uint32_t sub_block_index, uint32_t mem_rw);
	void print_cache_block();
	void reset_block_access_distribution();
	void get_data_from_evicted(CacheBlock *p_evicted_block);

	void push_data_into_upper_block(CacheBlock *p_upper_block);

	void output_cache_trace_wSubBlock();

	uint32_t get_sub_block_distribution();

	int is_invalid_cache(){return m_block_addr == INVALID_BLOCK;}
};

class CacheSet
{
protected:
	uint32_t m_way_count;  //the cache associaticity
	class CacheBlock *m_p_mru_block;
	class CacheBlock *m_p_lru_block;

	//uint32_t 

public:
	CacheSet(uint32_t way_count, uint32_t block_size, uint32_t min_granularity);
	~CacheSet();

	CacheBlock *find_block(uint64_t mem_tag); //if not in set, return NULL		
	void hit_access(CacheBlock **p_block, uint32_t sub_block_index);

	CacheBlock* evict_lru_block();
	void write_back_evicted_lru_block(CacheBlock *evicted_lru_block);
	void put_accessed_block_in_mru(CacheBlock *p_new_block);

	uint32_t load_new_block_in_LLC(uint64_t maddr, uint64_t mem_tag, int threadid);
	CacheBlock *get_mru_block(){return m_p_mru_block;}
	CacheBlock *get_lru_block(){return m_p_lru_block;}

	void print_cache_set();
};

class Caches
{
protected:
	enum Cache_Config{MAX_CACHE_LEVEL=8, MAX_SUB_BLOCK=64};

	//enum CacheBlockConfig{MAX_SUB_BLOCK=64};

	uint32_t m_level; //3 level cache
	uint64_t m_cache_capacity[MAX_CACHE_LEVEL]; //the capacity of each level cahce
	uint32_t m_cache_way_count[MAX_CACHE_LEVEL]; //the way of each level cache
	uint32_t m_block_size[MAX_CACHE_LEVEL];
	uint32_t m_min_granularity[MAX_CACHE_LEVEL];

	uint32_t m_cache_set_capacity[MAX_CACHE_LEVEL]; //the size of each set
	uint32_t m_cache_set_count[MAX_CACHE_LEVEL]; //the count of cache set at each level cache

	uint32_t m_block_low_bits[MAX_CACHE_LEVEL];  //the real low addr, 
	uint32_t m_sub_block_bits[MAX_CACHE_LEVEL];  //the sub block bits, as the min granularity
	uint32_t m_set_index_bits[MAX_CACHE_LEVEL];  //the cache block bits
	//uint32_t m_tag_bits[MAX_CACHE_LEVEL];

	uint32_t m_block_low_mask[MAX_CACHE_LEVEL];
	uint32_t m_sub_block_mask[MAX_CACHE_LEVEL];
	uint32_t m_set_index_mask[MAX_CACHE_LEVEL];
	//uint64_t m_tag_mask[MASK_CACHE_LEVEL];
	
	//some cache access statistics
	uint64_t m_mem_reads[MAX_CACHE_LEVEL];
	uint64_t m_mem_reads_hit[MAX_CACHE_LEVEL];
	uint64_t m_mem_reads_miss[MAX_CACHE_LEVEL];

	uint64_t m_mem_writes[MAX_CACHE_LEVEL];
	uint64_t m_mem_writes_hit[MAX_CACHE_LEVEL];
	uint64_t m_mem_writes_miss[MAX_CACHE_LEVEL];

	//
	uint32_t m_sub_block_count;
	uint64_t m_sub_block_distribution[MAX_SUB_BLOCK];

	int m_shared_LLC;  //whether the last level of cache is shared among cores, 1 for yes

	char *m_cache_config_fname;

	CacheSet **m_cache_sets[MAX_CACHE_LEVEL];

	void get_cache_addr_parts(uint64_t maddr, uint64_t *mem_tag, uint32_t *set_index, uint32_t *sub_block_index, uint32_t level);
	
	CacheSet* access_cache_at_level(uint64_t maddr, uint32_t level, uint32_t *hit_cache, uint64_t *mtag, uint32_t *sub_block_index);

	void cache_replaced(CacheSet *p_lower_set, CacheSet *p_upper_set, uint32_t lower_level, uint64_t upper_mtag, uint64_t maddr);

public:
	Caches(char *cache_config_fname, unsigned int numCores);
	~Caches();
	
	//void access_cache(uint64_t maddr, uint32_t mem_rw, int thdid);
    void access_cache(uint64_t maddr, uint32_t mem_rw, int thdid, CacheAccessType *cacheAccessType);

	void print_cache_config();
	void output_mem_reqs_statistics();
};

#endif
