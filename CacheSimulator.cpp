#include "CacheSimulator.h"
//#include "pin.H"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <cstdlib>
#include <cassert>
using namespace std;

#define CACHE_WRITE_BACK_SIM
#define RECORD_UPPER_INS

#define DEBUG_STATIC_RTN

//@@@@ not to write the mem trace into file, Need to remove it
////////////////////////////////////////////////////////////////////////////
//#define NOT_WRITE_TRACE_TO_FILE

/// use binary file read/write operations to compress the trace file size
//#define TRACE_BINARY_FILE


struct mem_trace_granularity
{
	unsigned long m_addr; //the memory address
	unsigned int m_rw;  // 1 represents read; 0 represents write
	unsigned int m_sb_count; //the number of sub-blocks accessed during
	unsigned int m_upper_ins_count; //count the non-mem instruction between two mem accesses
	
	unsigned int m_committed;

	unsigned int m_skipped;	

	CacheBlock *m_p_block_LLC;

	int m_threadid;	

    /*
     * The Cache Access Type for each memory request, here:
     * 0 -- L1 Cache Hit
     * 1 -- L2 Cache Hit
     * 2 -- L3 Cache Hit
     * 3 -- All Cache Miss
     */
    unsigned int m_cache_access_type;
};

#define max_mem_trace_gra_count (64UL<<20)


#ifndef MEM_TRACE_BUF_THREAD
unsigned long mem_trace_next_committing_index = max_mem_trace_gra_count; //0UL;
unsigned long mem_trace_next_ready_committed_index = 0UL;
unsigned long mem_trace_buf_next_index = 0UL;
struct mem_trace_granularity *p_mem_trace_buf = NULL;

unsigned int next_committing_index_committed = 1;
unsigned int committing_duration_num = 0;
#else
unsigned long mem_trace_next_committing_index_thread[MAX_NUM_THREAD];
unsigned long mem_trace_next_ready_committed_index_thread[MAX_NUM_THREAD];
unsigned long mem_trace_buf_next_index_thread[MAX_NUM_THREAD];
struct mem_trace_granularity *p_mem_trace_buf_thread[MAX_NUM_THREAD];

unsigned int next_committing_index_committed_thread[MAX_NUM_THREAD];
unsigned int committing_duration_num_thread[MAX_NUM_THREAD];
#endif

void add_mem_trace_to_buf(unsigned long maddr, unsigned int rw, int thdid, CacheAccessType *cacheAccessType);
void add_write_back_mem_trace_to_buf(unsigned long maddr, unsigned int sb_count, int thdid);
void commit_mem_trace_buf_to_file(int threadid);


FILE * trace;
Caches *myCaches;
//FILE *mtrace;
FILE *mtrace_gra[MAX_NUM_THREAD];


//INT32 numThreads = 0; 


#ifdef TRACE_BINARY_FILE

#define BINARY_TRACE_BUF_SIZE (1UL<<20)
unsigned long *btrace_buf[MAX_NUM_THREAD];
unsigned long btrace_buf_index[MAX_NUM_THREAD];


void init_btrace();
void fini_btrace();
void commit_binary_trace_to_file(int threadid, int full);
void add_btrace_to_buf(unsigned long btrace, int threadid);


void init_btrace()
{
    int i;

    /// No, Do not alloc binary trace buf here, this might waste lots of space.
    /*
    for(i = 0; i < MAX_NUM_THREAD; i++)
    {
        btrace_buf[i] = (unsigned long*)malloc(sizeof(unsigned long) * BINARY_TRACE_BUF_SIZE);
        if(!btrace_buf[i])
        {
            fprintf(stderr, "## Error: Failed to malloc space for binary trace buf\n");
            exit(-8);
        }
    }
    */

    for(i = 0; i < MAX_NUM_THREAD; i++)
    {
        btrace_buf_index[i] = 0;
    }
}

/*void fini_btrace()
{
    int i;

    /// First, write the leaved binary trace into file
    for(i = 0; i < numThreads; i++)
    {
        if(btrace_buf_index[i] > 0)
        {
            /// TODO: 
            commit_binary_trace_to_file(i, 0);  /// do not force full check
        }
    }

    /// Then, free the space of each binary buf
    for( i = 0; i < numThreads; i++)
    {
        free(btrace_buf[i]);
        btrace_buf[i] = NULL;
    }
}*/

void commit_binary_trace_to_file(int threadid, int full)
{
    if(full)
    {
        assert(btrace_buf_index[threadid] == BINARY_TRACE_BUF_SIZE);
    }
    
    /// write the binary trace from buf into corresponding file
    fwrite(btrace_buf[threadid], sizeof(unsigned long), btrace_buf_index[threadid], mtrace_gra[threadid]);

    /// reset the buf index into zero
    btrace_buf_index[threadid] = 0;
}

void add_btrace_to_buf(unsigned long btrace, int threadid)
{
    if(btrace_buf_index[threadid] == BINARY_TRACE_BUF_SIZE)
    {
        /// the binary trace buf is full, write it into file
        commit_binary_trace_to_file(threadid, 1); /// do check buf full
        assert(btrace_buf_index[threadid] == 0);
    }
    btrace_buf[threadid][btrace_buf_index[threadid]] = btrace;
    btrace_buf_index[threadid]++;

}


#endif



uint64_t evicted_LLC_count = 0;


unsigned int non_mem_ins_count[MAX_NUM_THREAD];// = 0;
unsigned long total_ins_count[MAX_NUM_THREAD];// = 0;
unsigned long total_non_mem_ins_count[MAX_NUM_THREAD];// = 0;
unsigned long total_mem_ins_count[MAX_NUM_THREAD];// = 0;

void init_instr_count()
{
    int i;
    for(i = 0; i < MAX_NUM_THREAD; i++)
    {
        non_mem_ins_count[i] = 0;
        total_ins_count[i] = 0;
        total_non_mem_ins_count[i] = 0;
        total_mem_ins_count[i] = 0;
    }
}


unsigned long mem_read_requests[MAX_NUM_THREAD];// = 0;
unsigned long mem_write_requests[MAX_NUM_THREAD];// = 0;

unsigned long mem_read_traces[MAX_NUM_THREAD];// = 0;
unsigned long mem_write_traces[MAX_NUM_THREAD];// = 0;

void init_memory_statistics()
{
    int i;
    for(i = 0; i < MAX_NUM_THREAD; i++)
    {
        mem_read_requests[i] = 0;
        mem_write_requests[i] = 0;

        mem_read_traces[i] = 0;
        mem_write_traces[i] = 0;
    }
}


unsigned long mem_trace_counts[64][64]; ///< threadid, granularity



CacheBlock::CacheBlock(uint32_t block_size, uint32_t min_granularity)
{
	int i;
    
    	m_block_size = block_size;
    	m_min_granularity = min_granularity;
    	m_block_addr = INVALID_BLOCK;
        
	m_next_lru = NULL;
	m_prev_lru = NULL;
	m_parent_block_in_lower = NULL;

	m_block_in_upper_cache = 0;

	for(i = 0; i < MAX_SUB_BLOCK; i++)
	{
		m_block_access_distribution[i] = 0;
	}
	m_accessed_sub_block_num = 0;	


	m_sub_block_count = m_block_size / m_min_granularity;

	m_mem_trace_buf_skipped = 0;

	m_dirty = 0;
}

CacheBlock::~CacheBlock()
{
    
}

void CacheBlock::reset_block_access_distribution()
{
	int i;
	for(i = 0; i < MAX_SUB_BLOCK; i++)
        {
                m_block_access_distribution[i] = 0;
        }
	m_accessed_sub_block_num = 0;
	
	m_dirty = 0;
}

void CacheBlock::hit_access(uint32_t sub_block_index, uint32_t mem_rw)
{
	assert(sub_block_index >= 0 && sub_block_index < m_sub_block_count);
	//if()
	m_block_access_distribution[sub_block_index]++;
	
	if(mem_rw == MEM_WRITE)
	{
		m_dirty = 1;
	}
}

void CacheBlock::get_data_from_evicted(CacheBlock *p_evicted_block)
{
	uint32_t i;
	
	//assert(m_block_addr == p_evicted_block->m_block_addr);
	assert(m_block_in_upper_cache == 1);

	//this block not in upper cache any more
	m_block_in_upper_cache = 0;
	p_evicted_block->m_parent_block_in_lower = NULL;

	//And, we just want to the access distribution info,
	for(i = 0; i < m_sub_block_count; i++)
        {
                m_block_access_distribution[i] = p_evicted_block->m_block_access_distribution[i];
        }
	
	m_dirty = p_evicted_block->m_dirty;

}

void CacheBlock::push_data_into_upper_block(CacheBlock *p_upper_block)
{
	uint32_t i;
       
        m_block_in_upper_cache = 1; //Yes, we put this block into upper cache

        //And, we just want to the access distribution info,
        for(i = 0; i < m_sub_block_count; i++)
        {
                p_upper_block->m_block_access_distribution[i] = m_block_access_distribution[i];
        }

	p_upper_block->m_parent_block_in_lower = this;

	p_upper_block->m_dirty = m_dirty;
}

void CacheBlock::print_cache_block()
{
	cout<<dec<<"size="<<m_block_size<<", min_granularity="<<m_min_granularity<<", block_addr=0x"<<hex<<m_block_addr<<dec<<endl;
}

uint32_t CacheBlock::get_sub_block_distribution()
{
	uint32_t i;
	uint32_t accessed_sub_block = 0;
	if(m_block_addr != INVALID_BLOCK)
	{
		for(i = 0; i < m_sub_block_count; i++)
		{
			if(m_block_access_distribution[i] != 0)
			{
				accessed_sub_block++;
			}
		}
		assert(accessed_sub_block <= m_sub_block_count);	
	}
	return accessed_sub_block;
}

void CacheBlock::output_cache_trace_wSubBlock()
{
	uint32_t i;
	m_accessed_sub_block_num = 0;
    
    if(m_block_addr != INVALID_BLOCK /*&& evicted_LLC_count % (8UL << 10) == 0*/)
    {      
	
        cout<<"#### Evicted from LLC: addr=0x"<<hex<<m_block_addr<<dec<<", sub_block=<";
	
        for(i = 0; i < m_sub_block_count; i++)
        {        
            cout<<m_block_access_distribution[i]<<",";
            if(m_block_access_distribution[i] != 0)
            {
                m_accessed_sub_block_num++;			
            }
        }
	    cout<<">, access_count="<<m_accessed_sub_block_num<<endl;
    }
}

CacheSet::CacheSet(uint32_t way_count, uint32_t block_size, uint32_t min_granularity):
	m_way_count(way_count)
{
	uint32_t i;

	CacheBlock *p_block = NULL;
	CacheBlock *p_next_block = NULL;

	p_block = new CacheBlock(block_size, min_granularity);
	m_p_mru_block = p_block;

	for(i = 1; i < way_count; i++)
	{
		p_next_block = new CacheBlock(block_size, min_granularity);
		p_block->m_next_lru = p_next_block;
		p_next_block->m_prev_lru = p_block;
		p_block = p_next_block;		
	}
	m_p_lru_block = p_next_block;

}

CacheSet::~CacheSet()
{
	//uint32_t i;
	CacheBlock *p_block;
	CacheBlock *p_next_block;
	
    	//cout<<"in ~CacheSet()"<<endl;


	p_block = m_p_mru_block;

	while(p_block)
	{
		p_next_block = p_block->m_next_lru;
		delete p_block;
		p_block = p_next_block;
	}
}

void CacheSet::hit_access(CacheBlock **pp_block, uint32_t sub_block_index)
{
    CacheBlock *p_block = *pp_block;
    assert(m_p_mru_block->m_prev_lru == NULL);
    assert(m_p_lru_block->m_next_lru == NULL);

	if(!p_block->m_prev_lru)
	{
		//it is the mru block, we do not need to move the block position
		assert(p_block->m_block_tag == m_p_mru_block->m_block_tag);
	}
	else
	{
		//get this block out of the link, and then put it in the mru position
		p_block->m_prev_lru->m_next_lru = p_block->m_next_lru;
		if(p_block->m_next_lru)
		{
			//this block is not the lru block
			p_block->m_next_lru->m_prev_lru = p_block->m_prev_lru;
		}
        	else
        	{
            		//this is the lru block
            		//Note: we need to update the lru pointer to its prev block, cause we move this block into mru
            		assert(p_block->m_block_tag == m_p_lru_block->m_block_tag);
            		m_p_lru_block = p_block->m_prev_lru;
        	}

		p_block->m_next_lru = m_p_mru_block;
		m_p_mru_block->m_prev_lru = p_block;

		p_block->m_prev_lru = NULL;  //now the p_block becomes the new mru block

		m_p_mru_block = p_block;
	}

	//p_block->hit_access(sub_block_index);
}

void CacheSet::print_cache_set()
{
	uint32_t i;

	cout<<"Set status: way_count="<<m_way_count<<endl;
	
	CacheBlock *p_block;
        CacheBlock *p_next_block;
	p_block = m_p_mru_block;
	i = 0;
	while(p_block)
	{
		p_next_block = p_block->m_next_lru;
		cout<<"Cache Block "<<i<<": ";
		p_block->print_cache_block();
		p_block = p_next_block;
		i++;
	}
	assert(i == m_way_count);
}

CacheBlock* CacheSet::find_block(uint64_t mem_tag)
{
	CacheBlock *p_block;

	p_block = m_p_mru_block;
	while(p_block)
	{
		if(mem_tag == p_block->m_block_tag)
		{
			//find the cache block
			return p_block;
		}
		p_block = p_block->m_next_lru;
	}
	return NULL;  //not find cache block in the set
}

CacheBlock* CacheSet::evict_lru_block()
{
	//Just evict the lru block, out of list
        //Add 06/12/2012: can not evict the lru block with it is in the upper cache
    
	CacheBlock *p_block = m_p_lru_block;
    	assert(p_block != NULL);
    	if(!p_block->m_block_in_upper_cache)
    	{
        	//Well, the lru block is not in the upper cache, just evict
        	//cout<<"## evicted lru block:"<<p_block->m_block_addr<<endl;
	    	assert(p_block != NULL && p_block->m_prev_lru != NULL);

	    	m_p_lru_block = p_block->m_prev_lru;
	    	m_p_lru_block->m_next_lru = NULL;
	    	p_block->m_prev_lru = NULL;
    	}
    	else
    	{
        	//we need to find the first block not in the upper cache
#ifdef DEBUG_CACHE_SIMULATOR
        	//cout<<"## In evict lru block, the lru block is in upper cache";
#endif
        	uint32_t block_num = 0;
        	while(p_block != NULL && p_block->m_block_in_upper_cache)
        	{
            		p_block = p_block->m_prev_lru;
            		block_num++;
            		//assert(p_block != NULL);
        	}
#ifdef DEBUG_CACHE_SIMULATOR
        	//cout<<":"<<block_num<<endl;
#endif
        	//Got the block, evict it
        	//Is it possible the mru block, no way
        	assert(p_block->m_block_tag != m_p_mru_block->m_block_tag);
        	p_block->m_prev_lru->m_next_lru = p_block->m_next_lru;
        	p_block->m_next_lru->m_prev_lru = p_block->m_prev_lru;
        
        	p_block->m_prev_lru = NULL;
        	p_block->m_next_lru = NULL;
    	}
	
	return p_block;
}

void CacheSet::put_accessed_block_in_mru(CacheBlock *p_new_block)
{
	p_new_block->m_next_lru = m_p_mru_block;
	m_p_mru_block->m_prev_lru = p_new_block;
	
	p_new_block->m_prev_lru = NULL;

	m_p_mru_block = p_new_block;
	
}

uint32_t CacheSet::load_new_block_in_LLC(uint64_t maddr, uint64_t mem_tag, int new_threadid)
{
#ifdef DEBUG_CACHE_SIMULATOR
    	//cout<<"## Evicted lru at level LLC"<<endl; 
#endif
	uint32_t accessed_sub_block = INVALID_SUB_BLOCK_DIS;
	CacheBlock *p_evicted_block = evict_lru_block();

	
    uint32_t write_back_mem_trace = 0;
#ifdef MEM_TRACE_BUF_THREAD
    int wb_threadid = -1;
#endif
    

	//To DO: print this evicted block as the output trace
    	evicted_LLC_count++;
	//update the num of accessed sub block
	if(!p_evicted_block->is_invalid_cache() && !p_evicted_block->m_mem_trace_buf_skipped) 
	{
		//if the evicted block had been skipped in the trace buf, do not write it to the buf.
		
		accessed_sub_block = p_evicted_block->get_sub_block_distribution();
	    
#ifdef MEM_TRACE_BUF_THREAD
        int threadid = p_evicted_block->m_threadid;
        unsigned long mem_trace_next_committing_index = mem_trace_next_committing_index_thread[threadid];
        //unsigned long mem_trace_next_ready_committed_index = mem_trace_next_ready_committed_index_thread[threadid];
        //unsigned long mem_trace_buf_next_index = mem_trace_buf_next_index_thread[threadid];
        struct mem_trace_granularity* p_mem_trace_buf = p_mem_trace_buf_thread[threadid];
                            
        unsigned int next_committing_index_committed = next_committing_index_committed_thread[threadid];
        unsigned int committing_duration_num = committing_duration_num_thread[threadid];
#endif

		assert(p_evicted_block->m_mem_trace_buf_index >= 0 && p_evicted_block->m_mem_trace_buf_index < max_mem_trace_gra_count);
        
        assert(!p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_skipped);

        if(p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_addr != p_evicted_block->m_block_addr)
        {
            fprintf(stderr, "## Error, tid=%d, addr=%lx, buf_addr=%lx, %lx--%lx\n",p_evicted_block->m_threadid, p_evicted_block->m_block_addr, p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_addr, p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index-1].m_addr, p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index+1].m_addr);
        }
		//assert(p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_addr == p_evicted_block->m_block_addr);
		
		p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_sb_count = accessed_sub_block;	
		p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_committed = 1;

		p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_skipped = 0;

		committing_duration_num++;
		if(p_evicted_block->m_mem_trace_buf_index == mem_trace_next_committing_index)
		{
			next_committing_index_committed = 1;
		}


#ifdef CACHE_WRITE_BACK_SIM
		if(p_evicted_block->m_dirty)
		{
			//the cache block is dirty, write back it into the memory
            assert(p_evicted_block->m_threadid == p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_threadid);
			add_write_back_mem_trace_to_buf(p_evicted_block->m_block_addr, accessed_sub_block, p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_threadid);
            wb_threadid = p_evicted_block->m_threadid;

#ifdef MEM_TRACE_BUF_THREAD

            if(new_threadid == p_evicted_block->m_threadid)
#endif
            {
			    write_back_mem_trace = 1;
                
            }
//#endif
			//wb_threadid = p_evicted_block->m_threadid;
		}
#endif
        
#ifdef MEM_TRACE_BUF_THREAD_ABORT
    if(mem_trace_next_committing_index != mem_trace_next_committing_index_thread[threadid]
            || mem_trace_next_ready_committed_index_thread[threadid] != mem_trace_next_ready_committed_index
            || mem_trace_buf_next_index_thread[threadid] != mem_trace_buf_next_index
            || next_committing_index_committed_thread[threadid] != next_committing_index_committed
            || committing_duration_num_thread[threadid] != committing_duration_num)
    {
        fprintf(stderr, "Failed to use reference for updating\n");
        exit(-8);
    }
#endif

#ifdef MEM_TRACE_BUF_THREAD_ABORT
             mem_trace_next_committing_index_thread[threadid] =  mem_trace_next_committing_index;
             mem_trace_next_ready_committed_index_thread[threadid] = mem_trace_next_ready_committed_index;
             mem_trace_buf_next_index_thread[threadid] = mem_trace_buf_next_index;
                            
             next_committing_index_committed_thread[threadid] = next_committing_index_committed;
             committing_duration_num_thread[threadid] = committing_duration_num;
#endif

	}

	//m_sub_block_distribution[p_evicted_block->get_sub_block_distribution()]++;
    	if(evicted_LLC_count % (1UL << 20) == 0)
    	{
        	p_evicted_block->output_cache_trace_wSubBlock();
    	}

	//construct this evicted as the new mru block
	p_evicted_block->m_block_addr = maddr;
	p_evicted_block->m_block_tag = mem_tag;
    p_evicted_block->m_threadid = new_threadid;
	p_evicted_block->reset_block_access_distribution();
    p_evicted_block->m_block_in_upper_cache = 0;
	p_evicted_block->m_mem_trace_buf_skipped = 0;

#ifndef MEM_TRACE_BUF_THREAD
	p_evicted_block->m_mem_trace_buf_index = (mem_trace_buf_next_index - write_back_mem_trace - 1) % max_mem_trace_gra_count;
	p_mem_trace_buf[p_evicted_block->m_mem_trace_buf_index].m_p_block_LLC = p_evicted_block;
#else
    p_evicted_block->m_mem_trace_buf_index = (mem_trace_buf_next_index_thread[new_threadid] - write_back_mem_trace - 1) % max_mem_trace_gra_count;
    p_mem_trace_buf_thread[new_threadid][p_evicted_block->m_mem_trace_buf_index].m_p_block_LLC = p_evicted_block;
    if(p_mem_trace_buf_thread[new_threadid][p_evicted_block->m_mem_trace_buf_index].m_addr != p_evicted_block->m_block_addr)
    {
        fprintf(stdout, "wb=%d, addr = %lx,--%lx, %lx, wb_threadid=%d, new_threadid=%d\n", write_back_mem_trace,p_evicted_block->m_block_addr, p_mem_trace_buf_thread[new_threadid][p_evicted_block->m_mem_trace_buf_index].m_addr, p_mem_trace_buf_thread[new_threadid][p_evicted_block->m_mem_trace_buf_index+1].m_addr, wb_threadid, new_threadid);
    }
    assert(p_mem_trace_buf_thread[new_threadid][p_evicted_block->m_mem_trace_buf_index].m_addr == p_evicted_block->m_block_addr);
#endif


	//ok then, put this new block in the mru location
	put_accessed_block_in_mru(p_evicted_block);
	
	return accessed_sub_block;

}

/*
void CacheSet::get_new_mru_block(CacheBlock *new_mru_block, CacheBlock *lower_block)
{
	new_mru_block->get_data_from_lower(lower_block);

	new_mru_block->m_next_lru = m_p_mru_block;
	m_p_mru_block->m_prev_lru = new_mru_block;
	m_p_mru_block = new_mru_block;
	m_p_mru_block->m_prev_lru = NULL;
}
*/

/*
void CacheSet::write_back_evicted_lru_block(CacheBlock *evicted_lru_block)
{
	CacheBlock *p_lower_block = find_block(evicted_lru_block->m_block_tag);
	assert(p_lower_block != NULL);
	p_lower_block->get_data_from_evicted(evicted_lru_block);
}
*/

Caches::Caches(char *cache_config_fname, unsigned int numCores)
{
	if(cache_config_fname == NULL)
	{
		uint32_t i;
		uint32_t j;
		//we use the default cache config of core i7
		m_level = 3;
		if(m_level > MAX_CACHE_LEVEL)
		{
			cerr<<"Invalid cache level:"<<m_level<<", max cache level is "<<MAX_CACHE_LEVEL<<endl;
			exit(-8);	
		}		

        fprintf(stdout, "Get num of cores : %u\n", numCores);


		m_cache_capacity[0] = (32UL << 10) * numCores;  //L1 cache 32KB
		m_cache_capacity[1] = (256UL << 10) * numCores; //L2 cahce 256KB
		m_cache_capacity[2] = (1UL << 20) * numCores;   //L3 cache 8MB, shared
		if(numCores < 4)
		{
			m_cache_capacity[2] = (4UL << 20);  //we use the 4MB for less cores
		}

		m_cache_way_count[0] = 4;  //L1 cache 4-way (Associativity)
		m_cache_way_count[1] = 8;
		m_cache_way_count[2] = 16;

		m_block_size[0] = 64;
		m_block_size[1] = 64;
		m_block_size[2] = 64;

		m_min_granularity[0] = 8;  //the access count for all sub blocks in each cache line
		m_min_granularity[1] = 8;
		m_min_granularity[2] = 8;


		m_sub_block_count = m_block_size[2] / m_min_granularity[2];

		for(i = 0; i < m_level; i++)
		{
			m_cache_set_capacity[i] = m_block_size[i] * m_cache_way_count[i];
			m_cache_set_count[i] = m_cache_capacity[i] / m_cache_set_capacity[i];

			m_mem_reads[i] = 0;
			m_mem_reads_hit[i] = 0;
			m_mem_reads_miss[i] = 0;

			m_mem_writes[i] = 0;
			m_mem_writes_hit[i] = 0;
			m_mem_writes_miss[i] = 0;
		}

		for(i = 0; i < m_level; i++)
		{
			m_sub_block_bits[i] = FloorLog2(m_min_granularity[i]);
			m_block_low_bits[i] = FloorLog2(m_block_size[i]) - m_sub_block_bits[i];
			m_set_index_bits[i] = FloorLog2(m_cache_set_count[i]);
	
			m_sub_block_mask[i] = (1UL << m_sub_block_bits[i]) - 1;
			m_block_low_mask[i] = (1UL << m_block_low_bits[i]) - 1;
			m_set_index_mask[i] = (1UL << m_set_index_bits[i]) - 1;
		}


		m_shared_LLC = 1;
		
		m_cache_config_fname = NULL;
	
		//alloc memoryu for real cache sets
		for(i = 0; i < MAX_CACHE_LEVEL; i++)
		{
			m_cache_sets[i] = NULL;
		}

		for(i = 0; i < m_level; i++)
		{
			m_cache_sets[i] = new CacheSet *[m_cache_set_count[i]];
			for(j = 0; j < m_cache_set_count[i]; j++)
			{
				m_cache_sets[i][j] = new CacheSet(m_cache_way_count[i], m_block_size[i], m_min_granularity[i]);
			}
		}

		for(i = 0; i < MAX_SUB_BLOCK; i++)
		{
			m_sub_block_distribution[i] = 0;
		}
	
	}
	else
	{
		cerr<<"#### Sorry, we have not supported read cache configs from file"<<endl;
		exit(-8);
	}

#ifdef DEBUG_CACHE_SIMULATOR
	//print_cache_config();
#endif
}

Caches::~Caches()
{
	uint32_t i;
	uint32_t j;
    	cout<<"in ~Caches()"<<endl;

	for(i = 0; i < m_level; i++)
        {
        	for(j = 0; j < m_cache_set_count[i]; j++)
                {
			if(m_cache_sets[i][j])
			{
				delete m_cache_sets[i][j];
				m_cache_sets[i][j] = NULL;
			}
                }
		delete []m_cache_sets[i];
		m_cache_sets[i] = NULL;
       	}
}

CacheSet* Caches::access_cache_at_level(uint64_t maddr, uint32_t level, uint32_t *hit_cache, uint64_t *mtag, uint32_t *sub_block_index)
{
	//uint64_t mem_tag;
	uint32_t set_index;
	//uint32_t sub_block_index;
	*hit_cache = 0;

	assert(level >= 0 && level < m_level);

	get_cache_addr_parts(maddr, mtag, &set_index, sub_block_index, level);
    
    	assert(set_index >= 0 && set_index < m_cache_set_count[level] && (m_cache_sets[level][set_index] != NULL));

	CacheBlock *p_block = m_cache_sets[level][set_index]->find_block(*mtag);
	if(p_block)
	{
		//Yeah, we find the cache block in this set. Hit it in the mru
		m_cache_sets[level][set_index]->hit_access(&p_block, *sub_block_index);
        	assert(m_cache_sets[level][set_index]->get_mru_block()->m_block_tag == *mtag);
		*hit_cache = 1;
#ifdef DEBUG_CACHE_SIMULATOR
		//cout<<"Cache Hit at Level "<<level <<": addr=0x"<<hex<<maddr<<", mtag="<<*mtag<<dec<<", set_index="<<set_index<<", sb_index="<<*sub_block_index<<endl;
#endif
	}
	return m_cache_sets[level][set_index];
}

void Caches::output_mem_reqs_statistics()
{
	uint32_t i;
	cout<<endl<<endl<<"$$$$ Memory Request Cache Statistics:"<<endl;
	for(i = 0; i < m_level; i++)
	{
		cout<<i<<"th level cache:read="<<m_mem_reads[i]<<", read_hit="<<m_mem_reads_hit[i]<<", read_miss="<<m_mem_reads_miss[i]<<endl;
		cout<<"\t\twrite="<<m_mem_writes[i]<<", write_hit="<<m_mem_writes_hit[i]<<", write_miss="<<m_mem_writes_miss[i]<<endl;
	}

	cout<<"Cache sub block accessed statistics:"<<endl;
	for(i = 0; i <= m_sub_block_count; i++)
	{
		cout<<m_sub_block_distribution[i]<<", ";
	}
	cout<<endl;
}

void Caches::access_cache(uint64_t maddr, uint32_t memop, int thdid, CacheAccessType *cacheAccessType)
{
	uint32_t i;
	CacheSet *access_cache_sets[MAX_CACHE_LEVEL];
	uint64_t mtags[MAX_CACHE_LEVEL];
	uint32_t sub_block_indexes[MAX_CACHE_LEVEL];	

	uint32_t hit_cache = 0;

	for(i = 0; i < m_level; i++)
	{
		access_cache_sets[i] = access_cache_at_level(maddr, i, &hit_cache, &mtags[i], &sub_block_indexes[i]);
        	assert(access_cache_sets[i] != NULL);
		if(memop == MEM_READ)
		{
			m_mem_reads[i]++;
			if(hit_cache)
			{
				m_mem_reads_hit[i]++;
			}
			else
			{
				m_mem_reads_miss[i]++;
			}
		}
		else if(memop == MEM_WRITE)
		{
			m_mem_writes[i]++;
			if(hit_cache)
			{
				m_mem_writes_hit[i]++;
			}
			else
			{
				m_mem_writes_miss[i]++;
			}
		}
		if(hit_cache)
		{
			//we got the cache block hit in this cache level
            
            /// Hit in this cache level, get the cache access type
            assert(i < 3);
            if( 0 == i)
            {
                /// Hit at the L1 Cache
                *cacheAccessType = L1_CACHE_HIT;
            }
            else if( 1 == i)
            {
                *cacheAccessType = L2_CACHE_HIT;
            }
            else if( 2 == i)
            {
                *cacheAccessType = L3_CACHE_HIT;
            }

            /// Note: Here we also need to add all the cache hit memory requests into the trace buf
            /// Set it already to be committed for all cache hit memory requests
            /// Set the sub block count 1
            add_mem_trace_to_buf(maddr, (unsigned int)memop, thdid, cacheAccessType);
#ifndef MEM_TRACE_BUF_THREAD
            assert(maddr == p_mem_trace_buf[(mem_trace_buf_next_index-1)%max_mem_trace_gra_count].m_addr);
            p_mem_trace_buf[(mem_trace_buf_next_index-1)%max_mem_trace_gra_count].m_committed = 1;
            p_mem_trace_buf[(mem_trace_buf_next_index-1)%max_mem_trace_gra_count].m_sb_count = 0;
#else
            assert(maddr == p_mem_trace_buf_thread[thdid][(mem_trace_buf_next_index_thread[thdid]-1)%max_mem_trace_gra_count].m_addr);
            p_mem_trace_buf_thread[thdid][(mem_trace_buf_next_index_thread[thdid]-1)%max_mem_trace_gra_count].m_committed = 1;
            p_mem_trace_buf_thread[thdid][(mem_trace_buf_next_index_thread[thdid]-1)%max_mem_trace_gra_count].m_sb_count = 0;
#endif
			break;
		}
		
	}
	
	if(!hit_cache)
	{
        /// Not hit at any cache
        *cacheAccessType = ALL_CACHE_MISS;


		//the cache block miss in all level of caches, we put it in the 
		assert(i == m_level);
		uint32_t accessed_sub_block;

		//for memory write request, first send read, write when the cache block is written back


#ifdef CACHE_WRITE_BACK_SIM
		add_mem_trace_to_buf(maddr, (unsigned int)MEM_READ/*memop*/, thdid, cacheAccessType);
#else
		add_mem_trace_to_buf(maddr, (unsigned int)memop, thdid, cacheAccessType);
#endif


		accessed_sub_block = access_cache_sets[m_level-1]->load_new_block_in_LLC(maddr, mtags[m_level-1], thdid);

		if(accessed_sub_block != INVALID_SUB_BLOCK_DIS)
		{
			m_sub_block_distribution[accessed_sub_block]++;
		}
#ifdef DEBUG_CACHE_SIMULATOR
	
#endif
		i = i - 1;
	}

#ifdef DEBUG_CACHE_SIMULATOR
    	//cout<<"## Enter in Cache replaced: "<<i<<endl;
#endif

	//Now we need to put this new block into the upper cache until to the L1 cache
	while(i > 0)
	{
		//replace the upper lru block with the lower new mru block
        	assert(i > 0);
        	assert(access_cache_sets[i] && access_cache_sets[i-1]);
        	assert(access_cache_sets[i]->get_mru_block()->m_block_tag == mtags[i]);
#ifdef DEBUG_CACHE_SIMULATOR
        	//cout<<"## Before cache replaced at level " << i <<endl;
#endif
		cache_replaced(access_cache_sets[i], access_cache_sets[i-1], i, mtags[i-1], maddr);
		i--;
	}

#ifdef DEBUG_CACHE_SIMULATOR
    	//cout<<"## After Cache replaced"<<endl;
#endif


	assert(access_cache_sets[0]->get_mru_block()->m_block_tag == mtags[0]);
	access_cache_sets[0]->get_mru_block()->hit_access(sub_block_indexes[0], memop);
}

void Caches::cache_replaced(CacheSet *p_lower_set, CacheSet *p_upper_set, uint32_t lower_level, uint64_t upper_mtag, uint64_t maddr)
{
	CacheBlock *p_evicted_block;
	CacheSet *p_wb_set;
	CacheBlock *p_wb_block;

	CacheBlock *p_new_mru_block;	

	uint64_t wb_maddr;
	uint64_t wb_mem_tag;
    	uint32_t wb_set_index;
    	uint32_t wb_sub_block_index;

    	assert(lower_level >= 1 && lower_level < m_level);

#ifdef DEBUG_CACHE_SIMULATOR
     //cout<<"## Evicted lru at level "<<lower_level-1<<endl;
#endif

	p_evicted_block = p_upper_set->evict_lru_block();
    	assert(p_evicted_block);
	wb_maddr = p_evicted_block->m_block_addr;


	if(wb_maddr != INVALID_BLOCK)
	{
		//we only write back the block with valid addr and tag,
		//Attention: we can not use the cache tag form upper set, cause it is different with the lower set
		//Thus, we need to recalculate the tag
        	get_cache_addr_parts(wb_maddr, &wb_mem_tag, &wb_set_index, &wb_sub_block_index, lower_level);

		p_wb_set = m_cache_sets[lower_level][wb_set_index];
        	p_wb_block = p_wb_set->find_block(wb_mem_tag);

		assert(p_wb_block != NULL);
		assert(p_evicted_block->m_parent_block_in_lower->m_block_tag == p_wb_block->m_block_tag);

		//write back the access distribution into the lower wb cache block
		p_wb_block->get_data_from_evicted(p_evicted_block);
	}

	
	//Now load the new block into upper set mru position
	p_new_mru_block = p_lower_set->get_mru_block();
	
	p_evicted_block->m_block_addr = maddr;
	p_evicted_block->m_block_tag = upper_mtag;
	
	p_new_mru_block->push_data_into_upper_block(p_evicted_block);

	//Finally, put this new block into the mru position of the upper cache
	p_upper_set->put_accessed_block_in_mru(p_evicted_block);	
}

void Caches::get_cache_addr_parts(uint64_t maddr, uint64_t *mem_tag, uint32_t *set_index, uint32_t *sub_block_index, uint32_t level)
{
	uint64_t tmp = maddr;

	assert(level < m_level);		

	tmp >>= m_block_low_bits[level];
	*sub_block_index = (tmp & m_sub_block_mask[level]);

	tmp >>= m_sub_block_bits[level];
	*set_index = (tmp & m_set_index_mask[level]);

	tmp >>= m_set_index_bits[level];
	*mem_tag = tmp;

    //assert(*sub_block_index < m_sub_block_count)
}

void Caches::print_cache_config()
{
	uint32_t i;
	uint32_t j;

	cout<<"$$$$ The cache config details:"<<endl;
	cout<<"\t level of cache = " <<m_level<<endl;
	for(i = 0; i < m_level; i++)
	{
		cout<<"\t"<<i<<"th level cache:capacity="<<m_cache_capacity[i];
		cout<<", way_count="<<m_cache_way_count[i];
		cout<<", block_size="<<m_block_size[i];
		cout<<", min_granularity="<<m_min_granularity[i];
		cout<<", set_capacity="<<m_cache_set_capacity[i];
		cout<<", set_count="<<m_cache_set_count[i]<<endl;

		cout<<"\t"<<"Some bits masks info:";
		cout<<"<set_index_bits,sub_block_bits,low_bits>=<"<<m_set_index_bits[i]<<","<<m_sub_block_bits[i]<<","<<m_block_low_bits[i]<<">"<<endl;
		cout<<"mask:"<<hex<<m_set_index_mask[i]<<","<<m_sub_block_mask[i]<<","<<m_block_low_mask[i]<<dec<<endl;
	}	

	cout<<endl<<"LLC shared is "<<m_shared_LLC<<endl;

	cout<<endl<<endl<<"Cache Sets status:"<<endl;
	for(i = 0; i < m_level; i++)
        {
                for(j = 0; j < m_cache_set_count[i]; j++)
                {
                        if(m_cache_sets[i][j])
                        {
				cout<<"Cache Level "<<i<<", Set "<<j<<": ";
                                m_cache_sets[i][j]->print_cache_set();
                        }
                }
                
	}
}

void commit_mem_trace_buf_to_file(int threadid)
{
	//unsigned long commited_trace_len = 0;
	unsigned int no_committed = 1;

#ifdef MEM_TRACE_BUF_THREAD
    /// get the value from thread 
    unsigned long mem_trace_next_committing_index = mem_trace_next_committing_index_thread[threadid];
    unsigned long mem_trace_next_ready_committed_index = mem_trace_next_ready_committed_index_thread[threadid];
    unsigned long mem_trace_buf_next_index = mem_trace_buf_next_index_thread[threadid];
    struct mem_trace_granularity* p_mem_trace_buf = p_mem_trace_buf_thread[threadid];

    unsigned int next_committing_index_committed = next_committing_index_committed_thread[threadid];
    unsigned int committing_duration_num = committing_duration_num_thread[threadid];
#endif


	if(!next_committing_index_committed)
	{
		fprintf(stdout,"@@@@ Oh no, the next committing index trace is not committed--%u\n", committing_duration_num);

		//skip the uncommitted trace, we need to write back the trace into file
		unsigned long skip_trace_count = 0;
		while(mem_trace_next_committing_index < max_mem_trace_gra_count)
		{
			if(!p_mem_trace_buf[mem_trace_next_committing_index].m_committed)
			{
				p_mem_trace_buf[mem_trace_next_committing_index].m_skipped = 1;

				//we set the block in the LLC to be skipped, so we would ignore it, if it is evicted from LLC
				assert(p_mem_trace_buf[mem_trace_next_committing_index].m_p_block_LLC->m_block_addr == p_mem_trace_buf[mem_trace_next_committing_index].m_addr);
				p_mem_trace_buf[mem_trace_next_committing_index].m_p_block_LLC->m_mem_trace_buf_skipped = 1;


				mem_trace_next_committing_index++;
				skip_trace_count++;
				if(skip_trace_count >= max_mem_trace_gra_count / 64)
				{
					break;
				}
			}
			else
			{
				break;
			}
		}
		if(mem_trace_next_committing_index == max_mem_trace_gra_count)
		{
			mem_trace_next_committing_index = 0;
		}
		while(mem_trace_next_committing_index < mem_trace_buf_next_index)
		{
			if(!p_mem_trace_buf[mem_trace_next_committing_index].m_committed)
                        {
				assert(p_mem_trace_buf[mem_trace_next_committing_index].m_p_block_LLC->m_block_addr == p_mem_trace_buf[mem_trace_next_committing_index].m_addr);
				p_mem_trace_buf[mem_trace_next_committing_index].m_p_block_LLC->m_mem_trace_buf_skipped = 1;

                                mem_trace_next_committing_index++;
                                skip_trace_count++;
                                if(skip_trace_count >= max_mem_trace_gra_count / 64)
                                {
                                        break;
                                }
                        }
                        else
                        {
                                break;
                        }
		}

		fprintf(stdout, "@@@@ We have to skip uncommitted memory trace:%lu, thead %d\n", skip_trace_count, threadid);
	}

	if(mem_trace_next_committing_index < mem_trace_buf_next_index)
	{
		while(mem_trace_next_committing_index < mem_trace_buf_next_index)
		{
			if(p_mem_trace_buf[mem_trace_next_committing_index].m_committed)
			{
				//write the memory trace to file
#ifndef NOT_WRITE_TRACE_TO_FILE
				///////////////
				//for GUPS, we do not want the mem trace from main thread 0
				//if(p_mem_trace_buf[mem_trace_next_committing_index].m_threadid != 0)
				{
				mem_trace_counts[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid][p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count]++;
                assert(p_mem_trace_buf[mem_trace_next_committing_index].m_threadid < MAX_NUM_THREAD);

#ifndef TRACE_BINARY_FILE

#ifdef RECORD_UPPER_INS
				fprintf(mtrace_gra[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid], "%8u \t%12lx \t%4u \t%4u \t%8d \t%8d \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_upper_ins_count, p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid, p_mem_trace_buf[mem_trace_next_committing_index].m_cache_access_type);
#else
				fprintf(mtrace_gra[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid], "%12lx \t%4u \t%4u \t%8d \t%8d \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid, p_mem_trace_buf[mem_trace_next_committing_index].m_cache_access_type);
				
#endif

#else           //#ifdef TRACE_BINARY_FILE
                unsigned long btrace = make_trace_binary(&p_mem_trace_buf[mem_trace_next_committing_index]);
                add_btrace_to_buf(btrace, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid);
#endif
				}
#endif
				
				mem_trace_next_committing_index++;
				no_committed = 0;
			}
			else
			{
				break;
			}
		}
	}
	else
	{
		//first, write the mem trace until the end of the buf
		while(mem_trace_next_committing_index < max_mem_trace_gra_count)
		{
			if(p_mem_trace_buf[mem_trace_next_committing_index].m_committed)
                        {
                                //write the memory trace to file                        
#ifndef NOT_WRITE_TRACE_TO_FILE
				//if(p_mem_trace_buf[mem_trace_next_committing_index].m_threadid != 0)
				{
				mem_trace_counts[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid][p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count]++;
                assert(p_mem_trace_buf[mem_trace_next_committing_index].m_threadid < MAX_NUM_THREAD);

#ifndef TRACE_BINARY_FILE

#ifdef RECORD_UPPER_INS
        			fprintf(mtrace_gra[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid], "%8u \t%12lx \t%4u \t%4u \t%8d \t%8d \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_upper_ins_count, p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid, p_mem_trace_buf[mem_trace_next_committing_index].m_cache_access_type);
#else
                                fprintf(mtrace_gra[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid], "%12lx \t%4u \t%4u \t%8d \t%8d \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid, p_mem_trace_buf[mem_trace_next_committing_index].m_cache_access_type);
#endif

#else             //#ifdef TRACE_BINARY_FILE
                  unsigned long btrace = make_trace_binary(&p_mem_trace_buf[mem_trace_next_committing_index]);
                  add_btrace_to_buf(btrace, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid);
#endif
				}
#endif
				//fprintf(mtrace_gra, "%12lx \t%4u \t%4u \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count);                                


                          	mem_trace_next_committing_index++;
				no_committed = 0;
                        }
                        else
                        {
                        	break;
                        }
		}
		if(mem_trace_next_committing_index == max_mem_trace_gra_count)
		{
			mem_trace_next_committing_index = 0;
			while(mem_trace_next_committing_index < mem_trace_buf_next_index)
			{
				if(p_mem_trace_buf[mem_trace_next_committing_index].m_committed)
                        	{
#ifndef NOT_WRITE_TRACE_TO_FILE
					//if(p_mem_trace_buf[mem_trace_next_committing_index].m_threadid != 0)
					{
					mem_trace_counts[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid][p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count]++;
                assert(p_mem_trace_buf[mem_trace_next_committing_index].m_threadid < MAX_NUM_THREAD);

#ifndef TRACE_BINARY_FILE

#ifdef RECORD_UPPER_INS
        				fprintf(mtrace_gra[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid], "%8u \t%12lx \t%4u \t%4u \t%8d \t%8d \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_upper_ins_count, p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid, p_mem_trace_buf[mem_trace_next_committing_index].m_cache_access_type);
#else
                                	fprintf(mtrace_gra[p_mem_trace_buf[mem_trace_next_committing_index].m_threadid], "%12lx \t%4u \t%4u \t%8d \t%8d \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid, p_mem_trace_buf[mem_trace_next_committing_index].m_cache_access_type);
#endif

#else           //#ifdef TRACE_BINARY_FILE
                unsigned long btrace = make_trace_binary(&p_mem_trace_buf[mem_trace_next_committing_index]);
                add_btrace_to_buf(btrace, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid);
#endif
					}
#endif


					//fprintf(mtrace_gra, "%12lx \t%4u \t%4u \t\n",p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count);


					mem_trace_next_committing_index++;
					no_committed = 0;
                                } 
                       		else
                        	{
                                	break;
                        	}
			}
			if(mem_trace_next_committing_index == mem_trace_buf_next_index)
			{
				//Well, we write all the trace in the buf back to file, 
				fprintf(stdout, "@@@@ Well, write all the trace in to file\n");
			}
		}
	}

	if(no_committed)
	{
		fprintf(stdout, "@@@@Oh no, bad luck, no trace could be committed into file, thread %d\n", threadid);

 
		fprintf(stdout, "@@@@ %12lx \t%4u \t%4u \t--index=%lu, ci=%u, thdid=%d\n",p_mem_trace_buf[mem_trace_next_committing_index].m_addr, p_mem_trace_buf[mem_trace_next_committing_index].m_rw, p_mem_trace_buf[mem_trace_next_committing_index].m_sb_count, mem_trace_next_committing_index, p_mem_trace_buf[mem_trace_next_committing_index].m_committed, p_mem_trace_buf[mem_trace_next_committing_index].m_threadid);
	}
	else
	{
		next_committing_index_committed = 0;
	}
	committing_duration_num = 0;

#ifdef MEM_TRACE_BUF_THREAD_ABORT
        if(mem_trace_next_committing_index != mem_trace_next_committing_index_thread[threadid]
               || mem_trace_next_ready_committed_index_thread[threadid] != mem_trace_next_ready_committed_index
               || mem_trace_buf_next_index_thread[threadid] != mem_trace_buf_next_index
               || next_committing_index_committed_thread[threadid] != next_committing_index_committed
               || committing_duration_num_thread[threadid] != committing_duration_num)
        {
            fprintf(stderr, "Failed to use reference for updating\n");
            exit(-8);
        }
#endif

#ifdef MEM_TRACE_BUF_THREAD  //_ABORT
    ///update all the value into thread
    mem_trace_next_committing_index_thread[threadid] =  mem_trace_next_committing_index; 
    mem_trace_next_ready_committed_index_thread[threadid] = mem_trace_next_ready_committed_index;
    mem_trace_buf_next_index_thread[threadid] = mem_trace_buf_next_index;
    //p_mem_trace_buf_thread[threadid] = p_mem_trace_buf;
    
    next_committing_index_committed_thread[threadid] = next_committing_index_committed;
    committing_duration_num_thread[threadid] = committing_duration_num;
#endif

}



void add_write_back_mem_trace_to_buf(unsigned long maddr, unsigned int sb_count, int thdid)
{
    CacheAccessType wbCacheAccessType = ALL_CACHE_MISS;
	add_mem_trace_to_buf(maddr, MEM_WRITE, thdid, &wbCacheAccessType);
#ifndef MEM_TRACE_BUF_THREAD
	p_mem_trace_buf[(mem_trace_buf_next_index-1)%max_mem_trace_gra_count].m_committed = 1;
	p_mem_trace_buf[(mem_trace_buf_next_index-1)%max_mem_trace_gra_count].m_sb_count = sb_count;
#else
    p_mem_trace_buf_thread[thdid][(mem_trace_buf_next_index_thread[thdid]-1)%max_mem_trace_gra_count].m_committed = 1;
    p_mem_trace_buf_thread[thdid][(mem_trace_buf_next_index_thread[thdid]-1)%max_mem_trace_gra_count].m_sb_count = sb_count;
#endif
#if 0
	if(mem_trace_buf_next_index == mem_trace_next_committing_index)
        {   
		//for debugging, if no space, do not write the dirty memory trace into file 
		return;
		commit_mem_trace_buf_to_file();
                assert(mem_trace_buf_next_index != mem_trace_next_committing_index);        
	}

	if(mem_trace_buf_next_index == max_mem_trace_gra_count)
        {       
                mem_trace_buf_next_index = 0; 
       	}
        assert(mem_trace_buf_next_index < max_mem_trace_gra_count);
        p_mem_trace_buf[mem_trace_buf_next_index].m_addr = maddr;      
  	p_mem_trace_buf[mem_trace_buf_next_index].m_rw = MEM_WRITE;
        p_mem_trace_buf[mem_trace_buf_next_index].m_committed = 1;
        p_mem_trace_buf[mem_trace_buf_next_index].m_sb_count = sb_count;

        p_mem_trace_buf[mem_trace_buf_next_index].m_skipped = 0;

	p_mem_trace_buf[mem_trace_buf_next_index].m_upper_ins_count = 0;

	mem_trace_buf_next_index++;
#endif
	
}

void add_mem_trace_to_buf(unsigned long maddr, unsigned int rw, int threadid, CacheAccessType *cacheAccessType)
{
#ifdef MEM_TRACE_BUF_THREAD
    unsigned long mem_trace_next_committing_index = mem_trace_next_committing_index_thread[threadid];
    unsigned long mem_trace_next_ready_committed_index = mem_trace_next_ready_committed_index_thread[threadid];
    unsigned long mem_trace_buf_next_index = mem_trace_buf_next_index_thread[threadid];
    struct mem_trace_granularity* p_mem_trace_buf = p_mem_trace_buf_thread[threadid];

    unsigned int next_committing_index_committed = next_committing_index_committed_thread[threadid];
    unsigned int committing_duration_num = committing_duration_num_thread[threadid];
#endif

	if(mem_trace_buf_next_index == mem_trace_next_committing_index)
	{
		//no space for new mem trace
		//we need to write back ready committed mem trace into file to free some space
		commit_mem_trace_buf_to_file(threadid);
#ifdef MEM_TRACE_BUF_THREAD
        mem_trace_next_committing_index = mem_trace_next_committing_index_thread[threadid];
        mem_trace_next_ready_committed_index = mem_trace_next_ready_committed_index_thread[threadid];
        mem_trace_buf_next_index = mem_trace_buf_next_index_thread[threadid];
        next_committing_index_committed = next_committing_index_committed_thread[threadid];
        committing_duration_num = committing_duration_num_thread[threadid];
#endif
		assert(mem_trace_buf_next_index != mem_trace_next_committing_index);
	}

	if(mem_trace_buf_next_index == max_mem_trace_gra_count)
	{
		mem_trace_buf_next_index = 0;
	}

	assert(mem_trace_buf_next_index < max_mem_trace_gra_count);
	p_mem_trace_buf[mem_trace_buf_next_index].m_addr = maddr;
	p_mem_trace_buf[mem_trace_buf_next_index].m_rw = rw;
	p_mem_trace_buf[mem_trace_buf_next_index].m_committed = 0;
	p_mem_trace_buf[mem_trace_buf_next_index].m_sb_count = 0;

	p_mem_trace_buf[mem_trace_buf_next_index].m_skipped = 0;

	p_mem_trace_buf[mem_trace_buf_next_index].m_threadid = threadid;

    p_mem_trace_buf[mem_trace_buf_next_index].m_cache_access_type = (int)(*cacheAccessType);


	p_mem_trace_buf[mem_trace_buf_next_index].m_upper_ins_count = non_mem_ins_count[threadid]; //////////
	total_non_mem_ins_count[threadid] += non_mem_ins_count[threadid];

	non_mem_ins_count[threadid] = 0;

	//assert(p_mem_trace_buf[mem_trace_buf_next_index].m_p_block_LLC->m_block_addr == maddr);

	mem_trace_buf_next_index++;

	if(rw == MEM_READ)
	{
		mem_read_traces[threadid]++;
	}
	else
	{
		mem_write_traces[threadid]++;
	}

#ifdef MEM_TRACE_BUF_THREAD_ABORT
        if(mem_trace_next_committing_index != mem_trace_next_committing_index_thread[threadid]
                || mem_trace_next_ready_committed_index_thread[threadid] != mem_trace_next_ready_committed_index
                || mem_trace_buf_next_index_thread[threadid] != mem_trace_buf_next_index
                || next_committing_index_committed_thread[threadid] != next_committing_index_committed
                || committing_duration_num_thread[threadid] != committing_duration_num)
        {
            fprintf(stderr, "Failed to use reference for updating\n");
            exit(-8);
        }
#endif


#ifdef MEM_TRACE_BUF_THREAD  //_ABORT
    mem_trace_next_committing_index_thread[threadid] =  mem_trace_next_committing_index;
    mem_trace_next_ready_committed_index_thread[threadid] = mem_trace_next_ready_committed_index;
    mem_trace_buf_next_index_thread[threadid] = mem_trace_buf_next_index;
                        
    next_committing_index_committed_thread[threadid] = next_committing_index_committed;
    committing_duration_num_thread[threadid] = committing_duration_num;
#endif


}

/*VOID Fini(INT32 code, VOID *v)
{
    int i,j;
	cout<<"## in Fini"<<endl;
	myCaches->output_mem_reqs_statistics();

	cout << "@@ Total number of threads = " << numThreads << endl;
    
    	for (INT32 t=0; t<numThreads; t++)
    	{
        	thread_data_t* tdata = get_tls(t);
        	cout << "Count[" << decstr(t) << "]= " << tdata->_count << endl;
    	}

	for(i = 0; i < numThreads; i++)
    {
        fprintf(stdout, "@@@@ thread %d: mem_read_requests=%lu, mem_write_requests=%lu\n", i, mem_read_requests[i], mem_write_requests[i]);
        fprintf(stdout, "@@@@ thread %d: mem_read_traces=%lu, mem_write_traces=%lu\n", i, mem_read_traces[i], mem_write_traces[i]);
        fprintf(stdout, "@@@@ thread %d: total ins count=%lu, total mem ins count=%lu, total non mem ins count=%lu\n", i, total_ins_count[i], total_mem_ins_count[i], total_non_mem_ins_count[i]);	
    }
	

	//int i;
	//int j;
	fprintf(stdout, "\n\n\n$$$$ Mem Trace Counts:");
	for(i = 0; i < 16; i++)
	{
		fprintf(stdout,"Thread %d:\n",i);
		for(j = 0; j<16; j++)
		{
			fprintf(stdout,"%lu\t ", mem_trace_counts[i][j]);
		}
		fprintf(stdout,"\n");
	}
    for(i = 0; i < numThreads; i++)
    {
	    commit_mem_trace_buf_to_file(i);
    }
    fini_mem_buf();
    
        //fprintf(trace, "#eof\n");
        fclose(trace);
        for(i = 0; i < numThreads; i++)
        {
            fclose(mtrace_gra[i]);
        }
        //fclose(mtrace);
        delete myCaches;
}*/

/*INT32 Usage()
{
        PIN_ERROR( "This Pintool prints a trace of memory addresses\n"
                              + KNOB_BASE::StringKnobSummary() + "\n");
            return -1;
}*/
/*
int main(int argc, char *argv[])
{
    //int i;
    //char trace_fname[1024];
    
	InitLock(&lock);

        if (PIN_Init(argc, argv)) return Usage();

        PIN_InitSymbols();

#ifdef PRINT_PIN_ARGV
        for(i = 0; i < argc; i++)
        {
            fprintf(stdout, "%d th argv is:%s\n", i, argv[i]);
        }
#endif

        trace = fopen("CacheSimulator.out", "w");
        //mtrace = fopen("pwd_mtrace.out","r");        
        myCaches = new Caches(NULL, NUM_CORES);

        //for(i = 0; i < MAX_NUM_THREAD; i++)
        {
            //sprintf(trace_fname,"traces/mem_trace_gra_t%d",i);
            //fprintf(stdout,"The %d th trace file:%s\n", i, trace_fname);
	        //mtrace_gra[i] = fopen(trace_fname,"w+");
            //assert(mtrace_gra[i] != NULL);
        }

    init_instr_count();
    init_memory_statistics();
	init_mem_buf();
  
#ifdef DEBUG_CACHE_SIMULATOR
        //myCaches->access_cache(0x7ffUL);
        //char mtrace_buf[1024];
        //assert(myCaches == NULL);
       [>uint64_t maddr = 0;
       uint64_t max_addr = (1UL << 49);
       uint64_t rand_count = 0;
       while(rand_count <= (16UL << 20))
       {
           maddr = rand() % max_addr;
           //cout << maddr <<endl;
            myCaches->access_cache(maddr);
            //myCaches->access_cache(maddr+1);
            //myCaches->access_cache(maddr+2);
            //myCaches->access_cache(maddr+4);
            //maddr += 16;
		rand_count++;
       }<]
       cout << "Access CacheSimulator Finished" <<endl;

       [>while(!feof(mtrace))
       {
            fgets(mtrace_buf, 1024, mtrace);
            sscanf(mtrace_buf,"%lu",&maddr);
            //cout<<maddr<<endl;
            myCaches->access_cache(maddr);
       }<]
#endif

        INS_AddInstrumentFunction(Instruction, 0);

        IMG_AddInstrumentFunction(ImageLoad, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
    	PIN_AddThreadFiniFunction(ThreadFini, 0);

        PIN_AddFiniFunction(Fini, 0);

        //Never returns
        PIN_StartProgram();
        return 0;
        
}*/
