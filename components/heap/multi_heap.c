// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/cdefs.h>
#include "heap_tlsf.h"
#include <multi_heap.h>
#include "multi_heap_internal.h"

/* Note: Keep platform-specific parts in this header, this source
   file should depend on libc only */
#include "multi_heap_platform.h"

/* Defines compile-time configuration macros */
#include "multi_heap_config.h"

#ifndef MULTI_HEAP_POISONING
/* if no heap poisoning, public API aliases directly to these implementations */
void *multi_heap_malloc(multi_heap_handle_t heap, size_t size)
    __attribute__((alias("multi_heap_malloc_impl")));

void *multi_heap_aligned_alloc(multi_heap_handle_t heap, size_t size, size_t alignment)
    __attribute__((alias("multi_heap_aligned_alloc_impl")));

void multi_heap_free(multi_heap_handle_t heap, void *p)
    __attribute__((alias("multi_heap_free_impl")));

void multi_heap_aligned_free(multi_heap_handle_t heap, void *p)
    __attribute__((alias("multi_heap_aligned_free_impl")));

void *multi_heap_realloc(multi_heap_handle_t heap, void *p, size_t size)
    __attribute__((alias("multi_heap_realloc_impl")));

size_t multi_heap_get_allocated_size(multi_heap_handle_t heap, void *p)
    __attribute__((alias("multi_heap_get_allocated_size_impl")));

multi_heap_handle_t multi_heap_register(void *start, size_t size)
    __attribute__((alias("multi_heap_register_impl")));

void multi_heap_get_info(multi_heap_handle_t heap, multi_heap_info_t *info)
    __attribute__((alias("multi_heap_get_info_impl")));

size_t multi_heap_free_size(multi_heap_handle_t heap)
    __attribute__((alias("multi_heap_free_size_impl")));

size_t multi_heap_minimum_free_size(multi_heap_handle_t heap)
    __attribute__((alias("multi_heap_minimum_free_size_impl")));

void *multi_heap_get_block_address(multi_heap_block_handle_t block)
    __attribute__((alias("multi_heap_get_block_address_impl")));

void *multi_heap_get_block_owner(multi_heap_block_handle_t block)
{
    return NULL;
}

#endif

#define ALIGN(X) ((X) & ~(sizeof(void *)-1))
#define ALIGN_UP(X) ALIGN((X)+sizeof(void *)-1)
#define ALIGN_UP_BY(num, align) (((num) + ((align) - 1)) & ~((align) - 1))


typedef struct multi_heap_info {
    void *lock;
    size_t free_bytes;
    size_t minimum_free_bytes;
    size_t pool_size;
    tlsf_t heap_data;
} heap_t;

/* Return true if this block is free. */
static inline bool is_free(const block_header_t *block)
{
    return ((block->size & 0x01) != 0);
}

/* Data size of the block (excludes this block's header) */
static inline size_t block_data_size(const block_header_t *block)
{
    return (block->size & ~0x03);
}

/* Check a block is valid for this heap. Used to verify parameters. */
static void assert_valid_block(const heap_t *heap, const block_header_t *block)
{
    pool_t pool = tlsf_get_pool(heap->heap_data);
    void *ptr = tlsf_cast(void*, tlsf_cast(unsigned char*, block) + 16UL);

    MULTI_HEAP_ASSERT((ptr >= pool) && 
                    (ptr < pool + heap->pool_size), 
                    (uintptr_t)ptr);
}

void *multi_heap_get_block_address_impl(multi_heap_block_handle_t block)
{
    void *ptr = tlsf_cast(void*, tlsf_cast(unsigned char*, block) + 16UL);
    return (ptr);
}

size_t multi_heap_get_allocated_size_impl(multi_heap_handle_t heap, void *p)
{
    return tlsf_block_size(p);
}

multi_heap_handle_t multi_heap_register_impl(void *start_ptr, size_t size)
{
    assert(start_ptr);
    assert(size >= tlsf_size() + tlsf_block_size_min() + sizeof(heap_t));

    heap_t *result = (heap_t *)start_ptr;
    size -= sizeof(heap_t);

    result->heap_data = tlsf_create_with_pool(start_ptr + sizeof(heap_t), size);
    if(!result->heap_data) {
        return NULL;
    }

    result->lock = NULL;
    result->free_bytes = size - tlsf_size();
    result->pool_size = size;
    result->minimum_free_bytes = result->free_bytes;
    return result;
}

void multi_heap_set_lock(multi_heap_handle_t heap, void *lock)
{
    heap->lock = lock;
}

void inline multi_heap_internal_lock(multi_heap_handle_t heap)
{
    MULTI_HEAP_LOCK(heap->lock);
}

void inline multi_heap_internal_unlock(multi_heap_handle_t heap)
{
    MULTI_HEAP_UNLOCK(heap->lock);
}

multi_heap_block_handle_t multi_heap_get_first_block(multi_heap_handle_t heap)
{
    assert(heap != NULL);
    pool_t pool = tlsf_get_pool(heap->heap_data);
    block_header_t* block = tlsf_cast(block_header_t*, tlsf_cast(tlsfptr_t, pool) + (-8));

    return (multi_heap_block_handle_t)block;
}

multi_heap_block_handle_t multi_heap_get_next_block(multi_heap_handle_t heap, multi_heap_block_handle_t block)
{
    assert(heap != NULL);
    assert_valid_block(heap, block);
    void *ptr = tlsf_cast(void*, tlsf_cast(unsigned char*, block) + 16UL);
    block_header_t* next = tlsf_cast(block_header_t*, tlsf_cast(tlsfptr_t, ptr) + block_data_size(block) - 8UL);;
 
    if(block_data_size(next) == 0) {
        //Last block:
        return NULL;
    } else {
        return (multi_heap_block_handle_t)next;
    }

}

bool multi_heap_is_free(multi_heap_block_handle_t block)
{
    return is_free(block);
}

void *multi_heap_malloc_impl(multi_heap_handle_t heap, size_t size)
{
    if (size == 0 || heap == NULL) {
        return NULL;
    }


    multi_heap_internal_lock(heap);
    void *result = tlsf_malloc(heap->heap_data, size);
    if(result) {
        heap->free_bytes -= tlsf_block_size(result);
        if (heap->free_bytes < heap->minimum_free_bytes) {
            heap->minimum_free_bytes = heap->free_bytes;
        }
    }    
    multi_heap_internal_unlock(heap);

    return result;
}

void *multi_heap_aligned_alloc_impl(multi_heap_handle_t heap, size_t size, size_t alignment)
{
    if (heap == NULL) {
        return NULL;
    }

    if (!size) {
        return NULL;
    }

    if (!alignment) {
        return NULL;
    }

    //Alignment must be a power of two...
    if ((alignment & (alignment - 1)) != 0) {
        return NULL;
    }

    uint32_t overhead = (sizeof(uint32_t) + (alignment - 1));

    multi_heap_internal_lock(heap);
    void *head = multi_heap_malloc_impl(heap, size + overhead);
    if (head == NULL) {
        multi_heap_internal_unlock(heap);
        return NULL;
    }

    //Lets align our new obtained block address:
    //and save information to recover original block pointer
    //to allow us to deallocate the memory when needed
    void *ptr = (void *)ALIGN_UP_BY((uintptr_t)head + sizeof(uint32_t), alignment);
    *((uint32_t *)ptr - 1) = (uint32_t)((uintptr_t)ptr - (uintptr_t)head);

    multi_heap_internal_unlock(heap);
    return ptr;
}

void multi_heap_aligned_free_impl(multi_heap_handle_t heap, void *p)
{
    if (p == NULL) {
        return;
    }

    multi_heap_internal_lock(heap);
    uint32_t offset = *((uint32_t *)p - 1);
    void *block_head = (void *)((uint8_t *)p - offset);

#ifdef MULTI_HEAP_POISONING_SLOW
        multi_heap_internal_poison_fill_region(block_head, multi_heap_get_allocated_size_impl(heap, block_head), true /* free */);
#endif

    multi_heap_free_impl(heap, block_head);
    multi_heap_internal_unlock(heap);
}

void multi_heap_free_impl(multi_heap_handle_t heap, void *p)
{

    if (heap == NULL || p == NULL) {
        return;
    }

    assert_valid_block(heap, p);

    multi_heap_internal_lock(heap);
    heap->free_bytes += tlsf_block_size(p);
    tlsf_free(heap->heap_data, p);
    multi_heap_internal_unlock(heap);
}

void *multi_heap_realloc_impl(multi_heap_handle_t heap, void *p, size_t size)
{
    assert(heap != NULL);

    if (p == NULL) {
        return multi_heap_malloc_impl(heap, size);
    }

    assert_valid_block(heap, p);

    if (heap == NULL) {
        return NULL;
    }

    multi_heap_internal_lock(heap);

    heap->free_bytes += tlsf_block_size(p);
    void *result = tlsf_realloc(heap->heap_data, p, size);
    if(result) {
        heap->free_bytes -= tlsf_block_size(result);
        if (heap->free_bytes < heap->minimum_free_bytes) {
            heap->minimum_free_bytes = heap->free_bytes;
        }
    }
    
    multi_heap_internal_unlock(heap);

    return result;
}

void *multi_heap_aligned_alloc_impl(multi_heap_handle_t heap, size_t size, size_t alignment)
{
    if(heap == NULL) {
        return NULL;
    }

    if(!size) {
        return NULL;
    }

    //Alignment must be a power of two:
    if(((alignment & (alignment - 1)) != 0) ||(!alignment)) {
        return NULL;
    }

    multi_heap_internal_lock(heap);
    void *result = tlsf_memalign(heap->heap_data, alignment, size);
    if(result) {
        heap->free_bytes -= tlsf_block_size(result);
        if(heap->free_bytes < heap->minimum_free_bytes) {
            heap->minimum_free_bytes = heap->free_bytes;
        }
    }
    multi_heap_internal_unlock(heap);

    return result;
}

bool multi_heap_check(multi_heap_handle_t heap, bool print_errors)
{
    (void)print_errors;
    bool valid = true;
    assert(heap != NULL);

    multi_heap_internal_lock(heap);
    if(tlsf_check(heap->heap_data)) {
        valid = false;
    }

    if(tlsf_check_pool(tlsf_get_pool(heap->heap_data))) {
        valid = false;
    }

    multi_heap_internal_unlock(heap);
    return valid;
}

static void multi_heap_dump_tlsf(void* ptr, size_t size, int used, void* user)
{
    (void)user;
    MULTI_HEAP_STDERR_PRINTF("Block %p data, size: %d bytes, Free: %s \n", 
                            (void *)ptr,
                            size,
                            used ? "No" : "Yes");
}

void multi_heap_dump(multi_heap_handle_t heap)
{
    assert(heap != NULL);

    multi_heap_internal_lock(heap);
    MULTI_HEAP_STDERR_PRINTF("Showing data for heap: %p \n", (void *)heap);
    tlsf_walk_pool(tlsf_get_pool(heap->heap_data), multi_heap_dump_tlsf, NULL);
    multi_heap_internal_unlock(heap);
}

size_t multi_heap_free_size_impl(multi_heap_handle_t heap)
{
    if (heap == NULL) {
        return 0;
    }

    return heap->free_bytes;
}

size_t multi_heap_minimum_free_size_impl(multi_heap_handle_t heap)
{
    if (heap == NULL) {
        return 0;
    }

    return heap->minimum_free_bytes;
}

static void multi_heap_get_info_tlsf(void* ptr, size_t size, int used, void* user)
{
    multi_heap_info_t *info = user;
    
    if(used) {
        info->allocated_blocks++;
        info->total_allocated_bytes += size;
    } else {
        info->free_blocks++;
        
        if(size > info->largest_free_block ) {
            info->largest_free_block = size;
        }   
    }
    
    info->total_blocks++; 
}

void multi_heap_get_info_impl(multi_heap_handle_t heap, multi_heap_info_t *info)
{
    memset(info, 0, sizeof(multi_heap_info_t));

    if (heap == NULL) {
        return;
    }

    multi_heap_internal_lock(heap);
    tlsf_walk_pool(tlsf_get_pool(heap->heap_data), multi_heap_get_info_tlsf, info);
    info->minimum_free_bytes = heap->minimum_free_bytes;
    info->total_free_bytes = heap->free_bytes;
    info->largest_free_block = info->largest_free_block ? 1 << (31 - __builtin_clz(info->largest_free_block)) : 0;
    multi_heap_internal_unlock(heap);
}
