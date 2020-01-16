#include "freertos/FreeRTOS.h"
#include <esp_types.h>
#include <stdio.h>
#include "unity.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include <stdlib.h>
#include <sys/param.h>
#include <string.h>

#define MAX_BLOCK_SIZE  (128 * 1024)
#define MAX_EXTERNAL_BLOCK_SIZE (1024 * 1024 * 2)

//This test only makes sense with poisoning disabled
#ifndef CONFIG_HEAP_POISONING_COMPREHENSIVE

TEST_CASE("Allocator timings test", "[heap]")
{
    size_t block_size = 2;
    uint32_t cycles_before;
    uint32_t cycles_measure;

    for(; block_size <= MAX_BLOCK_SIZE; block_size *= 2) {
        cycles_before = portGET_RUN_TIME_COUNTER_VALUE();
        void *result = heap_caps_malloc(block_size, MALLOC_CAP_8BIT);
        cycles_measure = portGET_RUN_TIME_COUNTER_VALUE() - cycles_before;
        TEST_ASSERT(result != NULL);
        printf("Time to alloc a block of %d size is %d cycles \n", block_size, cycles_measure);

        cycles_before = portGET_RUN_TIME_COUNTER_VALUE();
        heap_caps_free(result);
        cycles_measure = portGET_RUN_TIME_COUNTER_VALUE() - cycles_before;
        printf("Time to free a block of %d size is %d cycles \n", block_size, cycles_measure);
    }

#if CONFIG_ESP32_SPIRAM_SUPPORT || CONFIG_ESP32S2_SPIRAM_SUPPORT

    for(block_size = 2; block_size <= MAX_EXTERNAL_BLOCK_SIZE; block_size *= 2) {
        cycles_before = portGET_RUN_TIME_COUNTER_VALUE();
        void *result = heap_caps_malloc(block_size, MALLOC_CAP_SPIRAM);
        cycles_measure = portGET_RUN_TIME_COUNTER_VALUE() - cycles_before;
        TEST_ASSERT(result != NULL);
        printf("Time to alloc a SPIRAM block of %d size is %d cycles \n", block_size, cycles_measure);

        cycles_before = portGET_RUN_TIME_COUNTER_VALUE();
        heap_caps_free(result);
        cycles_measure = portGET_RUN_TIME_COUNTER_VALUE() - cycles_before;
        printf("Time to free a SPIRAM block of %d size is %d cycles \n", block_size, cycles_measure);
    }

#endif
}

#endif