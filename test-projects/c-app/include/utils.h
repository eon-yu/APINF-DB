#ifndef UTILS_H
#define UTILS_H

#include <pthread.h>

/*
 * Utility functions for C OSS compliance testing
 * Pure C interface - no C++ features
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Print library versions */
void print_library_versions(void);

/* Compress data using zlib */
int compress_data(const char* input, char* output, size_t output_size);

/* Decompress data using zlib */
int decompress_data(const char* input, char* output, size_t output_size);

/* Thread function for testing pthread */
void* test_thread_function(void* arg);

/* Get system information */
void print_system_info(void);

#ifdef __cplusplus
}
#endif

#endif /* UTILS_H */ 