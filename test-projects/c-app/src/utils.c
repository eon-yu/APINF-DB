#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <curl/curlver.h>
#include "utils.h"

void print_library_versions(void) {
    printf("Library versions:\n");
    printf("- OpenSSL: %s\n", OPENSSL_VERSION_TEXT);
    printf("- libcurl: %s\n", LIBCURL_VERSION);
    printf("- zlib: %s\n", ZLIB_VERSION);
    printf("- json-c: (runtime version)\n");
    printf("- pthread: POSIX threads (system)\n");
}

int compress_data(const char* input, char* output, size_t output_size) {
    /* Simplified implementation for testing */
    if (strlen(input) + 20 < output_size) {
        strcpy(output, "compressed_");
        strcat(output, input);
        return 0;
    }
    return -1;
}

int decompress_data(const char* input, char* output, size_t output_size) {
    /* Simplified implementation for testing */
    if (strncmp(input, "compressed_", 11) == 0) {
        strncpy(output, input + 11, output_size - 1);
        output[output_size - 1] = '\0';
        return 0;
    }
    return -1;
}

void* test_thread_function(void* arg) {
    int *value = (int*)arg;
    printf("   Thread running with value: %d\n", *value);
    
    /* Simulate some work */
    for (int i = 0; i < 1000000; i++) {
        /* busy wait */
    }
    
    printf("   Thread work completed\n");
    return NULL;
}

void print_system_info(void) {
    printf("System Information:\n");
    printf("- Compiler: " __VERSION__ "\n");
    printf("- C Standard: C99\n");
    printf("- Build System: Make\n");
    printf("- Target: Native C application\n");
} 