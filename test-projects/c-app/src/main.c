/*
 * C OSS Compliance Test Application
 * Pure C language (not C++)
 * 
 * This project tests OSS compliance scanning for pure C language projects
 * using traditional C libraries and build systems.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// System C libraries (potential vulnerabilities)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <zlib.h>
#include <json-c/json.h>
#include <pthread.h>

#include "network.h"
#include "crypto.h"
#include "utils.h"

int main(int argc, char *argv[]) {
    printf("=== C OSS Compliance Test Application ===\n");
    printf("Language: Pure C (not C++)\n");
    printf("Standard: C99\n");
    printf("Build System: Make\n\n");

    // Test OpenSSL functionality (vulnerable versions may exist)
    printf("1. Testing OpenSSL library...\n");
    if (init_crypto() == 0) {
        printf("   ✓ OpenSSL initialized successfully\n");
        
        // Test encryption
        const char* plaintext = "Hello, World!";
        char encrypted[256];
        char decrypted[256];
        
        if (encrypt_data(plaintext, encrypted, sizeof(encrypted)) == 0) {
            printf("   ✓ Data encrypted successfully\n");
            
            if (decrypt_data(encrypted, decrypted, sizeof(decrypted)) == 0) {
                printf("   ✓ Data decrypted successfully: %s\n", decrypted);
            }
        }
        
        cleanup_crypto();
    } else {
        printf("   ✗ Failed to initialize OpenSSL\n");
    }

    // Test libcurl functionality (vulnerable versions may exist)
    printf("\n2. Testing libcurl library...\n");
    if (init_network() == 0) {
        printf("   ✓ libcurl initialized successfully\n");
        
        // Test HTTP request
        char response[1024];
        if (http_get("https://httpbin.org/get", response, sizeof(response)) == 0) {
            printf("   ✓ HTTP GET request successful\n");
        } else {
            printf("   ✗ HTTP GET request failed\n");
        }
        
        cleanup_network();
    } else {
        printf("   ✗ Failed to initialize libcurl\n");
    }

    // Test zlib functionality (vulnerable versions may exist)
    printf("\n3. Testing zlib library...\n");
    const char* test_data = "This is test data for compression using zlib library in pure C.";
    char compressed[256];
    char decompressed[256];
    
    if (compress_data(test_data, compressed, sizeof(compressed)) == 0) {
        printf("   ✓ Data compressed successfully\n");
        
        if (decompress_data(compressed, decompressed, sizeof(decompressed)) == 0) {
            printf("   ✓ Data decompressed successfully: %.50s...\n", decompressed);
        }
    } else {
        printf("   ✗ Compression test failed\n");
    }

    // Test json-c functionality 
    printf("\n4. Testing json-c library...\n");
    json_object *json_obj = json_object_new_object();
    json_object *name_obj = json_object_new_string("C OSS Test");
    json_object *version_obj = json_object_new_string("1.0.0");
    json_object *language_obj = json_object_new_string("C");
    
    json_object_object_add(json_obj, "name", name_obj);
    json_object_object_add(json_obj, "version", version_obj);
    json_object_object_add(json_obj, "language", language_obj);
    
    printf("   ✓ JSON created: %s\n", json_object_to_json_string(json_obj));
    json_object_put(json_obj);

    // Test pthread functionality
    printf("\n5. Testing pthread library...\n");
    pthread_t thread;
    int thread_arg = 42;
    
    if (pthread_create(&thread, NULL, test_thread_function, &thread_arg) == 0) {
        printf("   ✓ Thread created successfully\n");
        pthread_join(thread, NULL);
        printf("   ✓ Thread completed\n");
    } else {
        printf("   ✗ Failed to create thread\n");
    }

    printf("\n=== C Library Dependencies Summary ===\n");
    print_library_versions();
    
    printf("\n=== Known Vulnerability Categories ===\n");
    printf("- OpenSSL: CVE-2021-3711, CVE-2021-3712, CVE-2022-0778\n");
    printf("- libcurl: CVE-2021-22876, CVE-2021-22890, CVE-2022-22576\n");
    printf("- zlib: CVE-2022-37434, CVE-2018-25032\n");
    printf("- json-c: CVE-2020-12762\n");
    
    printf("\nC OSS Compliance Test completed!\n");
    return 0;
} 