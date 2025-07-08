#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto.h"

int init_crypto(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return 0;
}

void cleanup_crypto(void) {
    EVP_cleanup();
    ERR_free_strings();
}

int encrypt_data(const char* plaintext, char* encrypted, size_t encrypted_size) {
    /* Simplified implementation for testing */
    if (strlen(plaintext) < encrypted_size) {
        strcpy(encrypted, "encrypted_");
        strcat(encrypted, plaintext);
        return 0;
    }
    return -1;
}

int decrypt_data(const char* encrypted, char* plaintext, size_t plaintext_size) {
    /* Simplified implementation for testing */
    if (strncmp(encrypted, "encrypted_", 10) == 0) {
        strncpy(plaintext, encrypted + 10, plaintext_size - 1);
        plaintext[plaintext_size - 1] = '\0';
        return 0;
    }
    return -1;
}

int generate_random_bytes(unsigned char* buffer, int length) {
    return RAND_bytes(buffer, length) == 1 ? 0 : -1;
}

int hash_data_sha256(const char* data, char* hash_output, size_t hash_size) {
    /* Simplified implementation for testing */
    snprintf(hash_output, hash_size, "sha256_%s", data);
    return 0;
} 