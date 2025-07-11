#ifndef CRYPTO_H
#define CRYPTO_H

/*
 * Cryptographic functions using OpenSSL (C API)
 * Pure C interface - no C++ features
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize cryptographic subsystem */
int init_crypto(void);

/* Cleanup cryptographic subsystem */
void cleanup_crypto(void);

/* Encrypt data using AES-256-CBC */
int encrypt_data(const char* plaintext, char* encrypted, size_t encrypted_size);

/* Decrypt data using AES-256-CBC */
int decrypt_data(const char* encrypted, char* plaintext, size_t plaintext_size);

/* Generate random bytes */
int generate_random_bytes(unsigned char* buffer, int length);

/* Hash data using SHA-256 */
int hash_data_sha256(const char* data, char* hash_output, size_t hash_size);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */ 