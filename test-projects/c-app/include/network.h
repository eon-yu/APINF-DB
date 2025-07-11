#ifndef NETWORK_H
#define NETWORK_H

/*
 * Network functions using libcurl (C API)
 * Pure C interface - no C++ features
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize network subsystem */
int init_network(void);

/* Cleanup network subsystem */
void cleanup_network(void);

/* Perform HTTP GET request */
int http_get(const char* url, char* response, size_t response_size);

/* Perform HTTP POST request */
int http_post(const char* url, const char* data, char* response, size_t response_size);

/* Download file from URL */
int download_file(const char* url, const char* filename);

/* Check if URL is reachable */
int check_connectivity(const char* url);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_H */ 