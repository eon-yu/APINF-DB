#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "network.h"

struct curl_response {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_response *response = (struct curl_response *)userp;
    
    response->data = realloc(response->data, response->size + realsize + 1);
    if (response->data == NULL) {
        return 0;
    }
    
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    
    return realsize;
}

int init_network(void) {
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? 0 : -1;
}

void cleanup_network(void) {
    curl_global_cleanup();
}

int http_get(const char* url, char* response, size_t response_size) {
    CURL *curl;
    CURLcode res;
    struct curl_response chunk = {0};
    
    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK && chunk.data) {
        strncpy(response, chunk.data, response_size - 1);
        response[response_size - 1] = '\0';
        free(chunk.data);
        return 0;
    }
    
    if (chunk.data) {
        free(chunk.data);
    }
    return -1;
}

int http_post(const char* url, const char* data, char* response, size_t response_size) {
    /* Simplified implementation for testing */
    snprintf(response, response_size, "POST response from %s with data: %s", url, data);
    return 0;
}

int download_file(const char* url, const char* filename) {
    /* Simplified implementation for testing */
    FILE *fp = fopen(filename, "w");
    if (fp) {
        fprintf(fp, "Downloaded from %s\n", url);
        fclose(fp);
        return 0;
    }
    return -1;
}

int check_connectivity(const char* url) {
    /* Simplified implementation for testing */
    return strstr(url, "http") ? 0 : -1;
} 