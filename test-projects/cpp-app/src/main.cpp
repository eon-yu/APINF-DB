#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <curl/curl.h>
#include <zlib.h>
#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

int main() {
    std::cout << "C++ OSS Compliance Test Application" << std::endl;
    
    // OpenSSL version info
    std::cout << "OpenSSL Version: " << OPENSSL_VERSION_TEXT << std::endl;
    
    // libcurl version info
    curl_version_info_data *curl_info = curl_version_info(CURLVERSION_NOW);
    std::cout << "libcurl Version: " << curl_info->version << std::endl;
    
    // zlib version info
    std::cout << "zlib Version: " << ZLIB_VERSION << std::endl;
    
    // Boost filesystem example
    boost::filesystem::path current_path = boost::filesystem::current_path();
    std::cout << "Current Path: " << current_path.string() << std::endl;
    
    // nlohmann/json example
    nlohmann::json j;
    j["name"] = "cpp-oss-test";
    j["version"] = "1.0.0";
    std::cout << "JSON: " << j.dump() << std::endl;
    
    // spdlog example
    spdlog::info("Application started successfully");
    
    return 0;
} 