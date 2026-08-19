#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct HttpResponse {
    int status_code = 0;
    std::vector<uint8_t> body;
    std::string error;
};

// Perform HTTP GET with cookie auth, timeout, and retry.
// timeout_sec: per-attempt timeout (default 10s).
// max_retries: total attempts = 1 + max_retries (default 2 retries = 3 attempts).
// Retries only on transient errors (5xx, timeout, connection error).
HttpResponse http_get(
    const std::string& url,
    const std::string& cookie_header = "",
    int timeout_sec = 10,
    int max_retries = 2);
