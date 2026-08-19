#include "vg_http.hpp"
#include <windows.h>
#include <winhttp.h>
#include <cstdio>
#include <thread>
#include <chrono>

#pragma comment(lib, "winhttp.lib")

using namespace std;

static std::wstring utf8_to_wstr(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

HttpResponse http_get_single(
    const string& url,
    const string& cookie_header,
    int timeout_sec) {
    
    HttpResponse resp;
    
    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);
    
    wstring host;
    host.resize(256);
    urlComp.lpszHostName = &host[0];
    urlComp.dwHostNameLength = static_cast<DWORD>(host.size());
    
    wstring path;
    path.resize(2048);
    urlComp.lpszUrlPath = &path[0];
    urlComp.dwUrlPathLength = static_cast<DWORD>(path.size());

    wstring wurl = utf8_to_wstr(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &urlComp)) {
        resp.error = "WinHttpCrackUrl failed: " + to_string(GetLastError());
        return resp;
    }

    host.resize(urlComp.dwHostNameLength);
    path.resize(urlComp.dwUrlPathLength);

    HINTERNET hSession = WinHttpOpen(L"RiotClient/63.0.9.4891152.4789131 rso-auth (Windows;10;;Professional, x64)",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
        
    if (hSession) {
        DWORD option = WINHTTP_PROTOCOL_FLAG_HTTP2;
        WinHttpSetOption(hSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &option, sizeof(option));
    }

    if (!hSession) {
        resp.error = "WinHttpOpen failed: " + to_string(GetLastError());
        return resp;
    }

    DWORD timeout_ms = timeout_sec * 1000;
    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), urlComp.nPort, 0);
    if (!hConnect) {
        resp.error = "WinHttpConnect failed: " + to_string(GetLastError());
        WinHttpCloseHandle(hSession);
        return resp;
    }

    DWORD requestFlags = 0;
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        requestFlags |= WINHTTP_FLAG_SECURE;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        requestFlags);

    if (!hRequest) {
        resp.error = "WinHttpOpenRequest failed: " + to_string(GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    if (requestFlags & WINHTTP_FLAG_SECURE) {
        DWORD dwFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    wstring wHeaders;
    if (!cookie_header.empty()) {
        wHeaders = L"Cookie: " + utf8_to_wstr(cookie_header) + L"\r\n";
    }

    bool bResults = WinHttpSendRequest(
        hRequest,
        wHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wHeaders.c_str(),
        wHeaders.empty() ? 0 : -1,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    if (!bResults) {
        resp.error = "WinHttpSendRequest/ReceiveResponse failed: " + to_string(GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    WinHttpQueryHeaders(
        hRequest, 
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, 
        &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    
    resp.status_code = dwStatusCode;

    DWORD dwBytesAvailable = 0;
    DWORD dwBytesRead = 0;
    vector<uint8_t> buffer;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            resp.error = "WinHttpQueryDataAvailable failed: " + to_string(GetLastError());
            break;
        }

        if (dwSize == 0) break;

        buffer.resize(dwSize);
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwBytesRead)) {
            resp.error = "WinHttpReadData failed: " + to_string(GetLastError());
            break;
        }

        if (dwBytesRead > 0) {
            resp.body.insert(resp.body.end(), buffer.begin(), buffer.begin() + dwBytesRead);
        }

        if (resp.body.size() > 200 * 1024 * 1024) { // 200MB limit
            resp.error = "Response too large";
            break;
        }

    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

HttpResponse http_get(
    const string& url,
    const string& cookie_header,
    int timeout_sec,
    int max_retries) {
    
    HttpResponse resp;
    for (int attempt = 0; attempt <= max_retries; ++attempt) {
        resp = http_get_single(url, cookie_header, timeout_sec);
        
        if (resp.error.empty() && resp.status_code >= 200 && resp.status_code < 400) {
            break; // Success
        }

        // Only retry on transient errors (5xx or connection/timeout errors)
        if (resp.status_code > 0 && resp.status_code < 500 && resp.status_code != 429) {
            break; // Non-retryable HTTP error
        }

        if (attempt < max_retries) {
            this_thread::sleep_for(chrono::seconds(3 * (attempt + 1)));
        }
    }
    return resp;
}
