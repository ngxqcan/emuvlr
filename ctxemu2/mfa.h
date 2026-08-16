#pragma once
#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <sstream>
#include <regex>
#include <thread>
#include <atomic>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")

#ifndef SECURITY_FLAG_IGNORE_REVOCATION
#define SECURITY_FLAG_IGNORE_REVOCATION 0x80
#endif

namespace mfa {

static std::atomic<bool> busy{ false };
static void (*on_msg)(int, const char*) = nullptr; // 1 ok, 2 fail, 3 info

static void msg(int k, const char* s) { if (on_msg) on_msg(k, s); }

static const char* PLATFORM =
"ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIkludGVsIg0KfQ==";

static const char* REGIONS[][2] = {
    { "ap", "ap" }, { "na", "na" }, { "eu", "eu" },
    { "kr", "kr" }, { "latam", "na" }, { "br", "na" },
};

static std::string b64(const std::string& in) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o; int v = 0, vb = -6;
    for (unsigned char c : in) { v = (v << 8) + c; vb += 8; while (vb >= 0) { o.push_back(t[(v >> vb) & 63]); vb -= 6; } }
    if (vb > -6) o.push_back(t[((v << 8) >> (vb + 8)) & 63]);
    while (o.size() % 4) o.push_back('=');
    return o;
}

static std::string jstr(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return "";
    if (json[pos] == '"') { pos++; auto end = json.find('"', pos); if (end == std::string::npos) return ""; return json.substr(pos, end - pos); }
    auto end = json.find_first_of(",}", pos);
    return json.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}
static bool jhas(const std::string& j, const std::string& k) { return j.find("\"" + k + "\"") != std::string::npos; }

struct resp { int code = 0; DWORD err = 0; std::string body; };

static std::wstring wide(const char* a) {
    if (!a || !*a) return L""; int n = MultiByteToWideChar(CP_ACP, 0, a, -1, 0, 0);
    if (n <= 1) return L""; std::wstring w(n - 1, 0); MultiByteToWideChar(CP_ACP, 0, a, -1, &w[0], n); return w;
}

static void ignore_cert(HINTERNET req) {
    DWORD f = 0, n = sizeof(f); InternetQueryOptionA(req, INTERNET_OPTION_SECURITY_FLAGS, &f, &n);
    f |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_REVOCATION;
    InternetSetOptionA(req, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof(f));
}

static resp wininet_req(const char* method, const char* host, INTERNET_PORT port, bool ssl, const char* path, const std::string& hdrs, const std::string& body = "") {
    resp o;
    HINTERNET h = InternetOpenA("RiotClient/1.0 (Windows; x64)", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
    if (!h) { o.err = GetLastError(); return o; }
    DWORD to = 15000; InternetSetOptionA(h, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof(to)); InternetSetOptionA(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof(to)); InternetSetOptionA(h, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof(to));
    HINTERNET c = InternetConnectA(h, host, port, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
    if (!c) { o.err = GetLastError(); InternetCloseHandle(h); return o; }
    DWORD fl = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE;
    if (ssl) fl |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    HINTERNET r = HttpOpenRequestA(c, method, path, "HTTP/1.1", 0, 0, fl, 0);
    if (!r) { o.err = GetLastError(); InternetCloseHandle(c); InternetCloseHandle(h); return o; }
    if (ssl) ignore_cert(r);
    if (!hdrs.empty()) HttpAddRequestHeadersA(r, hdrs.c_str(), (DWORD)-1, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
    BOOL ok = HttpSendRequestA(r, 0, 0, body.empty() ? 0 : (LPVOID)body.data(), (DWORD)body.size());
    if (!ok && ssl) { ignore_cert(r); ok = HttpSendRequestA(r, 0, 0, body.empty() ? 0 : (LPVOID)body.data(), (DWORD)body.size()); }
    if (!ok) o.err = GetLastError();
    else { char sc[16] = {}; DWORD sl = sizeof(sc); if (HttpQueryInfoA(r, HTTP_QUERY_STATUS_CODE, sc, &sl, 0)) o.code = atoi(sc); char buf[4096]; DWORD rd = 0; while (InternetReadFile(r, buf, sizeof(buf), &rd) && rd) o.body.append(buf, rd); }
    InternetCloseHandle(r); InternetCloseHandle(c); InternetCloseHandle(h); return o;
}

static resp winhttp_req(const char* host, INTERNET_PORT port, bool ssl, const char* method, const char* path, const std::string& hdrs, const std::string& body = "") {
    resp o;
    HINTERNET s = WinHttpOpen(L"RiotClient/1.0 (Windows; x64)", WINHTTP_ACCESS_TYPE_NO_PROXY, 0, 0, 0);
    if (!s) { o.err = GetLastError(); return o; }
    WinHttpSetTimeouts(s, 15000, 15000, 15000, 15000);
    auto wh = wide(host); HINTERNET c = WinHttpConnect(s, wh.c_str(), port, 0);
    if (!c) { o.err = GetLastError(); WinHttpCloseHandle(s); return o; }
    auto wm = wide(method); auto wp = wide(path);
    HINTERNET r = WinHttpOpenRequest(c, wm.c_str(), wp.c_str(), 0, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, ssl ? WINHTTP_FLAG_SECURE : 0);
    if (!r) { o.err = GetLastError(); WinHttpCloseHandle(c); WinHttpCloseHandle(s); return o; }
    if (ssl) { DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE; WinHttpSetOption(r, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec)); }
    auto whd = wide(hdrs.c_str());
    BOOL ok = WinHttpSendRequest(r, whd.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : whd.c_str(), whd.empty() ? 0 : (DWORD)-1, body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!ok && ssl) { DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE; WinHttpSetOption(r, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec)); ok = WinHttpSendRequest(r, whd.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : whd.c_str(), whd.empty() ? 0 : (DWORD)-1, body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0); }
    if (!ok) o.err = GetLastError();
    else if (WinHttpReceiveResponse(r, 0)) {
        DWORD st = 0, n2 = sizeof(st); if (WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &st, &n2, WINHTTP_NO_HEADER_INDEX)) o.code = (int)st;
        DWORD avail = 0; while (WinHttpQueryDataAvailable(r, &avail) && avail) { std::string chunk(avail, 0); DWORD rd = 0; if (!WinHttpReadData(r, &chunk[0], avail, &rd) || !rd) break; o.body.append(chunk.data(), rd); }
    }
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s); return o;
}

static resp local_get(int port, const char* path, const std::string& basic, bool ssl = true) {
    resp r = winhttp_req("127.0.0.1", (INTERNET_PORT)port, ssl, "GET", path, basic); if (r.code) return r;
    r = winhttp_req("localhost", (INTERNET_PORT)port, ssl, "GET", path, basic); if (r.code) return r;
    r = wininet_req("GET", "127.0.0.1", (INTERNET_PORT)port, ssl, path, basic); if (r.code) return r;
    return wininet_req("GET", "localhost", (INTERNET_PORT)port, ssl, path, basic);
}

static bool read_lockfile(int& port, std::string& pass, std::string& proto) {
    char app[MAX_PATH] = {}; if (!GetEnvironmentVariableA("LOCALAPPDATA", app, MAX_PATH)) return false;
    std::string p = std::string(app) + "\\Riot Games\\Riot Client\\Config\\lockfile";
    HANDLE h = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[512] = {}; DWORD n = 0; ReadFile(h, buf, sizeof(buf) - 1, &n, 0); CloseHandle(h);
    std::string line(buf, n);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) line.pop_back();
    if (line.size() >= 3 && (unsigned char)line[0] == 0xEF) line.erase(0, 3);
    std::vector<std::string> sp; std::stringstream ss(line); std::string t;
    while (std::getline(ss, t, ':')) sp.push_back(t);
    if (sp.size() < 5) return false;
    port = atoi(sp[2].c_str()); pass = sp[3]; proto = sp[4];
    return port > 0 && !pass.empty();
}

static std::string read_tail(const std::string& path, size_t maxn = 512 * 1024) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER sz = {}; if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0) { CloseHandle(h); return ""; }
    size_t take = (size_t)sz.QuadPart;
    if (take > maxn) { LARGE_INTEGER d; d.QuadPart = sz.QuadPart - (LONGLONG)maxn; SetFilePointerEx(h, d, 0, FILE_BEGIN); take = maxn; }
    std::string out(take, 0); DWORD rd = 0, tot = 0;
    while (tot < take && ReadFile(h, &out[tot], (DWORD)(take - tot), &rd, 0) && rd) tot += rd;
    CloseHandle(h); out.resize(tot); return out;
}

static std::string find_ver(const std::string& s) {
    static std::regex re("release-\\d+\\.\\d+-shipping-\\d+-\\d+");
    std::smatch m; std::string last; auto it = s.cbegin();
    while (std::regex_search(it, s.cend(), m, re)) { last = m.str(); it = m.suffix().first; }
    return last;
}

struct auth_t { std::string access, entitlement, puuid, region; int port = 0; bool ssl = true; std::string basic; };

static bool grab_auth(auth_t& a) {
    std::string pass, proto; if (!read_lockfile(a.port, pass, proto)) return false;
    a.ssl = _stricmp(proto.c_str(), "http") != 0;
    a.basic = "Authorization: Basic " + b64("riot:" + pass) + "\r\n";
    resp r = local_get(a.port, "/entitlements/v1/token", a.basic, a.ssl);
    if (r.code != 200 || r.body.empty()) return false;
    if (jhas(r.body, "accessToken"))          a.access      = jstr(r.body, "accessToken");
    if (jhas(r.body, "token"))                a.entitlement = jstr(r.body, "token");
    else if (jhas(r.body, "entitlements_token")) a.entitlement = jstr(r.body, "entitlements_token");
    if (jhas(r.body, "subject"))              a.puuid       = jstr(r.body, "subject");
    r = local_get(a.port, "/chat/v1/session", a.basic, a.ssl);
    if (r.code == 200 && !r.body.empty()) { if (a.puuid.empty() && jhas(r.body, "puuid")) a.puuid = jstr(r.body, "puuid"); if (jhas(r.body, "region")) a.region = jstr(r.body, "region"); }
    if (a.region.empty()) { r = local_get(a.port, "/riotclient/region-locale", a.basic, a.ssl); if (r.code == 200 && !r.body.empty() && jhas(r.body, "region")) a.region = jstr(r.body, "region"); }
    if (a.region.empty()) { r = local_get(a.port, "/player-affinity/v1/session", a.basic, a.ssl); if (r.code == 200 && !r.body.empty() && jhas(r.body, "live")) a.region = jstr(r.body, "live"); }
    if (a.access.empty() || a.entitlement.empty()) return false;
    if (a.puuid.empty()) { std::string h2 = "Authorization: Bearer " + a.access + "\r\n"; r = wininet_req("GET", "auth.riotgames.com", INTERNET_DEFAULT_HTTPS_PORT, true, "/userinfo", h2); if (r.code == 200 && !r.body.empty() && jhas(r.body, "sub")) a.puuid = jstr(r.body, "sub"); }
    return !a.puuid.empty();
}

static std::string client_ver(const auth_t& a) {
    char app[MAX_PATH] = {};
    if (GetEnvironmentVariableA("LOCALAPPDATA", app, MAX_PATH)) {
        std::string v = find_ver(read_tail(std::string(app) + "\\VALORANT\\Saved\\Logs\\ShooterGame.log"));
        if (v.empty()) v = find_ver(read_tail(std::string(app) + "\\VALORANT\\Saved\\Logs\\ShooterGame.log.1"));
        if (!v.empty()) return v;
    }
    if (a.port) { resp r = local_get(a.port, "/riotclient/get_info", a.basic, a.ssl); if (r.code == 200) { std::string v = find_ver(r.body); if (!v.empty()) return v; } }
    resp r = wininet_req("GET", "valorant-api.com", INTERNET_DEFAULT_HTTPS_PORT, true, "/v1/version", "");
    if (r.code == 200 && !r.body.empty() && jhas(r.body, "riotClientVersion")) return jstr(r.body, "riotClientVersion");
    return "";
}

static std::string pvp_hdr(const auth_t& a, const std::string& ver) {
    std::string h;
    h += "Authorization: Bearer " + a.access + "\r\n";
    h += "X-Riot-Entitlements-JWT: " + a.entitlement + "\r\n";
    h += "X-Riot-ClientPlatform: " + std::string(PLATFORM) + "\r\n";
    if (!ver.empty()) h += "X-Riot-ClientVersion: " + ver + "\r\n";
    h += "User-Agent: ShooterGame/13 Windows/10.0.19042.1.256.64bit\r\n";
    h += "Content-Type: application/json\r\n";
    return h;
}

struct party_t { std::string region, shard, id, host; };

static bool find_party(const auth_t& a, const std::string& hdrs, party_t& out) {
    int n = (int)(sizeof(REGIONS) / sizeof(REGIONS[0])); int order[8]; int cnt = 0;
    if (!a.region.empty()) { for (int i = 0; i < n; i++) if (!_stricmp(REGIONS[i][0], a.region.c_str())) order[cnt++] = i; }
    for (int i = 0; i < n; i++) { bool skip = false; for (int j = 0; j < cnt; j++) if (order[j] == i) { skip = true; break; } if (!skip) order[cnt++] = i; }
    std::string path = "/parties/v1/players/" + a.puuid;
    for (int k = 0; k < cnt; k++) {
        int i = order[k]; char host[128]; sprintf_s(host, "glz-%s-1.%s.a.pvp.net", REGIONS[i][0], REGIONS[i][1]);
        resp r = wininet_req("GET", host, INTERNET_DEFAULT_HTTPS_PORT, true, path.c_str(), hdrs);
        if (r.code != 200 || r.body.empty()) continue;
        std::string pid; if (jhas(r.body, "CurrentPartyID")) pid = jstr(r.body, "CurrentPartyID"); else if (jhas(r.body, "CurrentPartyId")) pid = jstr(r.body, "CurrentPartyId");
        if (pid.empty()) continue;
        out.region = REGIONS[i][0]; out.shard = REGIONS[i][1]; out.id = pid; out.host = host; return true;
    }
    return false;
}

static bool wait_party(const auth_t& a, const std::string& hdrs, party_t& out) {
    DWORD end = GetTickCount() + 45000;
    while (GetTickCount() < end) { if (find_party(a, hdrs, out)) return true; Sleep(2000); }
    return false;
}

static int join_q(const auth_t& a, const party_t& p, const std::string& hdrs) {
    std::string ready = "/parties/v1/parties/" + p.id + "/members/" + a.puuid + "/setReady";
    wininet_req("POST", p.host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, true, ready.c_str(), hdrs, "{\"ready\":true}");
    std::string join2 = "/parties/v1/parties/" + p.id + "/matchmaking/join";
    int last = 0;
    for (int i = 0; i < 40; i++) {
        resp r = wininet_req("POST", p.host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, true, join2.c_str(), hdrs, "");
        last = r.code; if (r.code >= 200 && r.code < 300) return r.code; if (r.code == 409) return r.code;
        if (r.code == 400 && i == 0) wininet_req("POST", p.host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, true, ready.c_str(), hdrs, "{\"ready\":true}");
        Sleep(250);
    }
    return last;
}

static void worker() {
    auth_t a; if (!grab_auth(a)) { msg(2, "MFA Bypass: failed"); return; }
    std::string ver = client_ver(a); if (ver.empty()) { msg(2, "MFA Bypass: failed"); return; }
    std::string hdrs = pvp_hdr(a, ver); msg(3, "MFA Bypass: searching session...");
    party_t p; if (!wait_party(a, hdrs, p)) { msg(2, "MFA Bypass: failed"); return; }
    msg(3, "MFA Bypass: session ready"); int st = join_q(a, p, hdrs);
    if ((st >= 200 && st < 300) || st == 409) msg(1, "MFA Bypass: done!");
    else msg(2, "MFA Bypass: failed");
}

inline void RequestRun() {
    bool exp = false;
    if (!busy.compare_exchange_strong(exp, true)) { msg(2, "MFA Bypass: already running"); return; }
    msg(3, "MFA Bypass: initializing...");
    std::thread([] { worker(); busy = false; }).detach();
}

} // namespace mfa
