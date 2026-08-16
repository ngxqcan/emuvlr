#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include "mfa.h"
#include "vanguard_gateway.h"
#include "winternl.h"
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <schannel.h>
#include <sspi.h>
#include <wincrypt.h>
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shobjidl.h>

#pragma comment(lib, "ntdll.lib")

#ifndef xorstr_
#define xorstr_(x) (x)
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/imgui_impl_win32.h"
#include <d3d11.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd,
                                                             UINT msg,
                                                             WPARAM wParam,
                                                             LPARAM lParam);

#include "modules/hb_parse.hpp"
#include "modules/hb_task_catalog.hpp"
#include "modules/task_payload_builder.hpp"
#include "modules/task_result_variants.hpp"
#include "modules/task_probe_matrix.hpp"
#include "modules/task_analysis.hpp"
#include <atomic>
#include <chrono>

#include <cstdint>
#include <deque>

#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

bool authenticatedsession = false;
HANDLE g_vanguard_mutex = nullptr;
static std::string g_selected_region = "ap";
HANDLE g_vanguard_shared_memory = nullptr;
std::atomic<bool> g_session_reset_needed{false};
std::atomic<int> g_102_count{0};
static std::atomic_bool g_gw_reauth_needed(false);
static std::atomic_int g_gateway_reauth_remaining_sec(30 * 60);
static std::atomic_int g_reauth_fail_count(0);
static std::atomic_int g_keepalive_fail_count(0);

static std::string g_cached_jwt;
static std::string g_cached_sid;
static std::string g_cached_ext_sid;
static std::string g_cached_puuid;
static std::string g_cached_region;
static std::string g_region_override;
static std::mutex g_jwt_cache_mtx;

static std::vector<uint8_t> g_gw_auth_response;
static std::mutex g_gw_auth_response_mtx;

static VGW::GatewaySession g_gw_session;
static std::mutex g_gw_session_mtx;

static TaskProbeQueue g_task_probe_queue;
static std::mutex g_task_probe_mtx;
static std::atomic_bool g_task_probe_dispatcher_running{false};
static void StartTaskProbeDispatcher();

static bool GatewayDoReauth();
static bool GatewaySendHeartbeat();
bool g_vgc_service_running = false;

static uint32_t GetValorantPID();

static bool IsVgcServiceRunning() {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm)
    return false;
  SC_HANDLE svc = OpenServiceW(scm, L"vgc", SERVICE_QUERY_STATUS);
  if (!svc) {
    CloseServiceHandle(scm);
    return false;
  }
  SERVICE_STATUS status{};
  bool running = false;
  if (QueryServiceStatus(svc, &status)) {
    running = (status.dwCurrentState == SERVICE_RUNNING);
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return running;
}

static std::string GetVgcServiceStatusStr() {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm)
    return "UNKNOWN (SCM error)";
  SC_HANDLE svc = OpenServiceW(scm, L"vgc", SERVICE_QUERY_STATUS);
  if (!svc) {
    CloseServiceHandle(scm);
    return "NOT_FOUND";
  }
  SERVICE_STATUS status{};
  std::string result = "UNKNOWN";
  if (QueryServiceStatus(svc, &status)) {
    switch (status.dwCurrentState) {
    case SERVICE_STOPPED:
      result = "STOPPED";
      break;
    case SERVICE_START_PENDING:
      result = "START_PENDING";
      break;
    case SERVICE_STOP_PENDING:
      result = "STOP_PENDING";
      break;
    case SERVICE_RUNNING:
      result = "RUNNING";
      break;
    case SERVICE_CONTINUE_PENDING:
      result = "CONTINUE_PENDING";
      break;
    case SERVICE_PAUSE_PENDING:
      result = "PAUSE_PENDING";
      break;
    case SERVICE_PAUSED:
      result = "PAUSED";
      break;
    default:
      result = "STATE_" + std::to_string(status.dwCurrentState);
      break;
    }
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return result;
}

constexpr bool RandomizedVersion = true;
constexpr uint16_t SERVER_PORT = 51820;
constexpr bool TLS_SKIP_VERIFY = true;
constexpr int IDLE_TIMEOUT_SEC = 0;
constexpr int HB_INTERVAL_MS = 10000;
constexpr int VAN84_THRESH_SEC = 1800;
constexpr int MAX_CLIENTS = 32;
constexpr int SESSION_KEEPALIVE_BOOST = 600;
constexpr int EMERGENCY_HB_MS = 6000;
constexpr int MAX_HB_BURST = 3;
constexpr int GATEWAY_REAUTH_INTERVAL_SEC = 30 * 60;

constexpr int MIN_VALID_PAYLOAD_SIZE = 32;
constexpr int MAX_RETRY_ATTEMPTS = 3;
constexpr int HEALTH_CHECK_INTERVAL_MS = 5000;
constexpr int MAX_CONSECUTIVE_FAILURES = 3;
constexpr int RSA_KEY_SIZE = 3072;

constexpr const char *SERVER_HOST = "127.0.0.1";
constexpr const char *AUTH_KEY = "";
constexpr const wchar_t *GW_PATH = L"/vanguard/v1/gateway";
constexpr INTERNET_PORT GW_PORT = 8443;
constexpr const wchar_t *VGC_UA = L"vanguard/1.18.5-11+20260805.032431";
constexpr const wchar_t *PIPE_NAME =
    L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC";

static std::wstring RegionToGwHost(const std::string &region) {
  if (region == "la" || region == "la1" || region == "la2")
    return L"latam.vg.ac.pvp.net";
  if (region == "br" || region == "br1")
    return L"br.vg.ac.pvp.net";
  if (region == "na" || region == "na1")
    return L"na.vg.ac.pvp.net";
  if (region == "eu" || region == "eu1" || region == "eu2" || region == "eu3")
    return L"eu.vg.ac.pvp.net";
  if (region == "ap" || region == "ap1" || region == "ap2")
    return L"ap.vg.ac.pvp.net";
  if (region == "kr")
    return L"kr.vg.ac.pvp.net";
  return L"na.vg.ac.pvp.net";
}

enum MsgType : uint32_t {
  MSG_HELLO = 1,
  MSG_HELLO_OK = 2,
  MSG_SYNC = 3,
  MSG_IOCTL = 4,
  MSG_IOCTL_RESP = 5,
  MSG_HB_BUFFER = 6,
  MSG_PING = 7,
  MSG_PONG = 8,
  MSG_ERROR = 9,
  MSG_JWT_UPDATE = 10,
  MSG_JWT_OK = 11,
  MSG_PIPE_AUTH = 12,
  MSG_PIPE_AUTH_OK = 13,
  MSG_SESSION_AUTH = 14,
  MSG_SESSION_AUTH_OK = 15,
  MSG_SESSION_ACCESS = 16,
  MSG_SESSION_ACCESS_OK = 17,
  MSG_SESSION_HEARTBEAT = 18,
  MSG_SESSION_HEARTBEAT_OK = 19,
  MSG_SESSION_REPORT = 20,
  MSG_SESSION_REPORT_OK = 21,
  MSG_SESSION_DISCONNECT = 22,
  MSG_SESSION_DISCONNECT_OK = 23,
  MSG_AUTH_REQUEST = 100,
  MSG_AUTH_RESPONSE = 101,
  MSG_TASKS_DATA = 102,
  MSG_TASKS_ACK = 103,
  MSG_ROUND_START = 110,
  MSG_ROUND_END = 111,
};

constexpr uint32_t IOCTL_VGK_HB = 0x222000;
constexpr uint32_t IOCTL_VGK_ACC = 0x22C03C;
constexpr size_t MAX_PAYLOAD = 128 * 1024 * 1024;

static std::mutex g_log_mtx;
static std::ofstream g_log_file;
static std::mutex g_ui_log_mtx;
static std::deque<std::string> g_ui_log_lines;

static std::vector<std::string> g_log_lines;
static std::mutex g_log_mutex;

static void PushUiLogLine(const std::string &line) {
  std::lock_guard<std::mutex> lk(g_ui_log_mtx);
  g_ui_log_lines.push_back(line);
  while (g_ui_log_lines.size() > 300) {
    g_ui_log_lines.pop_front();
  }
  {
    std::lock_guard<std::mutex> lk2(g_log_mutex);
    g_log_lines.push_back(line);
    while (g_log_lines.size() > 20)
      g_log_lines.erase(g_log_lines.begin());
  }
}

static std::string g_last_log_msg;
static int g_repeat_log_count = 0;
static std::chrono::steady_clock::time_point g_last_log_tp;

static void Log(const std::string &msg) {
  auto now = std::chrono::system_clock::now();
  auto steady_now = std::chrono::steady_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;
  std::tm bt{};
  localtime_s(&bt, &t);
  std::ostringstream ss_time;
  ss_time << "[" << std::put_time(&bt, "%H:%M:%S") << "." << std::setfill('0')
          << std::setw(3) << ms.count() << "] ";

  std::lock_guard<std::mutex> lk(g_log_mtx);

  if (msg == g_last_log_msg) {
    g_repeat_log_count++;
    auto dur = std::chrono::duration_cast<std::chrono::seconds>(steady_now - g_last_log_tp).count();
    if (g_repeat_log_count % 20 == 0 || dur >= 5) {
      std::string rep_line = ss_time.str() + msg + " [repeated x" + std::to_string(g_repeat_log_count) + "]";
      std::cout << rep_line << std::endl;
      if (g_log_file.is_open()) {
        g_log_file << rep_line << "\n";
        g_log_file.flush();
      }
      PushUiLogLine(rep_line);
      g_last_log_tp = steady_now;
    }
    return;
  }

  if (g_repeat_log_count > 1) {
    std::string rep_summary = ss_time.str() + "  ^^^ [last message repeated " + std::to_string(g_repeat_log_count) + " times]";
    std::cout << rep_summary << std::endl;
    if (g_log_file.is_open()) {
      g_log_file << rep_summary << "\n";
      g_log_file.flush();
    }
    PushUiLogLine(rep_summary);
  }

  g_last_log_msg = msg;
  g_repeat_log_count = 1;
  g_last_log_tp = steady_now;

  std::string formatted = ss_time.str() + msg;
  std::cout << formatted << std::endl;
  if (g_log_file.is_open()) {
    g_log_file << formatted << "\n";
    g_log_file.flush();
  }
  PushUiLogLine(formatted);
}

class DataAnalysisManager {
private:
  TaskCatalog m_catalog;
  std::mutex m_mtx;
  size_t m_total_parsed_count = 0;
  std::unordered_set<std::string> m_discovered_tasks;
  std::unordered_set<std::string> m_discovered_modules;
  std::unordered_set<std::string> m_discovered_cdns;

public:
  static bool IsValidStructure(const std::vector<uint8_t> &raw_data) {
    if (raw_data.empty())
      return false;
    std::vector<uint8_t> plain = VGW::DecryptGatewayResponse(raw_data);
    if (plain.empty())
      plain = raw_data;
    if (plain.size() < 20)
      return false;
    return looks_like_hb_response_root(plain) || plain[0] == 0x08;
  }

  void ProcessReceivedData(const std::vector<uint8_t> &raw_data,
                           const std::string &source_label = "gateway") {
    if (raw_data.size() < MIN_VALID_PAYLOAD_SIZE) {
      Log("WARNING: Payload too small: " + std::to_string(raw_data.size()) +
          " bytes");
      return;
    }
    if (!IsValidStructure(raw_data)) {
      Log("ERROR: Invalid payload structure");
      return;
    }
    try {
      std::vector<uint8_t> plain = VGW::DecryptGatewayResponse(raw_data);
      if (plain.empty()) {
        plain = raw_data;
      }

      int env_type = 8;
      if (looks_like_hb_response_root(plain)) {
        env_type = 8;
      }

      HbParseResult parsed = parse_hb_plain(plain, env_type);

      std::lock_guard<std::mutex> lock(m_mtx);
      m_total_parsed_count++;

      TaskCatalog cat = catalog_from_parsed(parsed);
      m_catalog.merge(cat);

      size_t new_tasks = 0;
      for (const auto &task : parsed.tasks) {
        if (task.id_uint.has_value()) {
          std::string tid = std::to_string(task.id_uint.value());
          if (m_discovered_tasks.insert(tid).second)
            new_tasks++;
        }
        if (task.module_task.has_value() && !task.module_task->id_str.empty()) {
          if (m_discovered_tasks.insert(task.module_task->id_str).second)
            new_tasks++;
        }
      }

      size_t new_modules = 0;
      for (const auto &mod : parsed.modules) {
        if (!mod.module_id.empty()) {
          if (m_discovered_modules.insert(mod.module_id).second)
            new_modules++;
        }
      }

      size_t new_cdns = 0;
      for (const auto &cdn : parsed.cdn_urls) {
        if (!cdn.empty()) {
          if (m_discovered_cdns.insert(cdn).second)
            new_cdns++;
        }
      }

      std::ostringstream ss;
      ss << "[DATA_PARSE][" << source_label << "] Parse #"
         << m_total_parsed_count << " | Raw: " << raw_data.size()
         << "B, Plain: " << plain.size() << "B, Slice: " << parsed.slice_bytes
         << "B"
         << " | Tasks: " << parsed.tasks.size() << " (New: " << new_tasks
         << ", Total: " << m_discovered_tasks.size() << ")"
         << " | Modules: " << parsed.modules.size() << " (New: " << new_modules
         << ", Total: " << m_discovered_modules.size() << ")"
         << " | CDN URLs: " << parsed.cdn_urls.size() << " (New: " << new_cdns
         << ", Total: " << m_discovered_cdns.size() << ")"
         << " | Disconnect: " << (parsed.should_disconnect ? "YES" : "NO")
         << " | Fields: [" << parsed.field_summary << "]";

      Log(ss.str());

      if (!parsed.tasks.empty() || !parsed.modules.empty()) {
        std::string report = format_parse_report(parsed);
        Log("[DATA_PARSE_REPORT]\n" + report);
      }

      std::string current_token;
      std::string current_region = g_selected_region.empty() ? "la" : g_selected_region;
      std::string current_puuid;
      std::string current_sid;
      {
        std::lock_guard<std::mutex> lk_j(g_jwt_cache_mtx);
        current_token = g_cached_jwt;
        current_puuid = g_cached_puuid;
        current_sid = g_cached_sid;
        if (!g_cached_region.empty())
          current_region = g_cached_region;
      }
      {
        std::lock_guard<std::mutex> lk_s(g_gw_session_mtx);
        if (!g_gw_session.token.empty())
          current_token = g_gw_session.token;
      }

      std::vector<uint8_t> session_aes(32, 0x5a);
      std::vector<uint8_t> server_rsa_pub;
      {
        std::lock_guard<std::mutex> lk_s(g_gw_session_mtx);
        if (!g_gw_session.server_public_key.empty()) {
          if (g_gw_session.server_public_key.find("-----BEGIN") != std::string::npos)
            server_rsa_pub = VGW::PemToDer(g_gw_session.server_public_key);
          else
            server_rsa_pub = VGW::Base64Decode(g_gw_session.server_public_key);
        }
      }

      {
        std::lock_guard<std::mutex> lk_pq(g_task_probe_mtx);
        g_task_probe_queue.region = current_region;
        ingest_hb_response(g_task_probe_queue, current_sid.empty() ? "session" : current_sid,
                           env_type, plain, current_token, session_aes, server_rsa_pub);
      }
      StartTaskProbeDispatcher();
    } catch (const std::exception &e) {
      Log(std::string("[DATA_PARSE][ERROR] Parsing exception: ") + e.what());
    } catch (...) {
      Log("[DATA_PARSE][ERROR] Unknown parsing exception");
    }
  }

  TaskCatalog GetCatalog() {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_catalog;
  }

  size_t GetTotalParsedCount() const { return m_total_parsed_count; }
};

static DataAnalysisManager g_data_analysis_mgr;

static void PushU32BE(std::vector<uint8_t> &v, uint32_t x) {
  v.push_back((x >> 24) & 0xFF);
  v.push_back((x >> 16) & 0xFF);
  v.push_back((x >> 8) & 0xFF);
  v.push_back(x & 0xFF);
}
static void PushU64BE(std::vector<uint8_t> &v, uint64_t x) {
  for (int i = 7; i >= 0; i--)
    v.push_back((uint8_t)(x >> (i * 8)));
}
static void PushLenStr(std::vector<uint8_t> &v, const std::string &s) {
  PushU32BE(v, (uint32_t)s.size());
  v.insert(v.end(), s.begin(), s.end());
}
static void PushLenBytes(std::vector<uint8_t> &v,
                         const std::vector<uint8_t> &b) {
  PushU32BE(v, (uint32_t)b.size());
  v.insert(v.end(), b.begin(), b.end());
}
static uint32_t ReadU32BE(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t ReadU64BE(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++)
    v = (v << 8) | p[i];
  return v;
}

static std::vector<uint8_t> PackMsg(uint32_t type,
                                    const std::vector<uint8_t> &payload) {
  if (payload.size() > MAX_PAYLOAD)
    throw std::runtime_error("payload too large");
  std::vector<uint8_t> pkt;
  PushU32BE(pkt, type);
  PushU32BE(pkt, (uint32_t)payload.size());
  pkt.insert(pkt.end(), payload.begin(), payload.end());
  return pkt;
}
static std::vector<uint8_t> PackMsg(uint32_t type) {
  std::vector<uint8_t> pkt;
  PushU32BE(pkt, type);
  PushU32BE(pkt, 0);
  return pkt;
}

static std::string ParseLPStr(const std::vector<uint8_t> &buf, size_t &off) {
  if (off + 4 > buf.size())
    return "";
  uint32_t len = ReadU32BE(buf.data() + off);
  off += 4;
  if (off + len > buf.size())
    return "";
  std::string s((char *)buf.data() + off, len);
  off += len;
  return s;
}
static std::vector<uint8_t> ParseLPBytes(const std::vector<uint8_t> &buf,
                                         size_t &off) {
  if (off + 4 > buf.size())
    return {};
  uint32_t len = ReadU32BE(buf.data() + off);
  off += 4;
  if (off + len > buf.size())
    return {};
  std::vector<uint8_t> b(buf.data() + off, buf.data() + off + len);
  off += len;
  return b;
}

static std::vector<uint8_t>
ParseSessionGatewayBody(const std::vector<uint8_t> &payload,
                        std::string *session_id = nullptr) {
  if (payload.empty())
    return {};

  // Attempt 1: Standard format [LPStr sid][U32BE gw_len][gw_bytes]
  {
    size_t off = 0;
    std::string sid = ParseLPStr(payload, off);
    if (off + 4 <= payload.size()) {
      uint32_t gw_len = ReadU32BE(payload.data() + off);
      if (gw_len > 0 && off + 4 + gw_len <= payload.size()) {
        if (session_id)
          *session_id = sid;
        Log("[PARSE_GW] Attempt 1 (Standard): sid=" +
            (sid.empty() ? "empty" : sid.substr(0, 8)) +
            " envelope=" + std::to_string(gw_len) + "B");
        return std::vector<uint8_t>(payload.begin() + off + 4,
                                    payload.begin() + off + 4 + gw_len);
      }
    }
    Log("[PARSE_GW] Attempt 1 (Standard) failed");
  }

  // Attempt 2: Direct format [U32BE gw_len][gw_bytes]
  if (payload.size() >= 4) {
    uint32_t gw_len = ReadU32BE(payload.data());
    if (gw_len > 0 && 4 + gw_len <= payload.size()) {
      if (session_id && session_id->empty())
        *session_id = g_cached_sid;
      Log("[PARSE_GW] Attempt 2 (Direct): envelope=" + std::to_string(gw_len) +
          "B");
      return std::vector<uint8_t>(payload.begin() + 4,
                                  payload.begin() + 4 + gw_len);
    }
    Log("[PARSE_GW] Attempt 2 (Direct) failed");
  }

  // Attempt 3: Raw format (entire payload as envelope)
  if (!payload.empty()) {
    if (session_id && session_id->empty())
      *session_id = g_cached_sid;
    Log("[PARSE_GW] Attempt 3 (Raw): envelope=" +
        std::to_string(payload.size()) + "B");
    return payload;
  }

  Log("[PARSE_GW] All parsing formats failed");
  return {};
}

static std::string Base64UrlDecode(const std::string &in) {
  std::string s = in;
  for (auto &c : s) {
    if (c == '-')
      c = '+';
    if (c == '_')
      c = '/';
  }
  while (s.size() % 4)
    s += '=';
  DWORD outLen = 0;
  CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64, nullptr,
                       &outLen, nullptr, nullptr);
  std::string out(outLen, '\0');
  CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64,
                       (BYTE *)out.data(), &outLen, nullptr, nullptr);
  out.resize(outLen);
  return out;
}

static std::string JsonGetStr(const std::string &json, const std::string &key) {
  std::string search = "\"" + key + "\"";
  auto pos = json.find(search);
  if (pos == std::string::npos)
    return "";
  pos = json.find(':', pos + search.size());
  if (pos == std::string::npos)
    return "";
  while (pos < json.size() &&
         (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t'))
    pos++;
  if (pos >= json.size())
    return "";
  if (json[pos] == '"') {
    pos++;
    auto end = json.find('"', pos);
    if (end == std::string::npos)
      return "";
    return json.substr(pos, end - pos);
  }
  auto end = json.find_first_of(",}", pos);
  return json.substr(pos,
                     end == std::string::npos ? std::string::npos : end - pos);
}

static std::string DecodeJwtPayload(const std::string &jwt) {
  auto dot1 = jwt.find('.');
  if (dot1 == std::string::npos)
    return "";
  auto dot2 = jwt.find('.', dot1 + 1);
  if (dot2 == std::string::npos)
    return "";
  return Base64UrlDecode(jwt.substr(dot1 + 1, dot2 - dot1 - 1));
}

static std::string NormalizeShardHintRobust(std::string value);

// FIX 1: Proper Shard extraction from JWT (strictly parse region without
// fallback)
static std::string ShardFromJwtRobust(const std::string &jwt) {
  auto payload = DecodeJwtPayload(jwt);
  if (payload.empty()) {
    return "";
  }

  // Direct keys where region/shard might be stored
  std::vector<std::string> keys = {
      "shard", "region", "affinity", "player_region", "geo_region",
      "r",     "pas",    "cty",      "lcty",          "p_region"};

  for (const auto &key : keys) {
    std::string value = JsonGetStr(payload, key);
    if (!value.empty()) {
      std::string normalized = NormalizeShardHintRobust(value);
      if (!normalized.empty()) {
        Log("[JWT-REGION] Extracted region '" + normalized +
            "' from payload field '" + key + "' (raw: '" + value + "')");
        return normalized;
      }
    }
  }

  // Also check for nested dat object
  auto dat_pos = payload.find("\"dat\"");
  if (dat_pos != std::string::npos) {
    auto brace = payload.find('{', dat_pos);
    auto close = payload.find('}', brace);
    if (brace != std::string::npos && close != std::string::npos) {
      std::string dat_part = payload.substr(brace, close - brace + 1);
      for (const auto &key :
           std::vector<std::string>{"r", "region", "shard", "affinity"}) {
        std::string sub_val = JsonGetStr(dat_part, key);
        if (!sub_val.empty()) {
          std::string normalized = NormalizeShardHintRobust(sub_val);
          if (!normalized.empty()) {
            Log("[JWT-REGION] Extracted region '" + normalized + "' from dat." +
                key + " (raw: '" + sub_val + "')");
            return normalized;
          }
        }
      }
    }
  }

  // Check inner pas_jwt if present
  std::string pas_jwt = JsonGetStr(payload, "pas_jwt");
  if (!pas_jwt.empty()) {
    auto pas_payload = DecodeJwtPayload(pas_jwt);
    if (!pas_payload.empty()) {
      for (const auto &key : keys) {
        std::string value = JsonGetStr(pas_payload, key);
        if (!value.empty()) {
          std::string normalized = NormalizeShardHintRobust(value);
          if (!normalized.empty()) {
            Log("[JWT-REGION] Extracted region '" + normalized +
                "' from pas_jwt field '" + key + "' (raw: '" + value + "')");
            return normalized;
          }
        }
      }
    }
  }

  return "";
}

static std::string ShardFromJwt(const std::string &jwt) {
  return ShardFromJwtRobust(jwt);
}

static std::string NormalizeShardHintRobust(std::string value) {
  for (auto &c : value)
    c = (char)tolower((unsigned char)c);
  while (!value.empty() &&
         (value.back() == '"' || value.back() == ' ' || value.back() == '\r' ||
          value.back() == '\n' || value.back() == '\t'))
    value.pop_back();
  while (!value.empty() && (value.front() == '"' || value.front() == ' ' ||
                            value.front() == '\r' || value.front() == '\n' ||
                            value.front() == '\t'))
    value.erase(value.begin());
  if (value.empty())
    return "";

  if (value == "la" || value == "la1" || value == "la2" || value == "latam")
    return "la";
  if (value == "br" || value == "br1" || value == "brazil")
    return "br";
  if (value == "na" || value == "na1" || value == "na2" ||
      value == "northamerica" || value == "north_america")
    return "na";
  if (value == "eu" || value == "eu1" || value == "eu2" || value == "eu3" ||
      value == "emea" || value == "europe" || value == "euw" || value == "eune")
    return "eu";
  if (value == "ap" || value == "ap1" || value == "ap2" || value == "apac" ||
      value == "asia" || value == "oce")
    return "ap";
  if (value == "kr" || value == "korea")
    return "kr";

  if (value.find("latam") != std::string::npos || value.rfind("la", 0) == 0)
    return "la";
  if (value.find("brazil") != std::string::npos || value.rfind("br", 0) == 0)
    return "br";
  if (value.find("emea") != std::string::npos ||
      value.find("europe") != std::string::npos || value.rfind("eu", 0) == 0)
    return "eu";
  if (value.find("north") != std::string::npos || value.rfind("na", 0) == 0)
    return "na";
  if (value.find("apac") != std::string::npos ||
      value.find("asia") != std::string::npos ||
      value.find("oce") != std::string::npos || value.rfind("ap", 0) == 0)
    return "ap";
  if (value.find("korea") != std::string::npos || value.rfind("kr", 0) == 0)
    return "kr";
  return "";
}

static void LogJwtRegionHints(const std::string &jwt,
                              const std::string &prefix) {
  auto payload = DecodeJwtPayload(jwt);
  if (payload.empty()) {
    Log(prefix + " jwt_payload=EMPTY");
    return;
  }

  std::string dat_r;
  auto dat_pos = payload.find("\"dat\"");
  if (dat_pos != std::string::npos) {
    auto brace = payload.find('{', dat_pos);
    auto close = payload.find('}', brace);
    if (brace != std::string::npos && close != std::string::npos) {
      dat_r = JsonGetStr(payload.substr(brace, close - brace + 1), "r");
    }
  }

  std::string iss = JsonGetStr(payload, "iss");
  if (iss.size() > 64)
    iss = iss.substr(0, 64) + "...";

  Log(prefix + " dat.r=" + (dat_r.empty() ? "<empty>" : dat_r) + " r=" +
      (JsonGetStr(payload, "r").empty() ? "<empty>"
                                        : JsonGetStr(payload, "r")) +
      " affinity=" +
      (JsonGetStr(payload, "affinity").empty()
           ? "<empty>"
           : JsonGetStr(payload, "affinity")) +
      " region=" +
      (JsonGetStr(payload, "region").empty() ? "<empty>"
                                             : JsonGetStr(payload, "region")) +
      " shard=" +
      (JsonGetStr(payload, "shard").empty() ? "<empty>"
                                            : JsonGetStr(payload, "shard")) +
      " player_region=" +
      (JsonGetStr(payload, "player_region").empty()
           ? "<empty>"
           : JsonGetStr(payload, "player_region")) +
      " geo_region=" +
      (JsonGetStr(payload, "geo_region").empty()
           ? "<empty>"
           : JsonGetStr(payload, "geo_region")) +
      " cty=" +
      (JsonGetStr(payload, "cty").empty() ? "<empty>"
                                          : JsonGetStr(payload, "cty")) +
      " lcty=" +
      (JsonGetStr(payload, "lcty").empty() ? "<empty>"
                                           : JsonGetStr(payload, "lcty")) +
      " iss=" + (iss.empty() ? "<empty>" : iss));
}

static std::string AccountFromJwt(const std::string &jwt) {
  auto payload = DecodeJwtPayload(jwt);
  for (auto &k : {"sub", "acct", "name"}) {
    auto v = JsonGetStr(payload, k);
    if (!v.empty())
      return v;
  }
  return "";
}

static std::string PuuidFromJwt(const std::string &jwt) {
  auto payload = DecodeJwtPayload(jwt);
  static const std::regex uuid_re(
      R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
  for (auto &k : {"sub", "puuid"}) {
    auto v = JsonGetStr(payload, k);
    if (std::regex_match(v, uuid_re))
      return v;
  }
  std::smatch m;
  if (std::regex_search(payload, m, uuid_re))
    return m[0].str();
  return "";
}

static std::string ResolveNonEmptySid(const std::string &jwt,
                                      const std::string &sid,
                                      const std::string &puuid,
                                      const char *tag) {
  if (!sid.empty() && sid != puuid)
    return sid;

  std::string jwt_puuid = PuuidFromJwt(jwt);
  if (!sid.empty() && sid != jwt_puuid)
    return sid;

  Log(std::string(tag) +
      " no distinct session UUID in pipe — f13 will be empty");
  return "";
}

static bool ValidateResponse(const std::vector<uint8_t> &response) {
  if (response.size() < 20) {
    Log("Invalid response: size too small (" + std::to_string(response.size()) +
        "B < 20B)");
    return false;
  }
  if (response[0] != 0x08) {
    Log("Invalid response: wrong field type");
    return false;
  }
  return true;
}

class FallbackCache {
public:
  void update(const std::string &sid, const std::vector<uint8_t> &resp) {
    if (resp.empty())
      return;
    if (!ValidateResponse(resp)) {
      Log("FallbackCache::update rejected invalid response structure for "
          "session " +
          sid);
      return;
    }
    std::lock_guard<std::mutex> lk(mtx_);
    store_[sid] = resp;
  }
  std::vector<uint8_t> get(const std::string &sid) const {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = store_.find(sid);
    return it != store_.end() ? it->second : std::vector<uint8_t>{};
  }
  void clear() {
    std::lock_guard<std::mutex> lk(mtx_);
    store_.clear();
  }

private:
  mutable std::mutex mtx_;
  std::map<std::string, std::vector<uint8_t>> store_;
};
static FallbackCache g_fallback;

static std::vector<uint8_t> RealVgkIoctl(uint32_t ioctl_code,
                                         const std::vector<uint8_t> &in_data);

static bool IsFatalError(const std::vector<uint8_t> &result) {
  DWORD err = GetLastError();
  if (err == ERROR_ACCESS_DENIED || err == ERROR_INVALID_PARAMETER ||
      err == ERROR_INVALID_HANDLE || err == ERROR_FILE_NOT_FOUND) {
    return true;
  }
  if (!result.empty() && result.size() == 4) {
    uint32_t status = *reinterpret_cast<const uint32_t *>(result.data());
    if (status == 0xC0000022 || status == 0xC000000D)
      return true;
  }
  return false;
}

static std::vector<uint8_t> ExecuteIO(const std::vector<uint8_t> &data) {
  return RealVgkIoctl(IOCTL_VGK_HB, data);
}

static std::vector<uint8_t> DoIOOperation(const std::vector<uint8_t> &data) {
  for (int attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
    auto result = ExecuteIO(data);
    if (!result.empty() && result.size() >= MIN_VALID_PAYLOAD_SIZE) {
      return result;
    }
    if (IsFatalError(result)) {
      Log("Fatal error encountered during IO operation, aborting retries.");
      break;
    }
    int delay_ms = 100 * (1 << attempt);
    Log("Retry attempt " + std::to_string(attempt) + " for IO operation");
    Sleep(delay_ms);
  }
  return {};
}

class EventLog {
public:
  EventLog() {}
  void log(const std::string &, const std::string &, const std::string &,
           const std::string & = "", int = 0, int = -1) {}

private:
  std::mutex mtx_;
};
static EventLog g_elog;

static std::vector<uint8_t> g_vgk_payload;
static std::mutex g_vgk_payload_mtx;

static void ClearCachedCredentials() {
  std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
  g_cached_jwt.clear();
  g_cached_sid.clear();
  g_cached_ext_sid.clear();
  g_cached_puuid.clear();
  g_cached_region.clear();
  {
    std::lock_guard<std::mutex> lk2(g_vgk_payload_mtx);
    g_vgk_payload.clear();
  }
  Log("[CACHE] Cleared cached credentials and stored IPC payload.");
}

static bool ValidateCachedCredentials() {
  std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
  if (g_cached_jwt.empty()) {
    return false;
  }

  auto dot1 = g_cached_jwt.find('.');
  auto dot2 = (dot1 == std::string::npos) ? std::string::npos
                                          : g_cached_jwt.find('.', dot1 + 1);
  if (dot1 == std::string::npos || dot2 == std::string::npos) {
    Log("[CACHE][VALIDATION] Invalid JWT structure in cache -> clearing cache "
        "to trigger new data capture");
    g_cached_jwt.clear();
    g_cached_sid.clear();
    g_cached_ext_sid.clear();
    g_cached_puuid.clear();
    g_cached_region.clear();
    return false;
  }

  std::string payload = DecodeJwtPayload(g_cached_jwt);
  if (payload.empty()) {
    Log("[CACHE][VALIDATION] Unable to decode JWT payload in cache -> clearing "
        "cache to trigger new data capture");
    g_cached_jwt.clear();
    g_cached_sid.clear();
    g_cached_ext_sid.clear();
    g_cached_puuid.clear();
    g_cached_region.clear();
    return false;
  }

  std::string exp_str = JsonGetStr(payload, "exp");
  if (!exp_str.empty()) {
    try {
      uint64_t exp = std::stoull(exp_str);
      uint64_t now_sec =
          (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count();
      if (now_sec >= exp) {
        Log("[CACHE][VALIDATION] Cached JWT has expired (exp=" + exp_str +
            ", now=" + std::to_string(now_sec) +
            ") -> clearing cache to trigger new data capture");
        g_cached_jwt.clear();
        g_cached_sid.clear();
        g_cached_ext_sid.clear();
        g_cached_puuid.clear();
        g_cached_region.clear();
        return false;
      }
    } catch (...) {
    }
  }

  return true;
}

static const uint8_t FALLBACK_TOKEN[] = {
    0x08, 0x01, 0x12, 0xA0, 0x02, 0x52, 0x47, 0x01, 0x00, 0x05, 0xFA, 0xA7,
    0x74, 0xC9, 0x93, 0x69, 0x50, 0x77, 0xF4, 0xB0, 0xD9, 0xC8, 0x0D, 0x6F,
    0x67, 0x57, 0x08, 0xCB, 0xFC, 0x03, 0x06, 0x60, 0x70, 0x2C, 0x73, 0x9E,
    0x2C, 0xA5, 0xF7, 0x25, 0xF0, 0x4E, 0x2A, 0x8F, 0x9F, 0xB5, 0xC7, 0x06,
    0xA9, 0x4E, 0x78, 0x15, 0x7B, 0x20, 0x7D, 0xD3, 0x0F, 0xC5, 0xB8, 0x24,
    0xEE, 0xD2, 0xBC, 0xA1, 0x9E, 0x83, 0x0F, 0x34, 0x98, 0x2F, 0x3D, 0xED,
    0xF1, 0x3A, 0xD2, 0x63, 0xDC, 0xA0, 0xA6, 0x16, 0x9F, 0xAA, 0x21, 0xD5,
    0xA4, 0xE9, 0x1C, 0xFE, 0xB6, 0x7A, 0xC2, 0x4B, 0x0C, 0x6F, 0x90, 0x7B,
    0x6F, 0x80, 0x77, 0x70, 0x67, 0x3B, 0x0A, 0xB5, 0x2A, 0x4A, 0x71, 0xBF,
    0xBE, 0xE9, 0xBE, 0x4C, 0xBE, 0xF3, 0xC2, 0xBE, 0xCD, 0x2F, 0xB2, 0xDA,
    0xE8, 0x82, 0xDB, 0xDD, 0x3F, 0xF0, 0x5A, 0x98, 0x0D, 0xA0, 0x2D, 0x7F,
    0xAD, 0xDA, 0xE7, 0xD6, 0xF5, 0x9D, 0x32, 0x1D, 0x0B, 0x38, 0x48, 0x9F,
    0x03, 0xBD, 0x23, 0xF0, 0x39, 0x76, 0x52, 0x67, 0x8F, 0x02, 0x32, 0x3B,
    0xBC, 0x82, 0xCA, 0x10, 0xDE, 0x6A, 0xC7, 0x3C, 0x51, 0x14, 0xFF, 0x58,
    0x8B, 0xFE, 0x7B, 0x63, 0xA6, 0xE2, 0x9D, 0xDB, 0x5B, 0xC0, 0xCD, 0x7F,
    0x92, 0xCE, 0xA6, 0x5D, 0x0C, 0x19, 0x25, 0x00, 0x6E, 0xDC, 0x7B, 0x3B,
    0x0F, 0x68, 0x2B, 0xE1, 0xDD, 0xE8, 0x66, 0x03, 0x70, 0x58, 0x3E, 0x5F,
    0xEA, 0xB1, 0x65, 0x68, 0x4C, 0xB1, 0x2D, 0xF9, 0x7E, 0xD9, 0x45, 0xBF,
    0x06, 0xAD, 0xDF, 0x74, 0xFC, 0x1A, 0x5F, 0x09, 0x41, 0x33, 0xA6, 0x30,
    0xF2, 0xD6, 0x02, 0xE6, 0xCB, 0x46, 0x37, 0xF3, 0x2B, 0x7A, 0xB9, 0x7A,
    0xC6, 0x06, 0x13, 0x7C, 0x0A, 0xF5, 0x78, 0xB4, 0x36, 0x43, 0xDD, 0x6E,
    0xBF, 0x68, 0xBF, 0x90, 0xC7, 0x0E, 0x7D, 0x19, 0x72, 0xBB, 0xDA, 0x9F,
    0xF5, 0x44, 0x82, 0x96, 0x2F, 0xD0, 0x2F, 0xEB, 0x49, 0xBE, 0x8B, 0x17,
    0x05, 0x5D, 0xE3, 0x8C, 0x10, 0xBA, 0xB3, 0x42, 0x7C, 0x01, 0xDD, 0xA9,
    0x00, 0xE5, 0xC2, 0x6D, 0xD0,
};
static const size_t FALLBACK_TOKEN_LEN = sizeof(FALLBACK_TOKEN);

static std::atomic<bool> g_hosts_created{false};

void hosts_olustur() {
  const char *path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
  const char *icerik = "127.0.0.1 na.vg.ac.pvp.net\n"
                       "127.0.0.1 eu.vg.ac.pvp.net\n"
                       "127.0.0.1 eu2.vg.ac.pvp.net\n"
                       "127.0.0.1 br.vg.ac.pvp.net\n"
                       "127.0.0.1 latam.vg.ac.pvp.net\n"
                       "127.0.0.1 kr.vg.ac.pvp.net\n"
                       "127.0.0.1 ap.vg.ac.pvp.net\n"
                       "127.0.0.1 data.riotgames.com\n"
                       "127.0.0.1 telemetry.sgp.pvp.net\n"
                       "127.0.0.1 player-events.vg.ac.pvp.net\n"
                       "127.0.0.1 clientlog.riotgames.com\n"
                       "127.0.0.1 diag.riotgames.com\n"
                       "127.0.0.1 logger.riotgames.com\n";

  std::ofstream f(path, std::ios::out | std::ios::trunc);
  if (f.is_open()) {
    f << icerik;
    g_hosts_created.store(true);
  }
}

void flush_dns_cache() {
  HMODULE h = LoadLibraryA("dnsapi.dll");
  if (!h)
    return;
  auto fn = (VOID(WINAPI *)())GetProcAddress(h, "DnsFlushResolverCache");
  if (fn)
    fn();
  FreeLibrary(h);
}

void hostssil() {
  return; // hostssil temporarily disabled
}

static std::vector<uint8_t> RealVgkIoctl(uint32_t ioctl_code,
                                         const std::vector<uint8_t> &in_data);

struct CryptoSession {
  std::string jwt;
  std::string puuid;
  bool mounted = false;
  int hb_count = 0;
  int token_variant = 0;

  void mount(const std::string &j, const std::string &p) {
    jwt = j;
    puuid = p;
    mounted = true;
    hb_count = 0;
    token_variant = 0;
  }
  void update_jwt(const std::string &j, const std::string &p) {
    jwt = j;
    puuid = p;
    token_variant = 0;
  }

  // FIX 1 & 3: Try device IOCTL call FIRST to get real data; validate size >
  // 100B before storing/returning
  std::vector<uint8_t> heartbeat_payload() {
    hb_count++;

    // 1. Try device IOCTL call FIRST to get real data
    auto real_payload = RealVgkIoctl(IOCTL_VGK_HB, {});
    if (!real_payload.empty() && real_payload.size() > 100) {
      std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
      g_vgk_payload = real_payload;
      Log("[CRYPTO] Captured real data via device IOCTL for hb#" +
          std::to_string(hb_count) +
          " (size=" + std::to_string(real_payload.size()) +
          "B) [stored globally for reuse]");
      return real_payload;
    }

    // 2. Only use stored data if device IOCTL returns empty/invalid AND stored
    // size > 100B
    {
      std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
      if (!g_vgk_payload.empty() && g_vgk_payload.size() > 100) {
        Log("[CRYPTO] Device IOCTL empty, using stored real payload for hb#" +
            std::to_string(hb_count) +
            " (size=" + std::to_string(g_vgk_payload.size()) + "B)");
        return g_vgk_payload;
      }
      if (!g_vgk_payload.empty() && g_vgk_payload.size() <= 100) {
        Log("[CRYPTO] Stored payload too small (" +
            std::to_string(g_vgk_payload.size()) +
            "B <= 100B) -> treated as invalid");
      }
    }

    // 3. Fallback if both device IOCTL and stored data are unavailable or
    // invalid
    Log("[CRYPTO] WARNING: Real device IOCTL and stored data unavailable. "
        "Falling back to FALLBACK_TOKEN hb#" +
        std::to_string(hb_count) +
        " (size=" + std::to_string(FALLBACK_TOKEN_LEN) + "B)");
    return std::vector<uint8_t>(FALLBACK_TOKEN,
                                FALLBACK_TOKEN + FALLBACK_TOKEN_LEN);
  }

  std::vector<uint8_t> ioctl_response(uint32_t code,
                                      const std::vector<uint8_t> &data) {
    if (!mounted)
      return {};
    if (code == IOCTL_VGK_HB)
      return heartbeat_payload();
    if (code == IOCTL_VGK_ACC) {
      if (!data.empty())
        return heartbeat_payload();
      return {0x43, 0x4C, 0x45, 0x41, 0x4E, 0x00};
    }
    if ((code >> 16) == 0x22) {
      if (!data.empty())
        return heartbeat_payload();
      return {0x43, 0x4C, 0x45, 0x41, 0x4E, 0x00};
    }
    if (!data.empty())
      return data;
    return heartbeat_payload();
  }
};

struct ProgramWorker {
  std::string container_id;
  std::string program_path;
  HANDLE proc = INVALID_HANDLE_VALUE;
  uint16_t port = 0;
  bool ready_ = false;

  bool alive() const {
    if (proc == INVALID_HANDLE_VALUE)
      return false;
    DWORD code = 0;
    return GetExitCodeProcess(proc, &code) && code == STILL_ACTIVE;
  }

  bool start() {
    if (program_path.empty() ||
        GetFileAttributesA(program_path.c_str()) == INVALID_FILE_ATTRIBUTES)
      return false;
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET tmp = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(tmp, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
      closesocket(tmp);
      return false;
    }
    int salen = sizeof(sa);
    getsockname(tmp, (sockaddr *)&sa, &salen);
    port = (uint16_t)ntohs(sa.sin_port);
    closesocket(tmp);

    std::string cmd = program_path + " --container " + container_id +
                      " --ipc-port " + std::to_string(port);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
      return false;
    CloseHandle(pi.hThread);
    proc = pi.hProcess;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < deadline) {
      if (!alive())
        return false;
      if (_ping()) {
        ready_ = true;
        return true;
      }
      Sleep(150);
    }
    stop();
    return false;
  }

  void stop() {
    if (alive())
      TerminateProcess(proc, 0);
    if (proc != INVALID_HANDLE_VALUE) {
      CloseHandle(proc);
      proc = INVALID_HANDLE_VALUE;
    }
    ready_ = false;
  }

  std::vector<uint8_t> ioctl(uint32_t code, const std::vector<uint8_t> &data,
                             int timeout_ms = 5000) {
    std::vector<uint8_t> req(10 + data.size());
    req[0] = 1;
    req[1] = 2;
    req[2] = req[3] = 0;
    req[4] = (code >> 24) & 0xFF;
    req[5] = (code >> 16) & 0xFF;
    req[6] = (code >> 8) & 0xFF;
    req[7] = code & 0xFF;
    uint32_t dlen = (uint32_t)data.size();
    req[8] = (dlen >> 8) & 0xFF;
    req[9] = dlen & 0xFF;
    memcpy(req.data() + 10, data.data(), data.size());
    auto resp = _request(req, timeout_ms);
    if (resp.size() < 4)
      return {};
    uint32_t status = (resp[0] << 8) | resp[1];
    if (status != 0)
      return {};
    uint32_t rlen = (resp[2] << 8) | resp[3];
    if (resp.size() < 4 + rlen)
      return {};
    return std::vector<uint8_t>(resp.begin() + 4, resp.begin() + 4 + rlen);
  }

  bool _ping() {
    std::vector<uint8_t> req = {1, 4, 0, 0, 0, 0, 0, 0, 0, 0};
    try {
      auto r = _request(req, 500);
      return r.size() >= 2 && r[0] == 0 && r[1] == 0;
    } catch (...) {
      return false;
    }
  }

  std::vector<uint8_t> _request(const std::vector<uint8_t> &req,
                                int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&to, sizeof(to));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (sockaddr *)&addr, sizeof(addr)) != 0) {
      closesocket(s);
      return {};
    }
    send(s, (char *)req.data(), (int)req.size(), 0);
    std::vector<uint8_t> buf(16384);
    int got = recv(s, (char *)buf.data(), (int)buf.size(), 0);
    closesocket(s);
    if (got <= 0)
      return {};
    buf.resize(got);
    return buf;
  }
};

struct SessionContext {
  std::string token;
  std::string user;
  std::string region;
  std::string context_hash;
  bool is_valid = false;
};

static SessionContext GenerateSessionContext(const std::string &token,
                                             const std::string &user,
                                             const std::string &region = "") {
  SessionContext ctx;
  ctx.token = token;
  ctx.user = user;
  ctx.region = region.empty() ? g_selected_region : region;

  std::string combined = token + ":" + user + ":" + ctx.region;
  uint64_t h = 14695981039346656037ULL;
  for (char c : combined) {
    h ^= (uint8_t)c;
    h *= 1099511628211ULL;
  }
  std::ostringstream ss;
  ss << std::hex << std::setfill('0') << std::setw(16) << h;
  ctx.context_hash = ss.str();
  ctx.is_valid = true;
  return ctx;
}

struct Session {
  std::string session_id;
  std::string riot_token;
  std::string puuid;
  std::string region;
  std::string riot_account;
  std::string hostname;
  std::string client_ip;
  std::string container_id;
  std::vector<uint8_t> gateway_machine_id;
  std::vector<uint8_t> hwid_fingerprint;
  uint32_t valorant_pid = 0;
  int64_t client_ts_ms = 0;
  int jwt_push_count = 0;
  int pipe_auth_count = 0;
  int ping_count = 0;
  int ioctl_count = 0;
  double created_at = 0;
  double last_activity = 0;
  CryptoSession crypto;
  std::shared_ptr<ProgramWorker> worker;

  SessionContext context;
  int failure_count = 0;

  uint64_t hb_sequence = 0;
  double hb_last_sent = 0;
  double hb_last_success = 0;
  int hb_missed = 0;
  int hb_success_count = 0;
  double last_keepalive_boost = 0;
  bool session_hardened = false;
  bool emergency_mode = false;
  int burst_counter = 0;
  double last_burst_time = 0;

  struct HbEntry {
    uint64_t seq;
    std::vector<uint8_t> data;
  };
  std::deque<HbEntry> hb_buffer;
};

static bool ValidateSessionContext(const std::shared_ptr<Session> &session,
                                   const std::string &token = "",
                                   const std::string &user = "") {
  if (!session)
    return false;
  if (!session->context.is_valid)
    return false;
  if (!token.empty() && !session->context.token.empty() &&
      session->context.token != token) {
    Log("Session context validation failed: token mismatch for session " +
        session->session_id);
    return false;
  }
  if (!user.empty() && !session->context.user.empty() &&
      session->context.user != user) {
    Log("Session context validation failed: user mismatch for session " +
        session->session_id);
    return false;
  }
  return true;
}

static double NowSec() {
  return std::chrono::duration<double>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

static std::vector<uint8_t> RealVgkIoctl(uint32_t ioctl_code,
                                         const std::vector<uint8_t> &in_data) {
  HANDLE hDev = CreateFileA("\\\\.\\vgk", GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

  if (hDev == INVALID_HANDLE_VALUE) {
    hDev = CreateFileA("\\\\.\\vgk0", GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  }
  if (hDev == INVALID_HANDLE_VALUE)
    return {};

  std::vector<uint8_t> out_buf(8192, 0);
  DWORD bytes_returned = 0;

  BOOL ok = DeviceIoControl(hDev, ioctl_code,
                            in_data.empty() ? nullptr : (LPVOID)in_data.data(),
                            (DWORD)in_data.size(), out_buf.data(),
                            (DWORD)out_buf.size(), &bytes_returned, nullptr);

  CloseHandle(hDev);

  if (!ok || bytes_returned == 0)
    return {};
  out_buf.resize(bytes_returned);
  return out_buf;
}

class SessionManager {
public:
  std::map<std::string, std::shared_ptr<Session>> sessions;
  mutable std::mutex mtx;
  std::string program_path;

  std::function<void(const std::string &, const std::string &,
                     const std::string &, const std::string &)>
      on_session_created;
  std::function<void(const std::string &)> on_session_destroyed;

  void clear() {
    std::lock_guard<std::mutex> lk(mtx);
    for (auto &kv : sessions) {
      if (kv.second && kv.second->worker) {
        kv.second->worker->stop();
      }
    }
    sessions.clear();
  }

  std::shared_ptr<Session> get(const std::string &sid) const {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    return it != sessions.end() ? it->second : nullptr;
  }
  std::vector<std::string> get_all_sids() const {
    std::lock_guard<std::mutex> lk(mtx);
    std::vector<std::string> out;
    for (const auto &kv : sessions)
      out.push_back(kv.first);
    return out;
  }
  bool is_active(const std::string &sid) const {
    std::lock_guard<std::mutex> lk(mtx);
    return sessions.count(sid) > 0;
  }
  void touch(const std::string &sid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it != sessions.end())
      it->second->last_activity = NowSec();
  }
  void note_ping(const std::string &sid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it != sessions.end()) {
      it->second->ping_count++;
      it->second->last_activity = NowSec();
    }
  }
  void note_ioctl(const std::string &sid, uint32_t code, int in_len,
                  int out_len) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it != sessions.end()) {
      it->second->ioctl_count++;
      it->second->last_activity = NowSec();
    }
    Log("IOCTL session=" + sid.substr(0, 8) + " code=0x" +
        [&] {
          std::ostringstream o;
          o << std::hex << code;
          return o.str();
        }() +
        " in=" + std::to_string(in_len) + " out=" + std::to_string(out_len));
  }

  std::string create_session(const std::string &token,
                             const std::string &user) {
    auto session = std::make_shared<Session>();
    BYTE rnd[16];
    BCryptGenRandom(nullptr, (PUCHAR)rnd, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    rnd[6] = (rnd[6] & 0x0F) | 0x40;
    rnd[8] = (rnd[8] & 0x3F) | 0x80;
    std::ostringstream ss;
    for (int i = 0; i < 16; i++) {
      if (i == 4 || i == 6 || i == 8 || i == 10)
        ss << '-';
      ss << std::hex << std::setfill('0') << std::setw(2) << (int)rnd[i];
    }
    std::string sid = ss.str();
    session->session_id = sid;
    session->riot_token = token;
    session->puuid = user;
    session->riot_account = user;
    session->context = GenerateSessionContext(token, user, g_selected_region);
    session->created_at = NowSec();
    session->last_activity = NowSec();
    session->hb_last_sent = NowSec();
    session->hb_last_success = NowSec();
    session->last_keepalive_boost = NowSec();
    session->session_hardened = true;
    session->crypto.mount(token, user);
    {
      std::lock_guard<std::mutex> lk(mtx);
      sessions[sid] = session;
    }
    Log("session " + sid.substr(0, 8) + " created via token+user context");
    if (on_session_created)
      on_session_created(sid, user, g_selected_region, user);
    return sid;
  }

  std::string create_session(const std::string &jwt, const std::string &puuid,
                             const std::string &region,
                             const std::string &riot_account,
                             const std::string &hostname,
                             const std::string &client_ip,
                             const std::vector<uint8_t> &gw_machine_id,
                             const std::vector<uint8_t> &hwid_fp,
                             uint32_t valorant_pid, int64_t client_ts_ms) {
    BYTE rnd[16];
    BCryptGenRandom(nullptr, (PUCHAR)rnd, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    rnd[6] = (rnd[6] & 0x0F) | 0x40;
    rnd[8] = (rnd[8] & 0x3F) | 0x80;
    std::ostringstream ss;
    for (int i = 0; i < 16; i++) {
      if (i == 4 || i == 6 || i == 8 || i == 10)
        ss << '-';
      ss << std::hex << std::setfill('0') << std::setw(2) << (int)rnd[i];
    }
    std::string sid = ss.str();

    auto s = std::make_shared<Session>();
    s->context = GenerateSessionContext(
        jwt, puuid.empty() ? riot_account : puuid, region);
    s->session_id = sid;
    s->riot_token = jwt;
    s->puuid = puuid;
    s->region = region;
    s->riot_account = riot_account;
    s->hostname = hostname;
    s->client_ip = client_ip;
    s->gateway_machine_id = gw_machine_id;
    s->hwid_fingerprint = hwid_fp;
    s->valorant_pid = valorant_pid;
    s->client_ts_ms = client_ts_ms;
    s->created_at = NowSec();
    s->last_activity = NowSec();
    s->hb_last_sent = NowSec();
    s->hb_last_success = NowSec();
    s->last_keepalive_boost = NowSec();
    s->session_hardened = true;
    s->crypto.mount(jwt, puuid);
    s->pipe_auth_count = 1;
    s->jwt_push_count = jwt.empty() ? 0 : 1;
    {
      std::lock_guard<std::mutex> lk(mtx);
      sessions[sid] = s;
    }
    g_elog.log(sid, "session_auth", "created",
               "ip=" + client_ip + " region=" + region);
    Log("session " + sid.substr(0, 8) + " CREATED ip=" + client_ip +
        " region=" + region + " account=" + riot_account.substr(0, 24) +
        " pid=" + std::to_string(valorant_pid) + " [INFINITE SESSION]");
    if (on_session_created)
      on_session_created(sid, puuid, region, riot_account);
    return sid;
  }

  std::string ensure_session_exists(const std::string &sid,
                                    const std::string &jwt,
                                    const std::string &puuid,
                                    const std::string &region,
                                    uint32_t valorant_pid) {
    std::lock_guard<std::mutex> lk(mtx);
    std::string effective_sid = sid;
    if (effective_sid.empty()) {
      BYTE rnd[16];
      BCryptGenRandom(nullptr, (PUCHAR)rnd, 16,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      rnd[6] = (rnd[6] & 0x0F) | 0x40;
      rnd[8] = (rnd[8] & 0x3F) | 0x80;
      std::ostringstream ss;
      for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
          ss << '-';
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)rnd[i];
      }
      effective_sid = ss.str();
    }
    auto it = sessions.find(effective_sid);
    if (it != sessions.end()) {
      it->second->riot_token = jwt;
      it->second->puuid = puuid;
      if (!region.empty())
        it->second->region = region;
      if (valorant_pid)
        it->second->valorant_pid = valorant_pid;
      it->second->last_activity = NowSec();
      return effective_sid;
    }
    auto s = std::make_shared<Session>();
    s->session_id = effective_sid;
    s->riot_token = jwt;
    s->puuid = puuid;
    s->region = region;
    s->valorant_pid = valorant_pid;
    s->created_at = NowSec();
    s->last_activity = NowSec();
    s->hb_last_sent = NowSec();
    s->hb_last_success = NowSec();
    s->last_keepalive_boost = NowSec();
    s->session_hardened = true;
    s->crypto.mount(jwt, puuid);
    s->pipe_auth_count = 1;
    s->jwt_push_count = jwt.empty() ? 0 : 1;
    sessions[effective_sid] = s;
    g_elog.log(effective_sid, "session_auth", "created_or_restored",
               "region=" + region);
    Log("session " +
        (effective_sid.size() > 8 ? effective_sid.substr(0, 8)
                                  : effective_sid) +
        " RESTORED/CREATED IMMEDIATELY");
    if (on_session_created)
      on_session_created(effective_sid, puuid, region, "");
    return effective_sid;
  }

  bool update_jwt(const std::string &sid, const std::string &jwt,
                  const std::string &puuid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it == sessions.end())
      return false;
    auto &s = *it->second;
    s.riot_token = jwt;
    s.puuid = puuid;
    s.jwt_push_count++;
    s.last_activity = NowSec();
    s.last_keepalive_boost = NowSec();
    s.hb_missed = 0;
    s.emergency_mode = false;
    s.burst_counter = 0;
    s.hb_success_count = 0;
    s.crypto.update_jwt(jwt, puuid);
    g_elog.log(sid, "jwt_update", "ok");
    Log("JWT UPDATE session=" + sid.substr(0, 8) + " - ALL COUNTERS RESET");
    return true;
  }

  bool note_pipe_auth(const std::string &sid, uint32_t pid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it == sessions.end())
      return false;
    it->second->valorant_pid = pid;
    it->second->pipe_auth_count++;
    it->second->last_activity = NowSec();
    return true;
  }

  void destroy_session(const std::string &sid) {
    std::shared_ptr<Session> s;
    {
      std::lock_guard<std::mutex> lk(mtx);
      auto it = sessions.find(sid);
      if (it != sessions.end()) {
        s = it->second;
        sessions.erase(it);
      }
    }
    if (s && s->worker)
      s->worker->stop();
    g_elog.log(sid, "session", "destroyed");
    Log("session " + sid.substr(0, 8) + " destroyed");
    if (on_session_destroyed)
      on_session_destroyed(sid);
  }

  void expire_idle() {
    if (IDLE_TIMEOUT_SEC <= 0) {
      return;
    }

    double now = NowSec();
    std::vector<std::string> expired;
    {
      std::lock_guard<std::mutex> lk(mtx);
      for (auto &kv : sessions) {
        double effective_timeout = IDLE_TIMEOUT_SEC;
        if (kv.second->session_hardened) {
          double boost_age = now - kv.second->last_keepalive_boost;
          if (boost_age < SESSION_KEEPALIVE_BOOST) {
            effective_timeout += SESSION_KEEPALIVE_BOOST;
          }
        }
        if (now - kv.second->last_activity > effective_timeout)
          expired.push_back(kv.first);
      }
    }
    for (auto &sid : expired) {
      Log("session " + sid.substr(0, 8) + " idle timeout");
      destroy_session(sid);
    }
  }

  std::vector<uint8_t> send_heartbeat(const std::string &sid,
                                      bool force = false,
                                      uint32_t code = IOCTL_VGK_HB,
                                      const std::vector<uint8_t> &data = {}) {
    auto s = get(sid);
    if (!s)
      return {};
    std::vector<uint8_t> resp;

    // FIX 1 & 3: Try device IOCTL call FIRST; validate size and protobuf header
    resp = RealVgkIoctl(code, data);
    bool valid_ioctl_resp = false;
    if (!resp.empty()) {
      if (resp.size() > 100 || (resp.size() >= 36 && (looks_like_hb_response_root(resp) || resp[0] == 0x08 || resp[0] == 0x67))) {
        valid_ioctl_resp = true;
      }
    }
    if (valid_ioctl_resp) {
      if (code == IOCTL_VGK_HB) {
        std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
        g_vgk_payload = resp;
        Log("[HB] Captured real data via device IOCTL code=0x" +
            [&] {
              std::ostringstream o;
              o << std::hex << code;
              return o.str();
            }() +
            " resp=" + std::to_string(resp.size()) +
            "B (stored globally for reuse)");
      } else {
        Log("[HB] Captured real data via device IOCTL code=0x" +
            [&] {
              std::ostringstream o;
              o << std::hex << code;
              return o.str();
            }() +
            " resp=" + std::to_string(resp.size()) + "B");
      }
    } else {
      if (!resp.empty()) {
        Log("[HB] Device IOCTL returned small/invalid packet (" +
            std::to_string(resp.size()) + "B) -> ignored");
        resp.clear();
      }
    }

    // Only use stored data if device IOCTL returned empty/invalid AND stored
    // size is valid
    if (resp.empty() && code == IOCTL_VGK_HB && data.empty()) {
      std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
      if (!g_vgk_payload.empty() && g_vgk_payload.size() >= 36) {
        resp = g_vgk_payload;
        Log("[HB] Device IOCTL empty, using stored payload globally for "
            "session " +
            (sid.size() > 8 ? sid.substr(0, 8) : sid) +
            " (size=" + std::to_string(resp.size()) + "B)");
      }
    }

    if (resp.empty() && s->worker && s->worker->alive()) {
      resp = s->worker->ioctl(code, data, 5000);
    }
    if (resp.empty())
      resp = s->crypto.ioctl_response(code, data);
    if (resp.empty())
      resp = g_fallback.get(sid);
    g_fallback.update(sid, resp);
    {
      std::lock_guard<std::mutex> lk(mtx);
      auto it = sessions.find(sid);
      if (it != sessions.end()) {
        auto &ss = *it->second;
        ss.hb_sequence++;
        ss.hb_last_sent = NowSec();
        if (!resp.empty()) {
          g_data_analysis_mgr.ProcessReceivedData(resp, "send_heartbeat");
          ss.hb_missed = 0;
          ss.hb_last_success = NowSec();
          ss.hb_success_count++;
          ss.emergency_mode = false;
          ss.burst_counter = 0;

          // Reset error counters on success
          g_102_count.store(0);
          g_session_reset_needed.store(false);
          g_reauth_fail_count.store(0);
          g_keepalive_fail_count.store(0);

          if (ss.hb_success_count % 10 == 0) {
            ss.last_activity = NowSec();
            ss.last_keepalive_boost = NowSec();
          }
        } else {
          ss.hb_missed++;
          Log("HB empty for session " + sid.substr(0, 8) +
              " (missed=" + std::to_string(ss.hb_missed) +
              ") -> auto-triggering gateway reauth");
          g_gw_reauth_needed.store(true);
          g_gateway_reauth_remaining_sec.store(0);
          std::thread([]() { GatewayDoReauth(); }).detach();

          if (ss.hb_missed >= 1) {
            g_session_reset_needed.store(true);
            g_102_count.fetch_add(1);
          }
          if (ss.hb_missed >= 5) {
            Log("WARN session " + sid.substr(0, 8) +
                " missed=" + std::to_string(ss.hb_missed) + " risk -102");
          }
          if (ss.hb_missed > 15)
            Log("CRITICAL session " + sid.substr(0, 8) +
                " missed HB risk Error 102");
        }
        ss.hb_buffer.push_back({ss.hb_sequence, resp});
        if (ss.hb_buffer.size() > 1024)
          ss.hb_buffer.pop_front();
      }
    }
    g_elog.log(sid, "heartbeat", resp.empty() ? "empty" : "ok");
    return resp;
  }

  std::vector<std::pair<uint64_t, std::vector<uint8_t>>>
  get_buffered(const std::string &sid, uint64_t from_seq) {
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> out;
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it == sessions.end())
      return out;
    for (auto &e : it->second->hb_buffer)
      if (e.seq >= from_seq)
        out.push_back({e.seq, e.data});
    return out;
  }
};
static SessionManager g_session_mgr;

static std::string ApplyConfiguredRegion(const std::string &detected_region,
                                         const char *tag) {
  std::string forced_region;
  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    forced_region = g_region_override;
  }

  if (!forced_region.empty()) {
    Log(std::string(tag) + " region override -> " + forced_region +
        (detected_region.empty() ? " (detected=<empty>)"
                                 : " (detected=" + detected_region + ")"));
    return forced_region;
  }
  return detected_region;
}

struct RoundTracker {
  std::atomic_int round_number{0};
  std::atomic_bool in_match{false};
  std::atomic_bool lobby_pending{false};
  double match_start_time = 0;
  double last_round_time = 0;
  std::mutex mtx;

  void on_match_start() {
    std::lock_guard<std::mutex> lk(mtx);
    in_match.store(true);
    lobby_pending.store(false);
    round_number.store(0);
    match_start_time = NowSec();
    last_round_time = NowSec();
    Log("[ROUND] Match started");
  }
  void on_round_end() {
    std::lock_guard<std::mutex> lk(mtx);
    round_number.fetch_add(1);
    last_round_time = NowSec();
    Log("[ROUND] Round " + std::to_string(round_number.load()) + " ended");
  }
  void on_lobby_return(std::function<void()> refresh_fn) {
    {
      std::lock_guard<std::mutex> lk(mtx);
      if (!in_match.load() && !lobby_pending.load())
        return;
      in_match.store(false);
      lobby_pending.store(true);
      Log("[ROUND] Lobby return after " + std::to_string(round_number.load()) +
          " rounds — refreshing session");
    }
    if (refresh_fn)
      refresh_fn();
    lobby_pending.store(false);
  }
  bool is_in_match() const { return in_match.load(); }
  int current_round() const { return round_number.load(); }
};
static RoundTracker g_round_tracker;

// FIX 3: Improved TasksModulesHandler with proper ACK responses
struct TasksModulesHandler {
  std::atomic_bool tasks_received{false};
  int ack_count = 0;
  std::mutex mtx;

  std::vector<uint8_t> handle_packet(const std::vector<uint8_t> &pkt) {
    std::lock_guard<std::mutex> lk(mtx);
    ack_count++;

    // Scan for potential task hex IDs or strings in pkt to mark in queue
    if (pkt.size() > 8) {
      std::string pkt_str(pkt.begin(), pkt.end());
      std::regex hex_task_re("[0-9a-fA-F]{16,32}");
      std::sregex_iterator it(pkt_str.begin(), pkt_str.end(), hex_task_re), end;
      std::lock_guard<std::mutex> lk_pq(g_task_probe_mtx);
      while (it != end) {
        std::string match_tid = it->str();
        if (looks_like_vanguard_task_id_hex(match_tid)) {
          g_task_probe_queue.acked_task_ids.insert(match_tid);
        }
        ++it;
      }
    }

    // Proper ACK construction based on packet format
    std::vector<uint8_t> ack;

    if (pkt.size() >= 8) {
      // Echo back the header with modified flags
      ack.push_back(pkt[0] + 1); // Increment magic
      ack.push_back(0x00);
      ack.push_back(0x00);
      ack.push_back(0x00);
      ack.push_back(pkt[4]);
      ack.push_back(pkt[5]);
      ack.push_back(pkt[6]);
      ack.push_back(pkt[7]);
    } else {
      // Default ACK
      ack = {0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    }

    Log("[TASKS] ACK sent for packet#" + std::to_string(ack_count));
    tasks_received.store(true);
    return ack;
  }

  std::vector<uint8_t> handle_auth_request(const std::string &jwt,
                                           const std::string &puuid,
                                           const std::string &sid,
                                           const std::string &region) {
    std::lock_guard<std::mutex> lk(mtx);
    Log("[AUTH_REQ] 0x64 new session request — puuid=" +
        (puuid.size() > 8 ? puuid.substr(0, 8) + "..." : puuid));
    std::vector<uint8_t> resp;
    if (!jwt.empty() && !puuid.empty()) {
      resp.push_back(0x00);
      uint32_t plen = (uint32_t)puuid.size();
      resp.push_back((plen >> 24) & 0xFF);
      resp.push_back((plen >> 16) & 0xFF);
      resp.push_back((plen >> 8) & 0xFF);
      resp.push_back(plen & 0xFF);
      resp.insert(resp.end(), puuid.begin(), puuid.end());
      if (!sid.empty()) {
        uint32_t slen = (uint32_t)sid.size();
        resp.push_back((slen >> 24) & 0xFF);
        resp.push_back((slen >> 16) & 0xFF);
        resp.push_back((slen >> 8) & 0xFF);
        resp.push_back(slen & 0xFF);
        resp.insert(resp.end(), sid.begin(), sid.end());
      }
    } else {
      resp.push_back(0x01);
    }
    return resp;
  }
};
static TasksModulesHandler g_tasks_handler;

static std::atomic_bool g_hb_running(false);
static std::atomic_bool g_van84_running(false);
static std::atomic_bool g_keepalive_running(false);
static constexpr bool GATEWAY_AUTO_SEND_ON_CAPTURE = true; // Changed to true
static std::atomic_bool g_gateway_reauth_restart_countdown(false);
static std::atomic_bool g_gateway_auto_send(GATEWAY_AUTO_SEND_ON_CAPTURE);
static std::atomic_bool g_gateway_send_inflight(false);
static std::atomic_bool g_gateway_manual_reauth_inflight(false);
static std::atomic<ULONGLONG> g_gateway_manual_last_trigger_ms(0);
static std::atomic_bool g_backend_started(false);
static std::atomic_bool g_vps_server_heartbeat_running(false);

struct PendingGatewayRequest {
  std::string jwt;
  std::string sid;
  std::string puuid;
  uint32_t pid = 0;
  std::chrono::steady_clock::time_point queued_at{};
  bool valid = false;
};

static std::mutex g_pending_gateway_mtx;
static PendingGatewayRequest g_pending_gateway;
static uint32_t g_valorant_pid_fwd = 0;
static void StopVgk();
struct RandomizedHardwareProfile {
  char cpu_brand[32];
  char cpu_model[128];
  uint32_t cpu_cores;
  char gpu_brand[32];
  char gpu_model[128];
  char bios_vendor[64];
  char bios_version[32];
  char mobo_model[64];
  char volume_serial[12];
  char machine_guid[40];
  char hostname[32];
  char os_version[20];
};

static std::string GetConfiguredGatewayMachineId();
static std::string GetCachedHwPart6();
static std::string GetStableHt();
static const RandomizedHardwareProfile &GetRandomizedHardwareProfile();
static void UpdateDisplaySessionState(const std::string &puuid,
                                      const std::string &region,
                                      const std::string &account);
static void UpdateConsoleTitle();
static void ResetGatewayReauthTimer();
static bool SmartGatewayMint(const std::string &jwt, const std::string &sid,
                             const std::string &puuid, uint32_t pid,
                             bool bypass_cooldown = false);

static void Van84Loop() {
  while (g_van84_running.load()) {
    Sleep(3000); // Reduced from 5000

    std::vector<std::string> sids;
    {
      std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
      for (auto &kv : g_session_mgr.sessions)
        sids.push_back(kv.first);
    }
    for (auto &sid : sids) {
      auto s = g_session_mgr.get(sid);
      if (!s)
        continue;
      double elapsed = NowSec() - s->hb_last_success;

      if (elapsed > 30.0 && elapsed < 90.0) { // Reduced thresholds
        Log("VAN84 preventive HB session=" + sid.substr(0, 8) +
            " elapsed=" + std::to_string((int)elapsed) + "s");
        g_session_mgr.send_heartbeat(sid, true);
      }

      if (elapsed > 90.0) { // Reduced from 120
        Log("VAN84 session stale, resetting hb_missed");
        std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
        s->hb_missed = 0;
        s->emergency_mode = false;
        s->burst_counter = 0;
      }

      if (s->session_hardened) {
        std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
        s->last_keepalive_boost = NowSec();
        s->last_activity = NowSec();
      }
    }
  }
}

static void HeartbeatLoop() {
  while (g_hb_running.load()) {
    Sleep(500); // Reduced from 1000
    std::vector<std::string> sids;
    {
      std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
      for (auto &kv : g_session_mgr.sessions)
        sids.push_back(kv.first);
    }

    for (auto &sid : sids) {
      auto s = g_session_mgr.get(sid);
      if (!s)
        continue;
      double elapsed_ms = (NowSec() - s->hb_last_sent) * 1000.0;

      if (elapsed_ms >= (double)(HB_INTERVAL_MS - 500) || s->hb_missed > 0) {
        g_session_mgr.send_heartbeat(sid, s->hb_missed > 0);
      }
    }
    g_session_mgr.expire_idle();
  }
}

struct SspiHandle {
  CredHandle cred{};
  CtxtHandle ctx{};
  bool cred_ok = false;
  bool ctx_ok = false;
  ~SspiHandle() {
    if (ctx_ok)
      DeleteSecurityContext(&ctx);
    if (cred_ok)
      FreeCredentialsHandle(&cred);
  }
};

class TlsSocket {
public:
  SOCKET s = INVALID_SOCKET;
  SspiHandle *ss = nullptr;
  std::vector<uint8_t> enc_pending, plain_pending;

  bool Connect(const char *host, uint16_t port, bool skip_verify) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
      return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    InetPtonA(AF_INET, host, &addr.sin_addr);
    if (connect(s, (sockaddr *)&addr, sizeof(addr)) != 0) {
      closesocket(s);
      s = INVALID_SOCKET;
      return false;
    }
    const DWORD t = 60000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof(t));
    ss = new SspiHandle();
    if (!Handshake(host, skip_verify)) {
      delete ss;
      ss = nullptr;
      closesocket(s);
      s = INVALID_SOCKET;
      return false;
    }
    return true;
  }

  bool Handshake(const char *host, bool skip_verify) {
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    if (skip_verify)
      sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
    TimeStamp ts{};
    if (AcquireCredentialsHandleW(nullptr, (SEC_WCHAR *)UNISP_NAME_W,
                                  SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                  nullptr, &ss->cred, &ts) != SEC_E_OK)
      return false;
    ss->cred_ok = true;
    std::vector<uint8_t> inbuf(32 * 1024), outbuf(32 * 1024);
    SecBufferDesc in_desc{};
    SecBuffer in_sec[2]{};
    DWORD ctx_attr = 0;
    bool first = true;
    const std::wstring whost(host, host + strlen(host));
    for (;;) {
      SecBuffer out_sec[1]{};
      out_sec[0].BufferType = SECBUFFER_TOKEN;
      out_sec[0].pvBuffer = outbuf.data();
      out_sec[0].cbBuffer = (ULONG)outbuf.size();
      SecBufferDesc out_desc;
      out_desc.ulVersion = SECBUFFER_VERSION;
      out_desc.cBuffers = 1;
      out_desc.pBuffers = out_sec;
      SECURITY_STATUS st = InitializeSecurityContextW(
          &ss->cred, first ? nullptr : &ss->ctx,
          const_cast<wchar_t *>(whost.c_str()),
          ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
              ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS,
          0, SECURITY_NATIVE_DREP, first ? nullptr : &in_desc, 0, &ss->ctx,
          &out_desc, &ctx_attr, &ts);
      first = false;
      if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED)
        return false;
      ss->ctx_ok = true;
      if (out_sec[0].cbBuffer && out_sec[0].pvBuffer) {
        send(s, (const char *)out_sec[0].pvBuffer, out_sec[0].cbBuffer, 0);
        FreeContextBuffer(out_sec[0].pvBuffer);
      }
      if (st == SEC_E_OK)
        return true;
      int got = recv(s, (char *)inbuf.data(), (int)inbuf.size(), 0);
      if (got <= 0)
        return false;
      in_sec[0].cbBuffer = (ULONG)got;
      in_sec[0].BufferType = SECBUFFER_TOKEN;
      in_sec[0].pvBuffer = inbuf.data();
      in_sec[1].cbBuffer = 0;
      in_sec[1].BufferType = SECBUFFER_EMPTY;
      in_sec[1].pvBuffer = nullptr;
      in_desc.ulVersion = SECBUFFER_VERSION;
      in_desc.cBuffers = 2;
      in_desc.pBuffers = in_sec;
    }
  }

  void SendAll(const uint8_t *data, size_t len) {
    SecPkgContext_StreamSizes sizes{};
    QueryContextAttributesW(&ss->ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    size_t max_chunk =
        sizes.cbMaximumMessage > 0 ? sizes.cbMaximumMessage : len;
    size_t off = 0;
    while (off < len) {
      size_t chunk = (std::min)(len - off, max_chunk);
      std::vector<uint8_t> buf(sizes.cbHeader + chunk + sizes.cbTrailer);
      memcpy(buf.data() + sizes.cbHeader, data + off, chunk);
      SecBuffer sec[4]{};
      sec[0].cbBuffer = sizes.cbHeader;
      sec[0].BufferType = SECBUFFER_STREAM_HEADER;
      sec[0].pvBuffer = buf.data();
      sec[1].cbBuffer = (ULONG)chunk;
      sec[1].BufferType = SECBUFFER_DATA;
      sec[1].pvBuffer = buf.data() + sizes.cbHeader;
      sec[2].cbBuffer = sizes.cbTrailer;
      sec[2].BufferType = SECBUFFER_STREAM_TRAILER;
      sec[2].pvBuffer = buf.data() + sizes.cbHeader + chunk;
      sec[3].cbBuffer = 0;
      sec[3].BufferType = SECBUFFER_EMPTY;
      sec[3].pvBuffer = nullptr;
      SecBufferDesc desc;
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers = 4;
      desc.pBuffers = sec;
      EncryptMessage(&ss->ctx, 0, &desc, 0);
      ULONG total = sec[0].cbBuffer + sec[1].cbBuffer + sec[2].cbBuffer;
      send(s, (const char *)buf.data(), total, 0);
      off += chunk;
    }
  }

  void Drain() {
    while (!enc_pending.empty()) {
      SecBuffer sec[4]{};
      sec[0].cbBuffer = (ULONG)enc_pending.size();
      sec[0].BufferType = SECBUFFER_DATA;
      sec[0].pvBuffer = enc_pending.data();
      for (int i = 1; i < 4; i++) {
        sec[i].cbBuffer = 0;
        sec[i].BufferType = SECBUFFER_EMPTY;
        sec[i].pvBuffer = nullptr;
      }
      SecBufferDesc desc;
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers = 4;
      desc.pBuffers = sec;
      SECURITY_STATUS st = DecryptMessage(&ss->ctx, &desc, 0, nullptr);
      if (st == SEC_E_INCOMPLETE_MESSAGE)
        break;
      if (st != SEC_E_OK)
        throw std::runtime_error("TLS decrypt failed");
      size_t extra_off = enc_pending.size(), extra_len = 0;
      for (int i = 0; i < 4; i++) {
        if (sec[i].BufferType == SECBUFFER_DATA && sec[i].cbBuffer)
          plain_pending.insert(plain_pending.end(), (uint8_t *)sec[i].pvBuffer,
                               (uint8_t *)sec[i].pvBuffer + sec[i].cbBuffer);
        if (sec[i].BufferType == SECBUFFER_EXTRA && sec[i].cbBuffer) {
          extra_off = (uint8_t *)sec[i].pvBuffer - enc_pending.data();
          extra_len = sec[i].cbBuffer;
        }
      }
      if (extra_len)
        enc_pending.assign(enc_pending.begin() + extra_off,
                           enc_pending.begin() + extra_off + extra_len);
      else
        enc_pending.clear();
    }
  }

  std::vector<uint8_t> RecvMsg() {
    for (;;) {
      Drain();
      if (plain_pending.size() >= 8) {
        uint32_t plen = ReadU32BE(plain_pending.data() + 4);
        size_t need = 8 + plen;
        if (plain_pending.size() >= need) {
          std::vector<uint8_t> msg(plain_pending.begin(),
                                   plain_pending.begin() + need);
          plain_pending.erase(plain_pending.begin(),
                              plain_pending.begin() + need);
          return msg;
        }
      }
      uint8_t chunk[16 * 1024];
      int got = recv(s, (char *)chunk, sizeof(chunk), 0);
      if (got <= 0)
        throw std::runtime_error("recv closed");
      enc_pending.insert(enc_pending.end(), chunk, chunk + got);
    }
  }

  void Close() {
    if (ss) {
      delete ss;
      ss = nullptr;
    }
    if (s != INVALID_SOCKET) {
      closesocket(s);
      s = INVALID_SOCKET;
    }
  }
};

static bool RecvExact(SOCKET s, uint8_t *buf, int n) {
  int got = 0;
  while (got < n) {
    int r = recv(s, (char *)buf + got, n - got, 0);
    if (r <= 0)
      return false;
    got += r;
  }
  return true;
}
static bool SendExact(SOCKET s, const uint8_t *buf, int n) {
  int sent = 0;
  while (sent < n) {
    int r = send(s, (char *)buf + sent, n - sent, 0);
    if (r <= 0)
      return false;
    sent += r;
  }
  return true;
}

struct ServerTlsConn {
  SOCKET sock = INVALID_SOCKET;
  CredHandle cred = {};
  CtxtHandle ctx = {};
  bool cred_ok = false, ctx_ok = false;
  std::vector<uint8_t> enc_buf, plain_buf;

  void close_handles() {
    if (ctx_ok) {
      DeleteSecurityContext(&ctx);
      ctx_ok = false;
    }
    if (cred_ok) {
      FreeCredentialsHandle(&cred);
      cred_ok = false;
    }
  }

  bool handshake(PCCERT_CONTEXT cert_ctx) {
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1;
    sc.paCred = &cert_ctx;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
    TimeStamp ts{};
    if (AcquireCredentialsHandleW(nullptr, (SEC_WCHAR *)UNISP_NAME_W,
                                  SECPKG_CRED_INBOUND, nullptr, &sc, nullptr,
                                  nullptr, &cred, &ts) != SEC_E_OK)
      return false;
    cred_ok = true;

    bool first_call = true;
    std::vector<uint8_t> inbuf(32 * 1024);
    for (;;) {
      int got = recv(sock, (char *)inbuf.data(), (int)inbuf.size(), 0);
      if (got <= 0)
        return false;

      SecBuffer in_sec[2] = {{(ULONG)got, SECBUFFER_TOKEN, inbuf.data()},
                             {0, SECBUFFER_EMPTY, nullptr}};
      SecBufferDesc in_desc = {SECBUFFER_VERSION, 2, in_sec};

      SecBuffer out_sec[1] = {{0, SECBUFFER_TOKEN, nullptr}};
      SecBufferDesc out_desc = {SECBUFFER_VERSION, 1, out_sec};

      DWORD ctx_attr = 0;
      TimeStamp ts2{};
      SECURITY_STATUS st = AcceptSecurityContext(
          &cred, first_call ? nullptr : &ctx, &in_desc,
          ASC_REQ_SEQUENCE_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM |
              ASC_REQ_ALLOCATE_MEMORY,
          SECURITY_NATIVE_DREP, &ctx, &out_desc, &ctx_attr, &ts2);
      first_call = false;
      ctx_ok = true;

      if (out_sec[0].pvBuffer && out_sec[0].cbBuffer) {
        send(sock, (const char *)out_sec[0].pvBuffer, out_sec[0].cbBuffer, 0);
        FreeContextBuffer(out_sec[0].pvBuffer);
      }
      if (st == SEC_E_OK)
        return true;
      if (st != SEC_I_CONTINUE_NEEDED)
        return false;
    }
  }

  void server_send(const std::vector<uint8_t> &data) {
    SecPkgContext_StreamSizes sizes{};
    QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    size_t off = 0, len = data.size();
    size_t max_chunk =
        sizes.cbMaximumMessage > 0 ? sizes.cbMaximumMessage : len;
    while (off < len) {
      size_t chunk = (std::min)(len - off, max_chunk);
      std::vector<uint8_t> buf(sizes.cbHeader + chunk + sizes.cbTrailer);
      memcpy(buf.data() + sizes.cbHeader, data.data() + off, chunk);
      SecBuffer sec[4]{};
      sec[0].cbBuffer = sizes.cbHeader;
      sec[0].BufferType = SECBUFFER_STREAM_HEADER;
      sec[0].pvBuffer = buf.data();
      sec[1].cbBuffer = (ULONG)chunk;
      sec[1].BufferType = SECBUFFER_DATA;
      sec[1].pvBuffer = buf.data() + sizes.cbHeader;
      sec[2].cbBuffer = sizes.cbTrailer;
      sec[2].BufferType = SECBUFFER_STREAM_TRAILER;
      sec[2].pvBuffer = buf.data() + sizes.cbHeader + chunk;
      sec[3].cbBuffer = 0;
      sec[3].BufferType = SECBUFFER_EMPTY;
      sec[3].pvBuffer = nullptr;
      SecBufferDesc desc;
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers = 4;
      desc.pBuffers = sec;
      EncryptMessage(&ctx, 0, &desc, 0);
      ULONG total = sec[0].cbBuffer + sec[1].cbBuffer + sec[2].cbBuffer;
      send(sock, (const char *)buf.data(), total, 0);
      off += chunk;
    }
  }

  void drain() {
    while (!enc_buf.empty()) {
      SecBuffer sec[4]{};
      sec[0] = {(ULONG)enc_buf.size(), SECBUFFER_DATA, enc_buf.data()};
      for (int i = 1; i < 4; i++)
        sec[i].BufferType = SECBUFFER_EMPTY;
      SecBufferDesc desc{SECBUFFER_VERSION, 4, sec};
      SECURITY_STATUS st = DecryptMessage(&ctx, &desc, 0, nullptr);
      if (st == SEC_E_INCOMPLETE_MESSAGE)
        break;
      if (st != SEC_E_OK)
        throw std::runtime_error("server TLS decrypt error");
      size_t extra_off = enc_buf.size(), extra_len = 0;
      for (int i = 0; i < 4; i++) {
        if (sec[i].BufferType == SECBUFFER_DATA && sec[i].cbBuffer)
          plain_buf.insert(plain_buf.end(), (uint8_t *)sec[i].pvBuffer,
                           (uint8_t *)sec[i].pvBuffer + sec[i].cbBuffer);
        if (sec[i].BufferType == SECBUFFER_EXTRA && sec[i].cbBuffer) {
          extra_off = (uint8_t *)sec[i].pvBuffer - enc_buf.data();
          extra_len = sec[i].cbBuffer;
        }
      }
      if (extra_len)
        enc_buf.assign(enc_buf.begin() + extra_off,
                       enc_buf.begin() + extra_off + extra_len);
      else
        enc_buf.clear();
    }
  }

  std::vector<uint8_t> recv_msg() {
    for (;;) {
      drain();
      if (plain_buf.size() >= 8) {
        uint32_t plen = ReadU32BE(plain_buf.data() + 4);
        size_t need = 8 + plen;
        if (plain_buf.size() >= need) {
          std::vector<uint8_t> msg(plain_buf.begin(), plain_buf.begin() + need);
          plain_buf.erase(plain_buf.begin(), plain_buf.begin() + need);
          return msg;
        }
      }
      uint8_t chunk[16 * 1024];
      int got = recv(sock, (char *)chunk, sizeof(chunk), 0);
      if (got <= 0)
        throw std::runtime_error("server recv closed");
      enc_buf.insert(enc_buf.end(), chunk, chunk + got);
    }
  }
};

static bool PostToGateway(const std::vector<uint8_t> &envelope,
                          const std::string &puuid, const std::string &region,
                          std::vector<uint8_t> *out_response = nullptr,
                          int vg_type = 3, bool bypass_cooldown = false);

static std::atomic_int g_active_clients(0);

static void HandleTunnelClient(SOCKET raw, PCCERT_CONTEXT cert_ctx) {
  if (g_active_clients.load() >= MAX_CLIENTS) {
    closesocket(raw);
    return;
  }
  g_active_clients++;

  ServerTlsConn conn;
  conn.sock = raw;
  std::string session_id;
  const DWORD rcvtimeo = 120000;
  setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, (char *)&rcvtimeo, sizeof(rcvtimeo));

  auto send_pkt = [&](uint32_t type, const std::vector<uint8_t> &payload = {}) {
    auto pkt = PackMsg(type, payload);
    conn.server_send(pkt);
  };
  auto send_err = [&](const char *msg) {
    std::vector<uint8_t> e(msg, msg + strlen(msg));
    send_pkt(MSG_ERROR, e);
  };

  try {
    if (!conn.handshake(cert_ctx))
      throw std::runtime_error("TLS handshake failed");
    Log("[SRV] client connected");

    for (;;) {
      auto msg = conn.recv_msg();
      uint32_t mt = ReadU32BE(msg.data());
      uint32_t plen = ReadU32BE(msg.data() + 4);
      std::vector<uint8_t> payload(msg.begin() + 8, msg.end());

      if (mt == MSG_SESSION_AUTH) {
        size_t off = 0;
        std::string auth_key = ParseLPStr(payload, off);
        auto gw_machine_id = ParseLPBytes(payload, off);
        std::string jwt = ParseLPStr(payload, off);
        std::string puuid = ParseLPStr(payload, off);
        uint32_t val_pid =
            (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0;
        off += 4;
        int64_t client_ts_ms = (off + 8 <= payload.size())
                                   ? (int64_t)ReadU64BE(payload.data() + off)
                                   : 0;
        off += 8;
        std::string region = ParseLPStr(payload, off);
        auto hwid_fp = ParseLPBytes(payload, off);
        std::string riot_acct = ParseLPStr(payload, off);
        std::string hostname = ParseLPStr(payload, off);

        if (auth_key != AUTH_KEY) {
          Log("[SRV] SESSION_AUTH auth_failed");
          send_err("auth_failed");
          break;
        }
        if (jwt.empty()) {
          send_err("jwt_empty");
          continue;
        }

        if (region.empty())
          region = ShardFromJwtRobust(jwt);
        if (region.empty()) {
          std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
          region = g_cached_region.empty()
                       ? (g_selected_region.empty() ? "ap" : g_selected_region)
                       : g_cached_region;
        }
        region = ApplyConfiguredRegion(region, "[SRV] SESSION_AUTH");
        {
          std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
          if (!region.empty()) {
            g_cached_region = region;
            g_selected_region = region;
          }
        }
        if (riot_acct.empty())
          riot_acct = AccountFromJwt(jwt);
        if (puuid.empty())
          puuid = PuuidFromJwt(jwt);

        std::string client_ip = "127.0.0.1";
        session_id = g_session_mgr.create_session(
            jwt, puuid, region, riot_acct, hostname, client_ip, gw_machine_id,
            hwid_fp, val_pid, client_ts_ms);

        const auto &_hwp1 = GetRandomizedHardwareProfile();
        auto gw_envelope = VGW::BuildGatewayAuthPayload(
            jwt, puuid, GetConfiguredGatewayMachineId(), GetStableHt(), "",
            _hwp1.cpu_brand, _hwp1.cpu_model, _hwp1.gpu_brand, _hwp1.gpu_model, "Windows 10 Pro",
            _hwp1.os_version);
        if (gw_envelope.empty()) {
          gw_envelope =
              g_session_mgr.send_heartbeat(session_id, true, IOCTL_VGK_HB, {});
          Log("[SRV] SESSION_AUTH_OK using vgk fallback envelope for session=" +
              session_id.substr(0, 8));
        }

        std::vector<uint8_t> ok_payload;
        PushLenStr(ok_payload, session_id);
        PushU32BE(ok_payload, (uint32_t)gw_envelope.size());
        ok_payload.insert(ok_payload.end(), gw_envelope.begin(),
                          gw_envelope.end());
        send_pkt(MSG_SESSION_AUTH_OK, ok_payload);
        Log("[SRV] SESSION_AUTH_OK session=" + session_id.substr(0, 8) +
            " gw_envelope=" + std::to_string(gw_envelope.size()) + "B");
      } else if (mt == MSG_HELLO) {
        send_err("use_session_auth");
      } else if (mt == MSG_SYNC) {
        if (session_id.empty()) {
          send_err("not_authenticated");
          continue;
        }
        size_t off = 0;
        std::string sync_sid = ParseLPStr(payload, off);
        uint64_t last_seq =
            (off + 8 <= payload.size()) ? ReadU64BE(payload.data() + off) : 0;
        session_id = sync_sid;
        if (!g_session_mgr.is_active(session_id))
          continue;
        g_session_mgr.touch(session_id);
        auto buffered = g_session_mgr.get_buffered(session_id, last_seq + 1);
        Log("[SRV] SYNC session=" + session_id.substr(0, 8) +
            " buffered=" + std::to_string(buffered.size()));
        for (auto &[seq, data] : buffered) {
          std::vector<uint8_t> hb_pkt;
          PushU64BE(hb_pkt, seq);
          PushU32BE(hb_pkt, (uint32_t)data.size());
          hb_pkt.insert(hb_pkt.end(), data.begin(), data.end());
          send_pkt(MSG_HB_BUFFER, hb_pkt);
        }
      } else if (mt == MSG_IOCTL) {
        if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
          send_err("not_authenticated");
          continue;
        }
        size_t off = 0;
        uint32_t ioctl_code =
            (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0;
        off += 4;
        uint32_t dlen =
            (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0;
        off += 4;
        std::vector<uint8_t> idata(payload.begin() + off,
                                   payload.begin() + off + dlen);
        g_session_mgr.touch(session_id);
        std::vector<uint8_t> resp;
        if ((ioctl_code >> 16) == 0x22 || ioctl_code == IOCTL_VGK_HB)
          resp =
              g_session_mgr.send_heartbeat(session_id, true, ioctl_code, idata);
        else
          resp = g_session_mgr.send_heartbeat(session_id, false, ioctl_code,
                                              idata);
        g_session_mgr.note_ioctl(session_id, ioctl_code, (int)idata.size(),
                                 (int)resp.size());
        std::vector<uint8_t> resp_pkt;
        PushU32BE(resp_pkt, (uint32_t)resp.size());
        resp_pkt.insert(resp_pkt.end(), resp.begin(), resp.end());
        send_pkt(MSG_IOCTL_RESP, resp_pkt);
      } else if (mt == MSG_PING) {
        if (!session_id.empty() && g_session_mgr.is_active(session_id))
          g_session_mgr.note_ping(session_id);
        send_pkt(MSG_PONG);
      } else if (mt == MSG_JWT_UPDATE) {
        if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
          send_err("not_authenticated");
          continue;
        }
        size_t off = 0;
        std::string new_jwt = ParseLPStr(payload, off);
        std::string new_puuid = ParseLPStr(payload, off);
        if (new_jwt.empty()) {
          send_err("jwt_empty");
          continue;
        }
        if (g_session_mgr.update_jwt(session_id, new_jwt, new_puuid))
          send_pkt(MSG_JWT_OK);
        else
          send_err("session_missing");
      } else if (mt == MSG_PIPE_AUTH) {
        if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
          send_err("not_authenticated");
          continue;
        }
        uint32_t val_pid =
            (payload.size() >= 4) ? ReadU32BE(payload.data()) : 0;
        g_session_mgr.note_pipe_auth(session_id, val_pid);
        send_pkt(MSG_PIPE_AUTH_OK);
      } else if (mt == MSG_SESSION_ACCESS) {
        if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
          send_err("not_authenticated");
          continue;
        }
        auto s = g_session_mgr.get(session_id);
        if (!s) {
          send_err("session_missing");
          continue;
        }

        std::string sid_out;
        auto envelope = ParseSessionGatewayBody(payload, &sid_out);
        if (envelope.empty()) {
          send_err("empty_envelope");
          continue;
        }

        Log("[SRV] SESSION_ACCESS envelope=" + std::to_string(envelope.size()) +
            "B session=" + session_id.substr(0, 8));

        std::string server_pub_out, token_out;
        auto access_envelope =
            VGW::BuildGatewayAccessPayload(envelope, server_pub_out, token_out);
        if (access_envelope.empty()) {
          send_err("access_payload_failed");
          continue;
        }

        std::vector<uint8_t> access_resp;
        bool ok = PostToGateway(access_envelope, s->puuid, s->region,
                                &access_resp, 4);
        if (!ok || access_resp.empty()) {
          Log("[SRV] SESSION_ACCESS PostToGateway failed, attempting fallback "
              "chain");
          {
            std::lock_guard<std::mutex> lk(g_gw_auth_response_mtx);
            if (!g_gw_auth_response.empty()) {
              access_resp = g_gw_auth_response;
              Log("[SRV] SESSION_ACCESS fallback 1: using cached "
                  "g_gw_auth_response (" +
                  std::to_string(access_resp.size()) + "B)");
            }
          }
          if (access_resp.empty()) {
            access_resp = g_fallback.get(session_id);
            if (!access_resp.empty()) {
              Log("[SRV] SESSION_ACCESS fallback 1: using g_fallback cache (" +
                  std::to_string(access_resp.size()) + "B)");
            }
          }
          if (access_resp.empty()) {
            Log("[SRV] SESSION_ACCESS fallback 2: triggering send_heartbeat");
            access_resp = g_session_mgr.send_heartbeat(session_id, true);
            if (!access_resp.empty()) {
              Log("[SRV] SESSION_ACCESS fallback 2: send_heartbeat returned (" +
                  std::to_string(access_resp.size()) + "B)");
            }
          }
          if (access_resp.empty()) {
            Log("[SRV] SESSION_ACCESS fallback chain exhausted: returning "
                "gateway_access_failed");
            send_err("gateway_access_failed");
            continue;
          }
        }

        g_data_analysis_mgr.ProcessReceivedData(access_resp,
                                                "MSG_SESSION_ACCESS");
        std::vector<uint8_t> ok_payload;
        PushLenStr(ok_payload, session_id);
        PushU32BE(ok_payload, (uint32_t)access_resp.size());
        ok_payload.insert(ok_payload.end(), access_resp.begin(),
                          access_resp.end());
        send_pkt(MSG_SESSION_ACCESS_OK, ok_payload);
        Log("[SRV] SESSION_ACCESS_OK session=" + session_id.substr(0, 8) +
            " resp=" + std::to_string(access_resp.size()) + "B");
      } else if (mt == MSG_SESSION_HEARTBEAT) {
        if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
          send_err("not_authenticated");
          continue;
        }
        auto s = g_session_mgr.get(session_id);
        if (!s) {
          send_err("session_missing");
          continue;
        }

        std::string sid_out;
        auto prev_resp = ParseSessionGatewayBody(payload, &sid_out);
        if (prev_resp.empty()) {
          send_err("empty_envelope");
          continue;
        }

        Log("[SRV] SESSION_HEARTBEAT session=" + session_id.substr(0, 8) +
            " prev_resp=" + std::to_string(prev_resp.size()) + "B");

        std::string server_pub_out;
        auto hb_envelope =
            VGW::BuildGatewayHeartbeatPayload(prev_resp, server_pub_out);
        if (hb_envelope.empty()) {
          send_err("hb_payload_failed");
          continue;
        }

        std::vector<uint8_t> hb_resp;
        bool ok = PostToGateway(hb_envelope, s->puuid, s->region, &hb_resp, 7);
        if (!ok || hb_resp.empty()) {
          hb_resp = g_fallback.get(session_id);
          if (hb_resp.empty()) {
            send_err("gateway_hb_failed");
            continue;
          }
          Log("[SRV] SESSION_HEARTBEAT using fallback cache session=" +
              session_id.substr(0, 8));
        }

        g_fallback.update(session_id, hb_resp);
        g_session_mgr.send_heartbeat(session_id, true);
        g_data_analysis_mgr.ProcessReceivedData(hb_resp,
                                                "MSG_SESSION_HEARTBEAT");

        std::vector<uint8_t> ok_payload;
        PushLenStr(ok_payload, session_id);
        PushU32BE(ok_payload, (uint32_t)hb_resp.size());
        ok_payload.insert(ok_payload.end(), hb_resp.begin(), hb_resp.end());
        send_pkt(MSG_SESSION_HEARTBEAT_OK, ok_payload);
        Log("[SRV] SESSION_HEARTBEAT_OK session=" + session_id.substr(0, 8) +
            " resp=" + std::to_string(hb_resp.size()) + "B");
      } else {
        Log("[SRV] unknown msg type=" + std::to_string(mt));
      }
    }
  } catch (const std::exception &e) {
    Log("[SRV] client exception: " + std::string(e.what()));
  }

  if (!session_id.empty())
    Log("[SRV] connection closed session=" + session_id.substr(0, 8) +
        " (session stays)");
  conn.close_handles();
  closesocket(raw);
  g_active_clients--;
}

static void RunAttribCmd(const std::string &args) {
  std::string cmd = std::string(xorstr_("cmd.exe /c attrib ")) + args;
  STARTUPINFOA si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi{};
  if (CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                     CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
}

static std::string GetPfxPath() {
  char exePath[MAX_PATH] = {};
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  std::string p(exePath);
  auto slash = p.find_last_of(xorstr_("\\/"));
  if (slash != std::string::npos)
    p = p.substr(0, slash + 1);
  p += xorstr_("server.pfx");
  return p;
}

static PCCERT_CONTEXT LoadOrCreateCert() {
  std::string pfxPath = GetPfxPath();

  RunAttribCmd(xorstr_("-h -s \"") + pfxPath + "\"");
  DeleteFileA(pfxPath.c_str());

  Log(xorstr_("[SRV] server.pfx deleted, generating new self-signed cert"));
  HCERTSTORE myStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                                     CERT_STORE_CREATE_NEW_FLAG, nullptr);
  if (!myStore) {
    Log(xorstr_("[SRV] CertOpenStore failed"));
    return nullptr;
  }

  CERT_NAME_BLOB nameBlob{};
  const char *subj = xorstr_("CN=DndVanguardServer");
  DWORD nameLen = 0;
  CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, nullptr, nullptr,
                 &nameLen, nullptr);
  std::vector<BYTE> nameBuf(nameLen);
  CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, nullptr,
                 nameBuf.data(), &nameLen, nullptr);
  nameBlob.cbData = nameLen;
  nameBlob.pbData = nameBuf.data();

  CRYPT_KEY_PROV_INFO kpi{};
  kpi.pwszContainerName = const_cast<wchar_t *>(L"DndVanguardSrv");
  kpi.pwszProvName = nullptr;
  kpi.dwProvType = PROV_RSA_FULL;
  kpi.dwFlags = CRYPT_MACHINE_KEYSET;
  kpi.dwKeySpec = AT_KEYEXCHANGE;

  SYSTEMTIME st_start{}, st_end{};
  GetSystemTime(&st_start);
  st_end = st_start;
  st_end.wYear += 10;

  PCCERT_CONTEXT ctx = CertCreateSelfSignCertificate(
      0, &nameBlob, 0, &kpi, nullptr, &st_start, &st_end, nullptr);
  if (!ctx) {
    Log(xorstr_("[SRV] CertCreateSelfSignCertificate failed err=") +
        std::to_string(GetLastError()));
    return nullptr;
  }

  CRYPT_DATA_BLOB pfx{};
  if (PFXExportCertStore(myStore, &pfx, L"", EXPORT_PRIVATE_KEYS)) {
    std::vector<BYTE> buf(pfx.cbData);
    pfx.pbData = buf.data();
    if (PFXExportCertStore(myStore, &pfx, L"", EXPORT_PRIVATE_KEYS)) {
      std::ofstream out(pfxPath, std::ios::binary);
      out.write((char *)buf.data(), buf.size());
      out.close();
      Log(xorstr_("[SRV] Saved server.pfx"));
      RunAttribCmd(xorstr_("+h +s \"") + pfxPath + "\"");
    }
  }
  CertCloseStore(myStore, 0);
  Log(xorstr_("[SRV] Self-signed cert created"));
  return ctx;
}

static std::atomic_bool g_server_running(false);
static void RunServer() {
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);

  PCCERT_CONTEXT cert = LoadOrCreateCert();
  if (!cert) {
    Log("[SRV] Cannot load cert — server abort");
    return;
  }

  SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  const int one = 1;
  setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(SERVER_PORT);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind(listen_sock, (sockaddr *)&addr, sizeof(addr)) != 0) {
    Log("[SRV] bind failed err=" + std::to_string(WSAGetLastError()));
    return;
  }
  listen(listen_sock, 64);
  Log("[SRV] TLS listening 127.0.0.1:" + std::to_string(SERVER_PORT));

  g_hb_running.store(true);
  g_van84_running.store(true);
  std::thread(HeartbeatLoop).detach();
  std::thread(Van84Loop).detach();
  StartTaskProbeDispatcher();

  while (g_server_running.load()) {
    sockaddr_in cli_addr{};
    int cli_len = sizeof(cli_addr);
    SOCKET cli = accept(listen_sock, (sockaddr *)&cli_addr, &cli_len);
    if (cli == INVALID_SOCKET)
      continue;
    std::thread(HandleTunnelClient, cli, cert).detach();
  }

  g_hb_running = false;
  g_van84_running = false;
  closesocket(listen_sock);
  CertFreeCertificateContext(cert);
  Log("[SRV] Server stopped");
}

static std::atomic_bool g_shutdown(false);
static std::atomic_bool g_api_called(false);
static std::atomic<void *> g_current_pipe(nullptr);
static uint32_t g_valorant_pid = 0;

static std::atomic_bool g_gw_auto_posted(false);

static std::atomic_int g_val_loading_pct(0);
static std::atomic_bool g_session_reset_in_progress(false);
static std::atomic<double> g_gw_cooldown_until_sec{0.0};

static bool IsGatewayInCooldown() {
  double now = NowSec();
  double cd = g_gw_cooldown_until_sec.load();
  if (now < cd) {
    double rem = cd - now;
    Log("[GW] Throttled: Gateway in HTTP 429 rate-limit cooldown for " +
        std::to_string((int)ceil(rem)) + "s");
    return true;
  }
  return false;
}

static void SetGatewayCooldown(double seconds = 60.0) {
  double until = NowSec() + seconds;
  g_gw_cooldown_until_sec.store(until);
  Log("[GW] HTTP 429 Rate limit encountered. Setting gateway cooldown for " +
      std::to_string((int)seconds) + "s.");
}

static void AutoResetSession() {
  g_session_reset_needed.store(false);

  // FIX 3: Check if game process is running before allowing reset
  uint32_t val_pid = GetValorantPID();
  if (val_pid == 0) {
    Log("[RESET][WARNING] Reset skipped: Game process "
        "(VALORANT-Win64-Shipping.exe) is not running!");
    // Distinct beep pattern for skip (warning tones)
    Beep(440, 150);
    Sleep(100);
    Beep(330, 250);
    return;
  }

  // FIX 4: Validate cached credentials before using
  if (!ValidateCachedCredentials()) {
    Log("[RESET] Cached credentials invalid or expired -> clearing cache to "
        "await new data capture");
    ClearCachedCredentials();
  }

  auto start_tp = std::chrono::steady_clock::now();
  Log("[RESET] AutoResetSession starting for PID " + std::to_string(val_pid) +
      "...");
  g_session_reset_in_progress.store(true);
  g_gw_cooldown_until_sec.store(0.0);

  // Save credentials BEFORE reset
  std::string saved_jwt, saved_puuid, saved_sid, saved_region;
  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    saved_jwt = g_cached_jwt;
    saved_puuid = g_cached_puuid;
    saved_sid = g_cached_sid;
    saved_region = g_cached_region;
  }

  // 1. Clear session manager
  Log("[RESET] Step 1/7: Clearing session manager...");
  g_session_mgr.clear();

  // 2. Reset gateway session & auth response
  Log("[RESET] Step 2/7: Resetting gateway session and auth responses...");
  {
    std::lock_guard<std::mutex> lk(g_gw_session_mtx);
    g_gw_session.Reset();
  }
  {
    std::lock_guard<std::mutex> lk(g_gw_auth_response_mtx);
    g_gw_auth_response.clear();
  }
  g_gw_auto_posted.store(false);

  // 3. Preserve cached credentials (jwt, puuid, sid, region)
  Log("[RESET] Step 3/7: Preserving cached credentials (jwt, puuid, sid, "
      "region)...");

  // 4. Clear VGK payload, FallbackCache, and error counters (keep pipe
  // connected!)
  Log("[RESET] Step 4/7: Resetting VGK payload, FallbackCache, and error "
      "counters (keeping pipe connected)...");
  {
    std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
    g_vgk_payload.clear();
  }

  // Do NOT disconnect named pipe; keep g_current_pipe open for continuous data
  // flow
  Log("[RESET] Named pipe connection (g_current_pipe) kept open.");

  // Reset FallbackCache & error counters
  g_fallback.clear();
  Log("[RESET] FallbackCache cleared.");
  g_102_count.store(0);
  g_reauth_fail_count.store(0);
  g_keepalive_fail_count.store(0);
  Log("[RESET] Error counters reset to 0.");

  // Log Valorant PID
  if (val_pid != 0) {
    Log("[RESET] Valorant process running with PID: " +
        std::to_string(val_pid));
  } else {
    Log("[RESET] Valorant process not found (PID: 0).");
  }

  // 5. Restart VGC service (sc stop vgc, sleep 3000, sc start vgc, sleep 3000)
  g_vgc_service_running = IsVgcServiceRunning();
  Log("[RESET] Step 5/7: VGC service status before restart: " +
      GetVgcServiceStatusStr() +
      " (running=" + (g_vgc_service_running ? "true" : "false") + ")");
  Log("[RESET] Stopping VGC service (sc stop vgc)...");
  system("sc stop vgc >nul 2>&1");
  Log("[RESET] Sleeping 3000ms after sc stop vgc...");
  Sleep(3000);
  Log("[RESET] Starting VGC service (sc start vgc)...");
  system("sc start vgc >nul 2>&1");
  Log("[RESET] Sleeping 3000ms after sc start vgc...");
  Sleep(3000);
  g_vgc_service_running = IsVgcServiceRunning();
  Log("[RESET] VGC service status after restart: " + GetVgcServiceStatusStr() +
      " (running=" + (g_vgc_service_running ? "true" : "false") + ")");

  // 6. Flush DNS cache twice (with Sleep 500 in between)
  Log("[RESET] Step 6/7: Flushing DNS cache (pass 1)...");
  flush_dns_cache();
  Log("[RESET] Sleeping 500ms between DNS flushes...");
  Sleep(500);
  Log("[RESET] Step 6/7: Flushing DNS cache (pass 2)...");
  flush_dns_cache();

  // Re-create session using saved credentials via SmartGatewayMint
  if (!saved_jwt.empty()) {
    Log("[RESET] Re-creating session using saved credentials via "
        "SmartGatewayMint...");
    bool mint_ok =
        SmartGatewayMint(saved_jwt, saved_sid, saved_puuid, val_pid, true);
    if (mint_ok) {
      std::string target_sid = saved_sid.empty() ? g_cached_sid : saved_sid;
      Log("[RESET] SmartGatewayMint re-creation succeeded! Forcing immediate "
          "heartbeat on session=" +
          target_sid);
      if (!target_sid.empty()) {
        g_session_mgr.send_heartbeat(target_sid, true);
      }
    } else {
      Log("[RESET] SmartGatewayMint re-creation returned false.");
    }
  } else {
    Log("[RESET] No saved JWT credentials available to re-create session.");
  }

  // 7. Sound notification
  Log("[RESET] Step 7/7: Sound notification (double beep)...");
  Beep(880, 100);
  Sleep(100);
  Beep(880, 100);

  auto end_tp = std::chrono::steady_clock::now();
  auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_tp - start_tp)
          .count();
  Log("[RESET] AutoResetSession finished in " + std::to_string(elapsed_ms) +
      " ms.");
  g_session_reset_in_progress.store(false);

  // Launch background thread to force heartbeat on all sessions post-reset with
  // retries FIX 1: Do NOT use stale saved_sid from before reset. Use new SIDs
  // from session manager / updated g_cached_sid.
  std::thread([]() {
    Log("[RESET] Post-reset background force-heartbeat thread starting");
    Sleep(1000);
    auto sids = g_session_mgr.get_all_sids();
    if (sids.empty() && !g_cached_sid.empty()) {
      sids.push_back(g_cached_sid);
    }
    for (const auto &sid : sids) {
      if (sid.empty())
        continue;
      bool ok = false;
      for (int retry = 1; retry <= 3; ++retry) {
        Log("[RESET] Force heartbeat attempt " + std::to_string(retry) +
            "/3 for session " + (sid.size() > 8 ? sid.substr(0, 8) : sid));
        auto resp = g_session_mgr.send_heartbeat(sid, true);
        if (!resp.empty()) {
          ok = true;
          Log("[RESET] Force heartbeat succeeded for session " +
              (sid.size() > 8 ? sid.substr(0, 8) : sid));
          break;
        }
        Sleep(500 * retry);
      }
      if (!ok) {
        Log("[RESET] Force heartbeat failed after 3 attempts for session " +
            (sid.size() > 8 ? sid.substr(0, 8) : sid));
      }
    }
  }).detach();
}

static std::string Base64Encode(const uint8_t *data, size_t len) {
  static const char *tbl =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, valb = -6;
  for (size_t i = 0; i < len; i++) {
    val = (val << 8) + data[i];
    valb += 8;
    while (valb >= 0) {
      out += tbl[(val >> valb) & 0x3F];
      valb -= 6;
    }
  }
  if (valb > -6)
    out += tbl[((val << 8) >> (valb + 8)) & 0x3F];
  while (out.size() % 4)
    out += '=';
  return out;
}

static std::string RegReadStr(HKEY root, const wchar_t *sub,
                              const wchar_t *val) {
  HKEY hk = nullptr;
  if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS)
    return {};
  wchar_t buf[512]{};
  DWORD sz = sizeof(buf);
  RegQueryValueExW(hk, val, nullptr, nullptr, (LPBYTE)buf, &sz);
  RegCloseKey(hk);
  std::string out;
  for (int i = 0; buf[i] && i < 256; i++)
    out += (char)(buf[i] & 0xFF);
  return out;
}

static std::vector<uint8_t> GetRealHwid() {
  std::string bios_vendor =
      RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                 L"BIOSVendor");
  std::string bios_ver =
      RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                 L"BIOSVersion");
  std::string bios =
      bios_vendor.empty() ? bios_ver : (bios_vendor + " " + bios_ver);
  if (bios.empty())
    bios =
        RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                   L"SystemProductName");
  std::string cpu = RegReadStr(
      HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
      L"ProcessorNameString");
  if (cpu.empty())
    cpu = RegReadStr(HKEY_LOCAL_MACHINE,
                     L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                     L"Identifier");
  wchar_t sysRoot[MAX_PATH]{};
  GetSystemDirectoryW(sysRoot, MAX_PATH);
  sysRoot[3] = L'\0';
  DWORD volSerial = 0;
  GetVolumeInformationW(sysRoot, nullptr, 0, &volSerial, nullptr, nullptr,
                        nullptr, 0);
  char volBuf[16];
  sprintf_s(volBuf, "%08X", volSerial);
  std::string guid = RegReadStr(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
  std::string composite = "BIOS:" + bios + "|CPU:" + cpu +
                          "|VOL:" + std::string(volBuf) + "|MGUID:" + guid;
  Log("[HWID] composite: " + composite.substr(0, 80) + "...");
  std::vector<uint8_t> hash(32, 0);
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  DWORD hashLen = 32;
  CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES,
                       CRYPT_VERIFYCONTEXT);
  CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
  CryptHashData(hHash, (BYTE *)composite.data(), (DWORD)composite.size(), 0);
  CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
  CryptDestroyHash(hHash);
  CryptReleaseContext(hProv, 0);
  std::ostringstream hex;
  for (auto b : hash)
    hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
  Log("[HWID] sha256=" + hex.str());
  return hash;
}

static std::string BytesToHexString(const std::vector<uint8_t> &bytes);

static std::wstring GetHwidProfilePath() {
  wchar_t path[MAX_PATH] = {};
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  wchar_t *last = wcsrchr(path, L'\\');
  if (last)
    *(last + 1) = L'\0';
  wcscat_s(path, L"hwid_profile.bin");
  return path;
}

static bool SaveHwidProfile(const RandomizedHardwareProfile &p) {
  static const uint32_t MAGIC = 0x44495748;
  static const uint32_t VER = 5;
  auto path = GetHwidProfilePath();
  HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  DWORD written = 0;
  WriteFile(h, &MAGIC, 4, &written, nullptr);
  WriteFile(h, &VER, 4, &written, nullptr);
  uint32_t sz = sizeof(p);
  WriteFile(h, &sz, 4, &written, nullptr);
  WriteFile(h, &p, sz, &written, nullptr);
  CloseHandle(h);
  return written == sz;
}

static bool LoadHwidProfile(RandomizedHardwareProfile &p) {
  static const uint32_t MAGIC = 0x44495748;
  static const uint32_t VER = 5;
  auto path = GetHwidProfilePath();
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  uint32_t magic = 0, ver = 0, sz = 0;
  DWORD read = 0;
  ReadFile(h, &magic, 4, &read, nullptr);
  ReadFile(h, &ver, 4, &read, nullptr);
  ReadFile(h, &sz, 4, &read, nullptr);
  if (magic != MAGIC || ver != VER || sz != sizeof(p)) {
    CloseHandle(h);
    return false;
  }
  ReadFile(h, &p, sz, &read, nullptr);
  CloseHandle(h);
  return read == sz;
}

static const RandomizedHardwareProfile &GetRandomizedHardwareProfile() {
  static RandomizedHardwareProfile profile{};
  static bool initialized = false;
  if (initialized)
    return profile;

  struct CpuEntry {
    const char *brand;
    const char *cpuid;
    const char *model;
    uint32_t cores;
    int intel;
  };
  static const CpuEntry cpus[] = {
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz", 6,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz", 12,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz", 8,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz", 16,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i5-11400F CPU @ 2.60GHz", 12,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz", 16,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i5-12400F CPU @ 2.50GHz", 12,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz", 20,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i9-12900K CPU @ 3.20GHz", 24,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i5-13400F CPU @ 2.50GHz", 16,
       1},
      {"GenuineIntel", "Intel", "Intel(R) Core(TM) i7-13700K CPU @ 3.40GHz", 24,
       1},
      {"AuthenticAMD", "AMD", "AMD Ryzen 5 3600 6-Core Processor", 12, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 7 3700X 8-Core Processor", 16, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 5 5600X 6-Core Processor", 12, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 7 5700X 8-Core Processor", 16, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 7 5800X 8-Core Processor", 16, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 9 5900X 12-Core Processor", 24, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 5 7600X 6-Core Processor", 12, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 7 7700X 8-Core Processor", 16, 0},
      {"AuthenticAMD", "AMD", "AMD Ryzen 9 7900X 12-Core Processor", 24, 0},
  };

  struct GpuEntry {
    const char *brand;
    const char *model;
  };
  static const GpuEntry gpus[] = {
      {"NVIDIA", "NVIDIA GeForce GTX 1660 SUPER"},
      {"NVIDIA", "NVIDIA GeForce GTX 1660 Ti"},
      {"NVIDIA", "NVIDIA GeForce RTX 2060"},
      {"NVIDIA", "NVIDIA GeForce RTX 2070 SUPER"},
      {"NVIDIA", "NVIDIA GeForce RTX 3060"},
      {"NVIDIA", "NVIDIA GeForce RTX 3060 Ti"},
      {"NVIDIA", "NVIDIA GeForce RTX 3070"},
      {"NVIDIA", "NVIDIA GeForce RTX 3080"},
      {"NVIDIA", "NVIDIA GeForce RTX 4060"},
      {"NVIDIA", "NVIDIA GeForce RTX 4060 Ti"},
      {"NVIDIA", "NVIDIA GeForce RTX 4070"},
      {"AMD", "AMD Radeon RX 6600"},
      {"AMD", "AMD Radeon RX 6600 XT"},
      {"AMD", "AMD Radeon RX 6700 XT"},
      {"AMD", "AMD Radeon RX 6800 XT"},
      {"AMD", "AMD Radeon RX 7600"},
      {"AMD", "AMD Radeon RX 7700 XT"},
  };

  struct MoboEntry {
    int intel;
    const char *vendor;
    const char *model;
    const char *bios_ver;
  };
  static const MoboEntry mobos[] = {
      {1, "American Megatrends Inc.", "ASUS PRIME Z490-P", "0501"},
      {1, "American Megatrends Inc.", "ASUS ROG STRIX Z490-F", "0603"},
      {1, "American Megatrends Inc.", "ASUS PRIME Z590-P", "0606"},
      {1, "American Megatrends Inc.", "ASUS TUF GAMING Z590", "1401"},
      {1, "American Megatrends Inc.", "ASUS PRIME Z690-P", "1201"},
      {1, "American Megatrends Inc.", "ASUS ROG STRIX Z690-F", "1403"},
      {1, "American Megatrends Inc.", "MSI MAG Z490 TOMAHAWK", "A.40"},
      {1, "American Megatrends Inc.", "MSI MPG Z590 GAMING", "A.60"},
      {1, "American Megatrends Inc.", "MSI MAG Z690 TOMAHAWK", "A.80"},
      {1, "American Megatrends Inc.", "Gigabyte Z490 AORUS", "F60"},
      {1, "American Megatrends Inc.", "Gigabyte Z590 AORUS", "F65"},
      {1, "American Megatrends Inc.", "Gigabyte Z690 AORUS", "F10"},
      {0, "American Megatrends Inc.", "ASUS ROG STRIX X570-E", "2606"},
      {0, "American Megatrends Inc.", "ASUS TUF GAMING X570", "2803"},
      {0, "American Megatrends Inc.", "ASUS PRIME B550-PLUS", "2402"},
      {0, "American Megatrends Inc.", "MSI MAG X570 TOMAHAWK", "A.60"},
      {0, "American Megatrends Inc.", "MSI MPG B550 GAMING", "A.40"},
      {0, "American Megatrends Inc.", "Gigabyte X570 AORUS", "F34"},
      {0, "American Megatrends Inc.", "Gigabyte B550 AORUS", "F17"},
      {0, "American Megatrends Inc.", "ASRock X570 Phantom", "P4.10"},
  };

  std::vector<uint8_t> seed(64, 0);
  BCryptGenRandom(nullptr, seed.data(), (ULONG)seed.size(),
                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);

  const auto &cpu = cpus[seed[0] % (sizeof(cpus) / sizeof(cpus[0]))];
  const auto &gpu = gpus[seed[1] % (sizeof(gpus) / sizeof(gpus[0]))];

  const MoboEntry *matched[20];
  int mc = 0;
  for (auto &m : mobos)
    if (m.intel == cpu.intel && mc < 20)
      matched[mc++] = &m;
  const auto &mobo = *matched[seed[2] % mc];

  strcpy_s(profile.cpu_brand, cpu.cpuid);
  strcpy_s(profile.cpu_model, cpu.model);
  profile.cpu_cores = cpu.cores;
  strcpy_s(profile.gpu_brand, gpu.brand);
  strcpy_s(profile.gpu_model, gpu.model);
  strcpy_s(profile.bios_vendor, mobo.vendor);
  strcpy_s(profile.bios_version, mobo.bios_ver);
  strcpy_s(profile.mobo_model, mobo.model);

  sprintf_s(
      profile.volume_serial, "%08X",
      (uint32_t)((seed[4] << 24) | (seed[5] << 16) | (seed[6] << 8) | seed[7]));

  sprintf_s(
      profile.machine_guid,
      "%02x%02x%02x%02x-%02x%02x-4%01x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      seed[8], seed[9], seed[10], seed[11], seed[12], seed[13], seed[14] & 0x0F,
      seed[15], (seed[16] & 0x3F) | 0x80, seed[17], seed[18], seed[19],
      seed[20], seed[21], seed[22], seed[23]);

  static const char *prefixes[] = {"DESKTOP-", "WIN-"};
  static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const char *pfx = prefixes[seed[24] % 2];
  strcpy_s(profile.hostname, pfx);
  size_t pfx_len = strlen(pfx);
  for (int i = 0; i < 7; i++)
    profile.hostname[pfx_len + i] =
        charset[seed[25 + i] % (sizeof(charset) - 1)];
  profile.hostname[pfx_len + 7] = '\0';

  static const char *os_builds[] = {
      "10.0.19044", "10.0.19045", "10.0.22000",
      "10.0.22621", "10.0.22631", "10.0.26100",
  };
  strcpy_s(
      profile.os_version,
      os_builds[seed[32 % 32] % (sizeof(os_builds) / sizeof(os_builds[0]))]);

  Log(std::string("[HWID] generated new profile cpu=") + profile.cpu_model +
      " os=" + profile.os_version);

  initialized = true;
  return profile;
}

static std::vector<uint8_t> GetRandomHwid() {
  const auto &profile = GetRandomizedHardwareProfile();
  std::string composite = std::string("BIOS:") + profile.bios_vendor + " " +
                          profile.bios_version + "|CPU:" + profile.cpu_model +
                          "|VOL:" + profile.volume_serial +
                          "|MGUID:" + profile.machine_guid;
  Log("[HWID] randomized composite: " + composite.substr(0, 80) + "...");

  std::vector<uint8_t> hash(32, 0);
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  DWORD hashLen = 32;
  CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES,
                       CRYPT_VERIFYCONTEXT);
  CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
  CryptHashData(hHash, (BYTE *)composite.data(), (DWORD)composite.size(), 0);
  CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
  CryptDestroyHash(hHash);
  CryptReleaseContext(hProv, 0);

  std::ostringstream hex;
  for (auto b : hash)
    hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
  Log("[HWID] randomized sha256=" + hex.str());
  return hash;
}

static std::string BytesToHexString(const std::vector<uint8_t> &bytes) {
  std::ostringstream hex;
  for (auto b : bytes)
    hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
  return hex.str();
}

static std::vector<uint8_t> GetConfiguredHwid() {
  auto hash = GetRandomHwid();
  Log("[HWID] SESSION_AUTH hwid=" + BytesToHexString(hash).substr(0, 16) +
      "...");
  return hash;
}

static std::string Md5HexUpper(const std::vector<uint8_t> &data) {
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL,
                       CRYPT_VERIFYCONTEXT);
  CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
  CryptHashData(hHash, data.data(), (DWORD)data.size(), 0);
  BYTE md5[16] = {};
  DWORD len = 16;
  CryptGetHashParam(hHash, HP_HASHVAL, md5, &len, 0);
  CryptDestroyHash(hHash);
  CryptReleaseContext(hProv, 0);
  std::ostringstream ss;
  for (int i = 0; i < 16; i++)
    ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
       << (int)md5[i];
  return ss.str();
}

static std::string GetCachedHwPart6() {
  static std::string cached_s6;
  if (!cached_s6.empty())
    return cached_s6;

  auto makeSlot = [](const std::string &entry) -> std::string {
    std::vector<uint8_t> buf(96, 0);
    size_t len = entry.size() < 96 ? entry.size() : 96;
    memcpy(buf.data(), entry.data(), len);
    return VGW::Base64Encode(buf.data(), buf.size());
  };

  auto r_pci = VGW::RandomBytes(16);
  std::ostringstream pci_ss;
  for (int i = 0; i < 16; i++) {
    if (i > 0 && i % 2 == 0)
      pci_ss << "_";
    pci_ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
           << (int)r_pci[i];
  }
  static const char *disk_models[] = {
      "SAMSUNG MZVL21T0HCLR-00B00",
      "SAMSUNG MZVLB512HAJQ-000H1",
      "WDC WDS500G2B0C-00PXH0",
      "KINGSTON SKC3000S1024G",
      "CT1000P3SSD8",
  };
  uint8_t dm_seed = 0;
  BCryptGenRandom(nullptr, &dm_seed, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  std::string slot0 = pci_ss.str() + "." + disk_models[dm_seed % 5];

  std::string empty_slot = makeSlot("");
  cached_s6 = makeSlot(slot0) + ";" + empty_slot + ";" + empty_slot + ";" +
              empty_slot + ";" + empty_slot;
  return cached_s6;
}

struct VgcMachineEntry {
  std::string machine_id;
  std::string ht;
};

static std::vector<VgcMachineEntry> g_machine_pool;
static size_t g_selected_machine_idx = (size_t)-1;
static std::mutex g_machine_pool_mtx;

static std::wstring GetOutputTxtPath() {
  wchar_t path[MAX_PATH]{};
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  wchar_t *last = wcsrchr(path, L'\\');
  if (last)
    *(last + 1) = L'\0';
  wcscat_s(path, L"output.txt");
  return path;
}

static const uint8_t HT_SUFFIX[] = {0xF4, 0xAD, 0x52, 0x9C, 0xDE, 0x17,
                                    0x0E, 0xE1, 0xD1, 0x02, 0x9B, 0x4A,
                                    0x3C, 0xA8, 0x98, 0x20};
static const char *VG_VERSION_STR = "1.18.5.11";
static const char *GAME_VERSION = "release-13.00-shipping-30-4955671";

static std::string GenRandB64(size_t n) {
  std::vector<uint8_t> buf(n);
  BCryptGenRandom(nullptr, buf.data(), (ULONG)n,
                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return Base64Encode(buf.data(), buf.size());
}

static std::string GenBuildToken6() {
  uint8_t rnd[8];
  BCryptGenRandom(nullptr, rnd, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  char hex_id[17] = {};
  for (int i = 0; i < 8; i++)
    snprintf(hex_id + i * 2, 3, "%02X", rnd[i]);

  char p0[5], p1[5], p2[5], p3[5];
  memcpy(p0, hex_id + 0, 4);
  p0[4] = 0;
  memcpy(p1, hex_id + 4, 4);
  p1[4] = 0;
  memcpy(p2, hex_id + 8, 4);
  p2[4] = 0;
  memcpy(p3, hex_id + 12, 4);
  p3[4] = 0;

  std::string prefix = std::string("0000_0000_0000_0000_") + p0 + "_" + p1 +
                       "_" + p2 + "_" + p3 + ".SAMSUNG MZVL21T0";

  uint8_t first[97] = {};
  size_t copy_len = prefix.size() < 97 ? prefix.size() : 96;
  memcpy(first, prefix.c_str(), copy_len);

  uint8_t zeros[97] = {};

  std::string seg0 = Base64Encode(first, 97);
  std::string seg_empty = Base64Encode(zeros, 97);

  return seg0 + ";" + seg_empty + ";" + seg_empty + ";" + seg_empty + ";" +
         seg_empty;
}

static std::vector<uint8_t> ComputeSha1(const uint8_t *data, size_t len) {
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
  BCRYPT_HASH_HANDLE hHash = nullptr;
  BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
  BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
  std::vector<uint8_t> hash(20);
  BCryptFinishHash(hHash, hash.data(), 20, 0);
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return hash;
}

static std::string ComputeHt(const std::string &machine_id) {
  std::map<char, std::string> tokens;
  size_t pos = 0;
  while (pos < machine_id.size()) {
    size_t bar = machine_id.find("||", pos);
    if (bar == std::string::npos)
      break;
    bar += 2;
    size_t next = machine_id.find("||", bar);
    std::string part = (next == std::string::npos)
                           ? machine_id.substr(bar)
                           : machine_id.substr(bar, next - bar);
    if (!part.empty()) {
      tokens[part[0]] = part;
    }
    pos = (next == std::string::npos) ? machine_id.size() : next;
  }

  std::string concat = tokens['6'] + tokens['1'] + tokens['2'] + tokens['3'] +
                       tokens['5'] + VG_VERSION_STR;

  std::vector<uint8_t> sha_input(concat.begin(), concat.end());
  sha_input.insert(sha_input.end(), HT_SUFFIX, HT_SUFFIX + sizeof(HT_SUFFIX));

  auto digest = ComputeSha1(sha_input.data(), sha_input.size());
  return Base64Encode(digest.data(), digest.size());
}

static VgcMachineEntry GenerateMachineEntry() {
  VgcMachineEntry e;

  std::string token1 = GenRandB64(16);
  std::string token2 = GenRandB64(64);
  std::string token3 = GenRandB64(64);
  std::string token5 = GenRandB64(6);
  std::string token6 = GenBuildToken6();

  e.machine_id = "||1;" + token1 + "||2;" + token2 + "||3;" + token3 + "||4" +
                 "||5;" + token5 + "||6;" + token6;

  e.ht = ComputeHt(e.machine_id);
  return e;
}

static bool LoadMachinePool() {
  std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
  if (!g_machine_pool.empty())
    return true;

  VgcMachineEntry e = GenerateMachineEntry();
  g_machine_pool.push_back(e);

  return true;
}

static std::wstring GetExeDirFile(const wchar_t *filename) {
  wchar_t path[MAX_PATH]{};
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  wchar_t *last = wcsrchr(path, L'\\');
  if (last)
    *(last + 1) = L'\0';
  wcscat_s(path, filename);
  return path;
}

static void EnsureMachineSelected() {
  if (g_selected_machine_idx != (size_t)-1)
    return;
  if (!LoadMachinePool() || g_machine_pool.empty()) {
    Log(xorstr_("[GW] ERROR: machine pool empty"));
    g_selected_machine_idx = 0;
    return;
  }

  size_t pool_size = g_machine_pool.size();

  uint32_t rnd = 0;
  BCryptGenRandom(nullptr, (PUCHAR)&rnd, sizeof(rnd),
                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  g_selected_machine_idx = rnd % pool_size;
  Log(xorstr_("[GW] machine idx=") + std::to_string(g_selected_machine_idx) +
      xorstr_(" selected (") + std::to_string(pool_size) +
      xorstr_(" entries)"));
}

static std::string GetConfiguredGatewayMachineId() {
  EnsureMachineSelected();
  std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
  if (g_machine_pool.empty())
    return "";
  return g_machine_pool[g_selected_machine_idx].machine_id;
}

static std::string GetStableHt() {
  EnsureMachineSelected();
  std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
  if (g_machine_pool.empty())
    return "";
  return g_machine_pool[g_selected_machine_idx].ht;
}

static std::string GetFakeHostname() {
  return GetRandomizedHardwareProfile().hostname;
}

static void GetCpuInfo(std::string &brand, std::string &model,
                       uint32_t &cores) {
  if (RandomizedVersion) {
    const auto &p = GetRandomizedHardwareProfile();
    brand = p.cpu_brand;
    model = p.cpu_model;
    cores = p.cpu_cores;
    return;
  }

  model = RegReadStr(HKEY_LOCAL_MACHINE,
                     L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                     L"ProcessorNameString");
  while (!model.empty() && (model.back() == ' ' || model.back() == '\t'))
    model.pop_back();
  brand = (model.find("Intel") != std::string::npos) ? "GenuineIntel"
          : (model.find("AMD") != std::string::npos) ? "AuthenticAMD"
                                                     : "Unknown";
  SYSTEM_INFO si{};
  GetSystemInfo(&si);
  cores = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
}

static void GetGpuInfo(std::string &brand, std::string &model) {
  if (RandomizedVersion) {
    const auto &p = GetRandomizedHardwareProfile();
    brand = p.gpu_brand;
    model = p.gpu_model;
    return;
  }

  model = RegReadStr(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-"
                     L"e325-11ce-bfc1-08002be10318}\\0000",
                     L"DriverDesc");
  if (model.empty()) {
    brand = "Unknown";
    model = "Unknown";
    Log("[HWINFO] GPU real brand=" + brand + " model=" + model);
    return;
  }
  brand = (model.find("NVIDIA") != std::string::npos) ? "NVIDIA"
          : (model.find("AMD") != std::string::npos ||
             model.find("Radeon") != std::string::npos)
              ? "AMD"
          : (model.find("Intel") != std::string::npos) ? "Intel"
                                                       : "Unknown";
}

static std::vector<uint8_t>
BcryptBlobToSpkiDer(const std::vector<uint8_t> &pubBlob) {
  auto *blob = (BCRYPT_RSAKEY_BLOB *)pubBlob.data();
  DWORD expLen = blob->cbPublicExp, modLen = blob->cbModulus;
  const uint8_t *expBytes = pubBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
  const uint8_t *modBytes = expBytes + expLen;
  auto der_len = [](size_t len, std::vector<uint8_t> &buf) {
    if (len < 0x80) {
      buf.push_back((uint8_t)len);
    } else if (len < 0x100) {
      buf.push_back(0x81);
      buf.push_back((uint8_t)len);
    } else {
      buf.push_back(0x82);
      buf.push_back((uint8_t)(len >> 8));
      buf.push_back((uint8_t)len);
    }
  };
  auto der_int = [&der_len](const uint8_t *d,
                            size_t sz) -> std::vector<uint8_t> {
    std::vector<uint8_t> r;
    r.push_back(0x02);
    size_t skip = 0;
    while (skip + 1 < sz && d[skip] == 0)
      skip++;
    bool pad = (d[skip] & 0x80) != 0;
    der_len(sz - skip + (pad ? 1 : 0), r);
    if (pad)
      r.push_back(0x00);
    r.insert(r.end(), d + skip, d + sz);
    return r;
  };
  auto mod_int = der_int(modBytes, modLen), exp_int = der_int(expBytes, expLen);
  std::vector<uint8_t> rsa_pk;
  rsa_pk.push_back(0x30);
  std::vector<uint8_t> rsa_pk_body;
  rsa_pk_body.insert(rsa_pk_body.end(), mod_int.begin(), mod_int.end());
  rsa_pk_body.insert(rsa_pk_body.end(), exp_int.begin(), exp_int.end());
  der_len(rsa_pk_body.size(), rsa_pk);
  rsa_pk.insert(rsa_pk.end(), rsa_pk_body.begin(), rsa_pk_body.end());
  std::vector<uint8_t> bit_str;
  bit_str.push_back(0x03);
  der_len(rsa_pk.size() + 1, bit_str);
  bit_str.push_back(0x00);
  bit_str.insert(bit_str.end(), rsa_pk.begin(), rsa_pk.end());
  static const uint8_t alg_oid[] = {0x30, 0x0D, 0x06, 0x09, 0x2A,
                                    0x86, 0x48, 0x86, 0xF7, 0x0D,
                                    0x01, 0x01, 0x01, 0x05, 0x00};
  std::vector<uint8_t> spki_body;
  spki_body.insert(spki_body.end(), alg_oid, alg_oid + sizeof(alg_oid));
  spki_body.insert(spki_body.end(), bit_str.begin(), bit_str.end());
  std::vector<uint8_t> der_spki;
  der_spki.push_back(0x30);
  der_len(spki_body.size(), der_spki);
  der_spki.insert(der_spki.end(), spki_body.begin(), spki_body.end());
  return der_spki;
}

static std::vector<uint8_t> GenerateRsaSpkiPem() {
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_KEY_HANDLE hKey = nullptr;
  std::vector<uint8_t> result;
  if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0) != 0)
    return result;
  NTSTATUS status = BCryptGenerateKeyPair(hAlg, &hKey, RSA_KEY_SIZE, 0);
  if (status != 0) {
    status = BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0);
  }
  if (status != 0) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
  }
  if (BCryptFinalizeKeyPair(hKey, 0) != 0) {
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
  }
  DWORD pubSz = 0;
  BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &pubSz, 0);
  std::vector<uint8_t> pubBlob(pubSz);
  BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, pubBlob.data(), pubSz,
                  &pubSz, 0);
  BCryptDestroyKey(hKey);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  if (!VGW::ValidatePublicKeyFormat(pubBlob))
    return result;
  auto der = BcryptBlobToSpkiDer(pubBlob);
  if (der.empty())
    return result;
  std::string b64 = Base64Encode(der.data(), der.size());
  if (!VGW::ValidatePublicKeyFormat(b64))
    return result;
  std::string pem = "-----BEGIN PUBLIC KEY-----\n";
  for (size_t i = 0; i < b64.size(); i += 64)
    pem += b64.substr(i, 64) + "\n";
  pem += "-----END PUBLIC KEY-----\n";
  result.assign(pem.begin(), pem.end());
  Log("[RSA] PEM SPKI generated " + std::to_string(result.size()) + "B (" +
      std::to_string(RSA_KEY_SIZE) + "-bit standard)");
  return result;
}

static const char *GatewayActionName(int vg_type) {
  switch (vg_type) {
  case 3:
    return "AUTH";
  case 4:
    return "ACCESS";
  case 6:
    return "REPORT";
  case 7:
    return "HEARTBEAT";
  case 9:
    return "TASK_RESULT";
  default:
    return "UNKNOWN";
  }
}

static std::mutex g_gw_post_mtx;

static bool PostToGateway(const std::vector<uint8_t> &envelope,
                          const std::string &puuid, const std::string &region,
                          std::vector<uint8_t> *out_response, int vg_type,
                          bool bypass_cooldown) {

  if (!bypass_cooldown && IsGatewayInCooldown()) {
    return false;
  }

  std::lock_guard<std::mutex> lk_post(g_gw_post_mtx);

  std::wstring gw_host = RegionToGwHost(region);
  std::string gw_host_s;
  for (wchar_t c : gw_host)
    gw_host_s += (char)(c & 0x7F);
  const std::string action_label =
      std::to_string(vg_type) + "(" + GatewayActionName(vg_type) + ")";
  const std::string target_url =
      "https://" + gw_host_s + ":8443/vanguard/v1/gateway";
  Log("[GW][PostToGateway] Target URL: " + target_url + " | Region: " + region +
      " | Action: " + action_label +
      " | Envelope Size: " + std::to_string(envelope.size()) + " bytes");

  HINTERNET hS = WinHttpOpen(VGC_UA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hS) {
    Log("[GW][PostToGateway] WinHttpOpen failed");
    return false;
  }
  WinHttpSetTimeouts(hS, 10000, 10000, 15000, 15000);
  HINTERNET hC = WinHttpConnect(hS, gw_host.c_str(), GW_PORT, 0);
  if (!hC) {
    WinHttpCloseHandle(hS);
    Log("[GW][PostToGateway] Connect failed to " + gw_host_s);
    return false;
  }
  HINTERNET hR =
      WinHttpOpenRequest(hC, L"POST", GW_PATH, L"HTTP/1.1", WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!hR) {
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    Log("[GW][PostToGateway] OpenRequest failed");
    return false;
  }

  DWORD ssl = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
              SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
              SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
  WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &ssl, sizeof(ssl));

  std::wstring headers;
  headers += L"User-Agent: vanguard/1.18.5.11\r\n";
  headers += L"Content-Type: application/x-protobuf\r\n";
  headers += L"X-Protobuf-Version: 3.21.12\r\n";
  if (!puuid.empty()) {
    std::wstring w(puuid.begin(), puuid.end());
    headers += L"X-VG-2: " + w + L"\r\n";
  }
  headers +=
      L"X-VG-1: " + std::to_wstring(vg_type) + L"\r\nX-VG-3: 1\r\nAccept: */*";

  BOOL ok = WinHttpSendRequest(hR, headers.c_str(), (DWORD)-1L,
                               (LPVOID)envelope.data(), (DWORD)envelope.size(),
                               (DWORD)envelope.size(), 0);
  if (!ok || !WinHttpReceiveResponse(hR, nullptr)) {
    Log("[GW][PostToGateway] Send/recv failed URL: " + target_url +
        " err=" + std::to_string(GetLastError()));
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return false;
  }

  DWORD status = 0, sz = sizeof(DWORD);
  WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                      WINHTTP_NO_HEADER_INDEX);

  std::vector<uint8_t> resp_body;
  DWORD avail = 0;
  while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
    std::vector<uint8_t> chunk(avail);
    DWORD rd = 0;
    WinHttpReadData(hR, chunk.data(), avail, &rd);
    chunk.resize(rd);
    resp_body.insert(resp_body.end(), chunk.begin(), chunk.end());
  }
  WinHttpCloseHandle(hR);
  WinHttpCloseHandle(hC);
  WinHttpCloseHandle(hS);

  Log("[GW][PostToGateway] Response from URL: " + target_url +
      " | Status Code: " + std::to_string(status) +
      " | Response Size: " + std::to_string(resp_body.size()) + " bytes");
  if (status == 429) {
    Log("[GW][PostToGateway] Rate limited (HTTP 429).");
    SetGatewayCooldown(60.0);
    return false;
  }
  if (status == 200) {
    Log("[GW] *** GATEWAY " + std::string(GatewayActionName(vg_type)) +
        " OK region=" + region + " action=" + action_label + " ***");
    g_data_analysis_mgr.ProcessReceivedData(
        resp_body, "Gateway:" + std::string(GatewayActionName(vg_type)));
    if (out_response)
      *out_response = resp_body;
    {
      std::lock_guard<std::mutex> lk(g_gw_auth_response_mtx);
      g_gw_auth_response = resp_body;
    }
    {
      std::lock_guard<std::mutex> lk(g_gw_session_mtx);
      g_gw_session.last_auth_response = resp_body;
      g_gw_session.ready = true;
      g_gw_session.cached_at =
          (double)std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count();
      if (vg_type == 3) {
        auto decrypted = VGW::DecryptGatewayResponse(resp_body);
        if (!decrypted.empty()) {
          auto ar = VGW::DecodeAuthResponse(decrypted);
          if (!ar.ephemeral_identifiers.empty())
            g_gw_session.ephemeral_identifiers = ar.ephemeral_identifiers;
        }
      }
    }
    Log("[GW] gateway response cached for next VPS gateway step/action");
    Log("[GW] next gateway action will use latest response body");
    return true;
  } else if (!resp_body.empty()) {
    std::string s(resp_body.begin(), resp_body.end());
    Log("[GW] body: " + s.substr(0, 300));
  } else {
    Log("[GW] empty body -- check rso_jwt/entitlement/region");
  }
  return false;
}

static bool ExchangeVpsGatewayStep(
    TlsSocket &tls, uint32_t request_type, uint32_t expected_response_type,
    int gateway_action, const std::vector<uint8_t> &gateway_response,
    const std::string &puuid, const std::string &region,
    std::vector<uint8_t> &next_gateway_response, const char *tag) {
  auto req = PackMsg(request_type, gateway_response);
  tls.SendAll(req.data(), req.size());

  auto msg = tls.RecvMsg();
  if (msg.size() < 8) {
    Log(std::string("[VPS] ") + tag + " response too short");
    return false;
  }

  uint32_t mt = ReadU32BE(msg.data());
  if (mt == MSG_ERROR) {
    std::string err(msg.begin() + 8, msg.end());
    Log(std::string("[VPS] ") + tag + " server error: " + err);
    return false;
  }
  if (mt != expected_response_type) {
    Log(std::string("[VPS] ") + tag + " expected type " +
        std::to_string(expected_response_type) + ", got " + std::to_string(mt));
    return false;
  }

  std::vector<uint8_t> payload(msg.begin() + 8, msg.end());
  std::string sid;
  auto envelope = ParseSessionGatewayBody(payload, &sid);
  std::string target_sid = sid.empty() ? g_cached_sid : sid;
  if (envelope.empty()) {
    if (!target_sid.empty()) {
      envelope = g_fallback.get(target_sid);
    }
    if (envelope.empty()) {
      Log(std::string("[VPS] ") + tag + " empty envelope");
      return false;
    }
    Log(std::string("[VPS] ") + tag +
        " empty envelope, using fallback cache (" +
        std::to_string(envelope.size()) + "B)");
  }

  Log(std::string("[VPS] ") + tag +
      " envelope=" + std::to_string(envelope.size()) +
      "B action=" + std::to_string(gateway_action));
  bool ok = PostToGateway(envelope, puuid, region, &next_gateway_response,
                          gateway_action);
  if (ok && !next_gateway_response.empty() && !target_sid.empty()) {
    g_fallback.update(target_sid, next_gateway_response);
    g_data_analysis_mgr.ProcessReceivedData(next_gateway_response,
                                            "ExchangeVpsGatewayStep");
  }
  return ok;
}

static void VpsServerHeartbeatLoop(std::unique_ptr<TlsSocket> tls,
                                   std::vector<uint8_t> latest_gateway_response,
                                   std::string puuid, std::string region) {
  if (tls)
    tls->Close();
  return;
}

static double g_last_reauth_time = 0;

static void UpdateConsoleTitle() {
  int remaining = g_gateway_reauth_remaining_sec.load();
  if (remaining < 0)
    remaining = 0;

  int hh = remaining / 3600;
  int mm = (remaining % 3600) / 60;
  int ss = remaining % 60;

  wchar_t title[128] = {};
  swprintf_s(title,
             L"TechnoVerse | Auto Match Transition Active | Keepalive "
             L"[%02d:%02d:%02d]",
             hh, mm, ss);
  SetConsoleTitleW(title);
}

static void ResetGatewayReauthTimer() {
  g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
  g_gateway_reauth_restart_countdown.store(true);
  UpdateConsoleTitle();
}

static void StartTaskProbeDispatcher() {
  if (g_task_probe_dispatcher_running.exchange(true)) {
    return;
  }
  std::thread([]() {
    Log("[TASK_PROBE] Task probe dispatcher background thread started");
    while (!g_shutdown.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));

      std::string token, puuid, region, sid;
      {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        token = g_cached_jwt;
        puuid = g_cached_puuid;
        sid = g_cached_sid;
        region = g_cached_region;
      }
      if (token.empty() || puuid.empty())
        continue;

      std::vector<uint8_t> session_aes(32, 0x5a);
      std::vector<uint8_t> server_rsa_pub;
      {
        std::lock_guard<std::mutex> lk_s(g_gw_session_mtx);
        if (!g_gw_session.server_public_key.empty()) {
          if (g_gw_session.server_public_key.find("-----BEGIN") !=
              std::string::npos)
            server_rsa_pub = VGW::PemToDer(g_gw_session.server_public_key);
          else
            server_rsa_pub = VGW::Base64Decode(g_gw_session.server_public_key);
        }
      }

      std::optional<ProbeQueueItem> probe_opt;
      {
        std::lock_guard<std::mutex> lk_pq(g_task_probe_mtx);
        probe_opt = pop_next_probe(g_task_probe_queue, token, session_aes,
                                   server_rsa_pub, {});
      }

      if (probe_opt.has_value()) {
        auto probe = probe_opt.value();
        if (!probe.wire.empty()) {
          if (region.empty())
            region = g_selected_region.empty() ? "la" : g_selected_region;
          region = ApplyConfiguredRegion(region, "[TASK_PROBE]");

          std::string task_label =
              probe.meta.count("task_id") ? probe.meta.at("task_id") : probe.task_id;
          Log("[TASK_PROBE] Dispatching task result probe: " + probe.label +
              " (task_id=" + task_label +
              ") wire_size=" + std::to_string(probe.wire.size()) + "B");

          std::vector<uint8_t> probe_resp;
          int vg_action = probe.vg_type > 0 ? probe.vg_type : 9; // VG_TASK_RESULT
          bool ok = PostToGateway(probe.wire, puuid, region, &probe_resp,
                                  vg_action, true);
          int http_status = ok ? 200 : (IsGatewayInCooldown() ? 429 : 500);

          {
            std::lock_guard<std::mutex> lk_pq(g_task_probe_mtx);
            record_probe_result(g_task_probe_queue, sid, probe, http_status, 0);
          }

          if (ok) {
            Log("[TASK_PROBE] Probe " + probe.label +
                " succeeded (HTTP 200 OK) -> task ACKed");
            g_102_count.store(0);
          } else {
            Log("[TASK_PROBE] Probe " + probe.label +
                " failed (status=" + std::to_string(http_status) + ")");
          }
        }
      }
    }
    g_task_probe_dispatcher_running.store(false);
  }).detach();
}

static bool GatewaySendHeartbeat() {
  std::string jwt, puuid, region, sid;
  std::vector<uint8_t> prev_resp;
  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    jwt = g_cached_jwt;
    puuid = g_cached_puuid;
    sid = g_cached_sid;
    region = g_cached_region;
  }
  {
    std::lock_guard<std::mutex> lk_s(g_gw_session_mtx);
    if (!g_gw_session.ready || g_gw_session.last_auth_response.empty()) {
      return false;
    }
    prev_resp = g_gw_session.last_auth_response;
  }

  if (puuid.empty())
    return false;
  if (region.empty())
    region = g_selected_region.empty() ? "ap" : g_selected_region;
  region = ApplyConfiguredRegion(region, "[GW-HB]");

  std::string server_pub_out;
  std::string eph_out;
  auto hb_envelope =
      VGW::BuildGatewayHeartbeatPayload(prev_resp, server_pub_out, &eph_out);
  if (hb_envelope.empty()) {
    Log("[GW-HB] Failed to build heartbeat payload");
    return false;
  }

  std::vector<uint8_t> hb_resp;
  bool ok = PostToGateway(hb_envelope, puuid, region, &hb_resp, 7, true);
  if (ok && !hb_resp.empty()) {
    Log("[GW-HB] Gateway Heartbeat OK (Action 7, resp=" +
        std::to_string(hb_resp.size()) + "B)");
    g_data_analysis_mgr.ProcessReceivedData(hb_resp, "Gateway:HEARTBEAT");
    g_102_count.store(0);
    g_session_reset_needed.store(false);

    {
      std::lock_guard<std::mutex> lk_s(g_gw_session_mtx);
      g_gw_session.last_auth_response = hb_resp;
      if (!eph_out.empty())
        g_gw_session.ephemeral_identifiers = eph_out;
      if (!server_pub_out.empty())
        g_gw_session.server_public_key = server_pub_out;
    }
    if (!sid.empty())
      g_fallback.update(sid, hb_resp);
    return true;
  } else {
    Log("[GW-HB] Gateway Heartbeat FAILED");
    return false;
  }
}

static bool GatewayDoReauth() {
  if (IsGatewayInCooldown()) {
    return false;
  }
  // FIX 4: Validate cached credentials before re-auth
  if (!ValidateCachedCredentials()) {
    Log("[GW-KA] re-auth skipped: cached credentials invalid or expired -> "
        "awaiting new data capture");
    return false;
  }
  std::string jwt, puuid, region, sid;
  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    jwt = g_cached_jwt;
    puuid = g_cached_puuid;
    sid = g_cached_sid;
    region = g_cached_region;
  }
  if (jwt.empty() || puuid.empty()) {
    Log("[GW-KA] re-auth skipped: no jwt/puuid");
    return false;
  }
  if (region.empty())
    region = ShardFromJwtRobust(jwt);
  if (region.empty())
    region = g_selected_region.empty() ? "ap" : g_selected_region;
  region = ApplyConfiguredRegion(region, "[GW-KA]");

  double now = NowSec();
  bool forced = g_gw_reauth_needed.load();
  bool hb_recovery_needed = (g_102_count.load() > 0 || g_session_reset_needed.load());
  if (!forced && !hb_recovery_needed && (now - g_last_reauth_time) < 30.0) {
    Log("[GW-KA] re-auth throttled — last was " +
        std::to_string((int)(now - g_last_reauth_time)) + "s ago");
    return false;
  }
  if (forced || hb_recovery_needed)
    Log("[GW-KA] re-auth forced (recovery / lobby return / new match)");

  const std::string resolved_sid =
      ResolveNonEmptySid(jwt, sid, puuid, "[GW-KA]");
  std::string last_ephemeral;
  {
    std::lock_guard<std::mutex> lk(g_gw_session_mtx);
    last_ephemeral = g_gw_session.ephemeral_identifiers;
  }
  const auto &_hwp2 = GetRandomizedHardwareProfile();
  auto envelope = VGW::BuildGatewayAuthPayload(
      jwt, resolved_sid, GetConfiguredGatewayMachineId(), GetStableHt(),
      last_ephemeral, _hwp2.cpu_brand, _hwp2.cpu_model, _hwp2.gpu_brand, _hwp2.gpu_model,
      "Windows 10 Pro", _hwp2.os_version);
  if (envelope.empty()) {
    Log("[GW-KA] re-auth skipped: envelope empty");
    return false;
  }

  g_last_reauth_time = NowSec();
  Log("[GW-KA] sending re-auth -> " + region);
  std::vector<uint8_t> new_resp;
  bool ok = PostToGateway(envelope, puuid, region, &new_resp, 3);
  if (ok) {
    if (!new_resp.empty()) {
      g_data_analysis_mgr.ProcessReceivedData(new_resp, "GatewayDoReauth");
      auto decrypted = VGW::DecryptGatewayResponse(new_resp);
      if (!decrypted.empty()) {
        auto resp = VGW::DecodeAuthResponse(decrypted);
        if (!resp.ephemeral_identifiers.empty()) {
          std::lock_guard<std::mutex> lk(g_gw_session_mtx);
          g_gw_session.ephemeral_identifiers = resp.ephemeral_identifiers;
        }
      }
    }
    g_reauth_fail_count.store(0);
    g_102_count.store(0);
    g_session_reset_needed.store(false);
    ResetGatewayReauthTimer();
    StartTaskProbeDispatcher();
    Log("[GW-KA] re-auth OK -> " + region);
  } else {
    int fails = g_reauth_fail_count.fetch_add(1) + 1;
    Log("[GW-KA] re-auth FAILED fails=" + std::to_string(fails));
    if (hb_recovery_needed) {
      g_last_reauth_time = NowSec() + 10.0;
      g_gateway_reauth_remaining_sec.store(10);
    } else {
      g_last_reauth_time = NowSec() + 30.0;
      g_gateway_reauth_remaining_sec.store(30);
    }
    UpdateConsoleTitle();
  }
  g_gw_reauth_needed.store(false);
  return ok;
}

static void GatewayKeepaliveLoop45Min() {
  Log("[GW-KA] Gateway keepalive loop started.");
  int hb_ticker = 0;
  while (g_keepalive_running.load()) {
    Sleep(1000);
    hb_ticker++;

    if (g_gateway_reauth_restart_countdown.exchange(false)) {
      g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
    }

    int rem = g_gateway_reauth_remaining_sec.fetch_sub(1) - 1;
    if (rem % 10 == 0 || rem <= 10) {
      UpdateConsoleTitle();
    }

    // Live Gateway Heartbeat (Action 7) every 25 seconds
    if (hb_ticker >= 25) {
      hb_ticker = 0;
      GatewaySendHeartbeat();
    }

    if (rem <= 0 || g_gw_reauth_needed.load()) {
      Log("[GW-KA] Keepalive timer expired or re-auth flag set. Triggering "
          "GatewayDoReauth...");
      bool ok = GatewayDoReauth();
      if (ok) {
        g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
        Log("[GW-KA] Gateway re-auth succeeded. Resetting keepalive timer (" +
            std::to_string(GATEWAY_REAUTH_INTERVAL_SEC) + "s).");
      } else {
        Log("[GW-KA] Gateway re-auth failed! Will retry in 30 seconds.");
        g_gateway_reauth_remaining_sec.store(30);
      }
      UpdateConsoleTitle();
    }
  }
  Log("[GW-KA] Gateway keepalive loop stopped.");
}

static bool ReconnectSession(const std::string &sid) {
  Log("Session unhealthy, reconnecting: " + sid);
  auto s = g_session_mgr.get(sid);
  if (!s)
    return false;

  g_gw_reauth_needed.store(true);
  bool ok = GatewayDoReauth();
  if (ok) {
    s->failure_count = 0;
    s->last_activity = NowSec();
    Log("Session reconnected successfully: " + sid);
    return true;
  }
  Log("Session reconnection failed: " + sid);
  return false;
}

static std::atomic_bool g_health_check_running{true};

static void HealthCheck() {
  while (g_health_check_running.load()) {
    Sleep(HEALTH_CHECK_INTERVAL_MS);
    auto sids = g_session_mgr.get_all_sids();
    for (const auto &sid : sids) {
      auto session = g_session_mgr.get(sid);
      if (session) {
        if (session->failure_count > MAX_CONSECUTIVE_FAILURES) {
          Log("Session unhealthy, reconnecting: " + session->session_id);
          ReconnectSession(session->session_id);
        } else {
          if (session->failure_count > 0 &&
              (NowSec() - session->last_activity < 10.0)) {
            session->failure_count = 0;
          }
        }
      }
    }
  }
}

static void GatewayKeepaliveLoop() { GatewayKeepaliveLoop45Min(); }

static bool SmartGatewayMint(const std::string &jwt, const std::string &sid,
                             const std::string &puuid, uint32_t pid,
                             bool bypass_cooldown) {
  if (!bypass_cooldown && IsGatewayInCooldown()) {
    Log("[GW] SmartGatewayMint skipped due to rate-limit cooldown");
    return false;
  }
  // FIX 4: Validate credentials if relying on cached state
  if (jwt.empty() && !ValidateCachedCredentials()) {
    Log("[GW] SmartGatewayMint skipped: Cached credentials invalid or expired "
        "-> clearing cache and awaiting new data capture");
    ClearCachedCredentials();
    return false;
  }
  const std::string resolved_sid = ResolveNonEmptySid(jwt, sid, puuid, "[GW]");

  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    if (!g_cached_jwt.empty() && g_cached_jwt == jwt &&
        g_cached_sid == resolved_sid) {
      std::lock_guard<std::mutex> lk2(g_gw_session_mtx);
      if (g_gw_session.ready) {
        return true;
      }
    }
  }

  {
    std::lock_guard<std::mutex> lk(g_gw_session_mtx);
    if (g_gw_session.ready) {
      Log("[GW] token or sid changed! -- allowing new JWT mint");
      g_gw_session.Reset();
    }
  }

  g_keepalive_running.store(false);

  Log("[GW] forwarding token to gateway (auto-mint)");

  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    g_cached_jwt = jwt;
    g_cached_sid = resolved_sid;
    g_cached_puuid = puuid;
  }

  std::string region = ShardFromJwtRobust(jwt);
  if (region.empty()) {
    std::lock_guard<std::mutex> lk3(g_jwt_cache_mtx);
    LogJwtRegionHints(jwt, "[JWT-REGION][GW]");
    region = g_cached_region.empty()
                 ? (g_selected_region.empty() ? "ap" : g_selected_region)
                 : g_cached_region;
    Log("[GW] region fallback -> " + region);
  }
  region = ApplyConfiguredRegion(region, "[GW]");
  {
    std::lock_guard<std::mutex> lk3(g_jwt_cache_mtx);
    if (!region.empty()) {
      g_cached_region = region;
      g_selected_region = region;
    }
  }

  Log("[GW] building auth payload (standalone protobuf+crypto)");
  const auto &_hwp3 = GetRandomizedHardwareProfile();
  auto envelope = VGW::BuildGatewayAuthPayload(
      jwt, resolved_sid, GetConfiguredGatewayMachineId(), GetStableHt(), "",
      _hwp3.cpu_brand, _hwp3.cpu_model, _hwp3.gpu_brand, _hwp3.gpu_model, "Windows 10 Pro",
      _hwp3.os_version);
  if (envelope.empty()) {
    Log("[GW] BuildGatewayAuthPayload failed -- trying device IOCTL for real "
        "payload");
    auto ioctl_data = RealVgkIoctl(IOCTL_VGK_HB, {});
    if (!ioctl_data.empty() && ioctl_data.size() > 100) {
      envelope = ioctl_data;
      std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
      g_vgk_payload = ioctl_data;
      Log("[GW] Captured real data via device IOCTL for gateway envelope "
          "(size=" +
          std::to_string(envelope.size()) + "B)");
    } else {
      std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
      if (!g_vgk_payload.empty() && g_vgk_payload.size() > 100) {
        envelope = g_vgk_payload;
        Log("[GW] Falling back to stored vgk payload (size=" +
            std::to_string(envelope.size()) + "B)");
      } else if (!g_vgk_payload.empty() && g_vgk_payload.size() <= 100) {
        Log("[GW] Stored vgk payload is invalid (size <= 100 bytes)");
      }
    }
  }
  if (envelope.empty()) {
    Log("[GW] no envelope available, mint aborted");
    return false;
  }

  std::vector<uint8_t> auth_resp;
  bool ok =
      PostToGateway(envelope, puuid, region, &auth_resp, 3, bypass_cooldown);
  if (ok) {
    Log("[GW] gateway mint success (auto)");
    ResetGatewayReauthTimer();

    g_last_reauth_time = NowSec();

    std::string target_sid = resolved_sid.empty() ? g_cached_sid : resolved_sid;
    g_session_mgr.ensure_session_exists(target_sid, jwt, puuid, region, pid);

    StopVgk();

    if (!g_keepalive_running.exchange(true)) {
      ResetGatewayReauthTimer();
      std::thread(GatewayKeepaliveLoop45Min).detach();
      StartTaskProbeDispatcher();
      std::thread(GatewaySendHeartbeat).detach();
    }
    return true;
  } else {
    Log("[GW] gateway mint failed -- will retry on next JWT");
    g_keepalive_running.store(false);
    g_gw_auto_posted.store(false);
  }
  return false;
}

static std::vector<uint8_t>
BuildSessionAuth(const std::string &jwt, const std::string &puuid,
                 const std::string &external_sid, const std::string &region,
                 uint32_t pid, const std::vector<uint8_t> &hwid,
                 const std::vector<uint8_t> &rsa_spki_pem,
                 const std::string &cpu_brand, const std::string &cpu_model,
                 const std::string &gpu_brand, const std::string &gpu_model,
                 uint32_t cpu_logical_count) {
  std::vector<uint8_t> body;
  PushLenStr(body, AUTH_KEY);
  PushLenBytes(body, hwid);
  PushLenStr(body, jwt);
  PushLenStr(body, puuid);
  PushU32BE(body, pid);
  uint64_t now_ms =
      (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  PushU64BE(body, now_ms);
  PushLenStr(body, region);
  PushLenBytes(body, hwid);
  PushLenStr(body, puuid);

  PushLenStr(body, RandomizedVersion ? GetFakeHostname() : "WIN-PC");

  PushLenBytes(body, rsa_spki_pem);
  PushLenStr(body, "release-13.00-shipping-30-4955671");
  PushU32BE(body, 4955671);
  PushU32BE(body, 13);
  PushU32BE(body, 0);
  PushU32BE(body, 30);
  PushU32BE(body, 0);
  PushLenStr(body, external_sid);
  PushLenStr(body, cpu_brand);
  PushLenStr(body, cpu_model);
  PushLenStr(body, gpu_brand);
  PushLenStr(body, gpu_model);
  PushU32BE(body, cpu_logical_count);
  return body;
}

typedef NTSTATUS(NTAPI *pfnNtUnloadDriver)(PUNICODE_STRING DriverServiceName);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
  USHORT UniqueProcessId;
  USHORT CreatorBackTraceIndex;
  UCHAR ObjectTypeIndex;
  UCHAR HandleAttributes;
  USHORT HandleValue;
  PVOID Object;
  ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
  ULONG NumberOfHandles;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16

typedef NTSTATUS(NTAPI *pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG,
                                                     PULONG);

static void KillVgkHandles() {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (!ntdll)
    return;
  auto NtQSI = (pfnNtQuerySystemInformation)GetProcAddress(
      ntdll, "NtQuerySystemInformation");
  if (!NtQSI)
    return;

  ULONG size = 1 << 20;
  std::vector<BYTE> buf(size);
  NTSTATUS st;
  while ((st = NtQSI(SystemHandleInformation, buf.data(), (ULONG)buf.size(),
                     &size)) == 0x80000005L) {
    buf.resize(buf.size() * 2);
  }
  if (st != 0)
    return;

  auto *info = (SYSTEM_HANDLE_INFORMATION *)buf.data();

  DWORD val_pid = 0;
  {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32W pe;
      pe.dwSize = sizeof(pe);
      if (Process32FirstW(snap, &pe)) {
        do {
          std::string n;
          for (wchar_t c : pe.szExeFile)
            if (c)
              n += (char)(c & 0x7F);
          if (_stricmp(n.c_str(), "VALORANT-Win64-Shipping.exe") == 0) {
            val_pid = pe.th32ProcessID;
            break;
          }
        } while (Process32NextW(snap, &pe));
      }
      CloseHandle(snap);
    }
  }
  if (!val_pid) {
    Log("[VGK] Valorant not found");
    return;
  }

  HANDLE hVgk = CreateFileA("\\\\.\\vgk", GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, 0, nullptr);

  PVOID vgk_obj = nullptr;
  if (hVgk != INVALID_HANDLE_VALUE) {
    DWORD my_pid = GetCurrentProcessId();
    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
      auto &e = info->Handles[i];
      if (e.UniqueProcessId == my_pid &&
          (HANDLE)(uintptr_t)e.HandleValue == hVgk) {
        vgk_obj = e.Object;
        break;
      }
    }
    CloseHandle(hVgk);
  }

  HANDLE hVal = OpenProcess(PROCESS_DUP_HANDLE, FALSE, val_pid);
  if (!hVal) {
    Log("[VGK] Cannot open Valorant process");
    return;
  }

  int killed = 0;
  for (ULONG i = 0; i < info->NumberOfHandles; i++) {
    auto &e = info->Handles[i];
    if (e.UniqueProcessId != (USHORT)val_pid)
      continue;
    if (vgk_obj && e.Object != vgk_obj)
      continue;
    if (!vgk_obj)
      continue;

    HANDLE dup = nullptr;
    if (DuplicateHandle(hVal, (HANDLE)(uintptr_t)e.HandleValue,
                        GetCurrentProcess(), &dup, 0, FALSE,
                        DUPLICATE_CLOSE_SOURCE)) {
      CloseHandle(dup);
      killed++;
    }
  }
  CloseHandle(hVal);
  Log("[VGK] Closed " + std::to_string(killed) +
      " vgk handle(s) from Valorant");
}

static bool ForceUnloadVgk() {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (!ntdll)
    return false;
  auto NtUnloadDriver =
      (pfnNtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
  if (!NtUnloadDriver)
    return false;

  WCHAR reg_path[] =
      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\vgk";
  UNICODE_STRING us;
  us.Buffer = reg_path;
  us.Length = (USHORT)(wcslen(reg_path) * sizeof(WCHAR));
  us.MaximumLength = us.Length + sizeof(WCHAR);

  NTSTATUS st = NtUnloadDriver(&us);
  Log("[VGK] NtUnloadDriver status=0x" +
      [&] {
        std::ostringstream o;
        o << std::hex << (uint32_t)st;
        return o.str();
      }() +
      (st == 0             ? " (OK)"
       : st == 0xC0000024L ? " (refs exist)"
       : st == 0xC000010EL ? " (not loaded)"
                           : ""));
  return st == 0;
}

static void StopVgk() {
  Log("[VGK] StopVgk called — skipping service stop (Valorant still running)");
}
struct ValorantWindowCtx {
  DWORD pid;
  int pct;
};
static int GetValorantLoadingPct() {
  int pct = 0;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) {
        ValorantWindowCtx ctx{pe.th32ProcessID, 0};
        EnumWindows(
            [](HWND hwnd, LPARAM lp) -> BOOL {
              auto *c = reinterpret_cast<ValorantWindowCtx *>(lp);
              DWORD wp = 0;
              GetWindowThreadProcessId(hwnd, &wp);
              if (wp != c->pid)
                return TRUE;
              wchar_t title[256]{};
              GetWindowTextW(hwnd, title, 255);
              std::wstring t(title);
              auto pos = t.find(L"Loading");
              if (pos != std::wstring::npos) {
                auto p1 = t.find(L'(', pos);
                auto p2 = t.find(L'%', pos);
                if (p1 != std::wstring::npos && p2 != std::wstring::npos &&
                    p2 > p1)
                  c->pct = _wtoi(t.substr(p1 + 1, p2 - p1 - 1).c_str());
              }
              return TRUE;
            },
            (LPARAM)&ctx);
        pct = ctx.pct;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pct;
}

#include <iostream>
#include <tlhelp32.h>
#include <windows.h>

bool TerminateProcessByName(const wchar_t *processName) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return false;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(PROCESSENTRY32W);

  if (Process32FirstW(hSnapshot, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, processName) == 0) {
        HANDLE hProcess =
            OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
        if (hProcess) {
          if (TerminateProcess(hProcess, 0)) {
            // 1211
          } else {
            // 3434343
          }

          CloseHandle(hProcess);
        }
      }
    } while (Process32NextW(hSnapshot, &pe));
  }

  CloseHandle(hSnapshot);
  return true;
}

static bool SendViaLocalServer(const std::string &rso_jwt,
                               const std::string &sid, const std::string &puuid,
                               uint32_t pid) {
  const std::string resolved_sid =
      ResolveNonEmptySid(rso_jwt, sid, puuid, "[CLI]");
  Log("[SendViaLocalServer] Starting local auth session for PUUID=" +
      (puuid.size() > 8 ? puuid.substr(0, 8) + "..." : puuid) + " SID=" +
      (resolved_sid.size() > 8 ? resolved_sid.substr(0, 8) + "..."
                               : resolved_sid) +
      " PID=" + std::to_string(pid));
  Log("[SendViaLocalServer] Bypassing VPS flow entirely -- calling "
      "SmartGatewayMint directly");

  bool ok = SmartGatewayMint(rso_jwt, resolved_sid, puuid, pid);
  if (ok) {
    std::string hb_sid = resolved_sid.empty() ? g_cached_sid : resolved_sid;
    Log("[SendViaLocalServer] SmartGatewayMint succeeded! Forcing immediate "
        "heartbeat on session=" +
        (hb_sid.size() > 8 ? hb_sid.substr(0, 8) : hb_sid));
    if (!hb_sid.empty()) {
      g_session_mgr.send_heartbeat(hb_sid, true);
    }
    return true;
  }

  Log("[SendViaLocalServer] SmartGatewayMint failed");
  return false;
}

static void QueuePendingGatewayRequest(const std::string &jwt,
                                       const std::string &sid,
                                       const std::string &puuid, uint32_t pid) {
  std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
  g_pending_gateway.jwt = jwt;
  g_pending_gateway.sid = sid;
  g_pending_gateway.puuid = puuid;
  g_pending_gateway.pid = pid;
  g_pending_gateway.queued_at = std::chrono::steady_clock::now();
  g_pending_gateway.valid = true;
}

#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

std::atomic<bool> g_time_warped{false};
std::atomic<bool> g_keep_warping{false};
std::thread g_warper_thread;

static FILETIME g_start_system_time = {};
static LARGE_INTEGER g_start_qpc = {};
static LARGE_INTEGER g_qpc_freq = {};
static std::once_flag g_time_init_flag;

static void InitRealTimeTracker() {
  std::call_once(g_time_init_flag, []() {
    GetSystemTimeAsFileTime(&g_start_system_time);
    QueryPerformanceCounter(&g_start_qpc);
    QueryPerformanceFrequency(&g_qpc_freq);
  });
}

static void restore_time_instant() {
  InitRealTimeTracker();
  if (g_qpc_freq.QuadPart != 0 && g_start_system_time.dwHighDateTime != 0) {
    LARGE_INTEGER cur_qpc;
    QueryPerformanceCounter(&cur_qpc);
    LONGLONG elapsed_qpc = cur_qpc.QuadPart - g_start_qpc.QuadPart;
    LONGLONG elapsed_100ns = (elapsed_qpc * 10000000ULL) / g_qpc_freq.QuadPart;

    ULARGE_INTEGER uli;
    uli.LowPart = g_start_system_time.dwLowDateTime;
    uli.HighPart = g_start_system_time.dwHighDateTime;
    uli.QuadPart += elapsed_100ns;

    FILETIME ft;
    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    SetSystemTime(&st);
  }
}

static void PrintLastError(const char *msg) {
  DWORD err = GetLastError();
  std::cerr << msg << " Error: " << err << std::endl;
}

static void geri_sar_6_saat() {
  SYSTEMTIME st;
  GetLocalTime(&st);

  FILETIME ft;
  SystemTimeToFileTime(&st, &ft);

  ULARGE_INTEGER uli;
  uli.LowPart = ft.dwLowDateTime;
  uli.HighPart = ft.dwHighDateTime;
  uli.QuadPart -= 6ULL * 3600 * 10000000ULL;

  ft.dwLowDateTime = uli.LowPart;
  ft.dwHighDateTime = uli.HighPart;

  FileTimeToSystemTime(&ft, &st);

  if (SetLocalTime(&st)) {
  } else {
    PrintLastError("SetLocalTime failed");
  }
}

static void RunCommand(const std::string &cmd, int timeout_sec) {
  STARTUPINFOA si = {sizeof(si)};
  PROCESS_INFORMATION pi{};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  std::string fullCmd = "cmd.exe /c " + cmd;

  if (CreateProcessA(nullptr, const_cast<char *>(fullCmd.c_str()), nullptr,
                     nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si,
                     &pi)) {

    WaitForSingleObject(pi.hProcess, timeout_sec * 1000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  } else {
    PrintLastError("CreateProcess failed");
  }
}

static void sync_time() {
  std::vector<std::pair<std::string, int>> komutlar = {
      {"sc start w32time", 3},
      {"w32tm /config /syncfromflags:manual "
       "/manualpeerlist:\"time.windows.com,0x9 time.google.com,0x9 "
       "pool.ntp.org,0x9\" /update",
       3},
      {"w32tm /resync /force", 5}};

  for (const auto &[komut, timeout] : komutlar) {
    RunCommand(komut, timeout);
  }
}

static void warping_loop() {
  while (g_keep_warping.load(std::memory_order_relaxed)) {
    geri_sar_6_saat();
    std::this_thread::sleep_for(std::chrono::seconds(5));
  }
}

static void warp_time_back() {
  InitRealTimeTracker();
  if (g_time_warped.exchange(true))
    return;

  g_keep_warping.store(true, std::memory_order_relaxed);

  if (g_warper_thread.joinable()) {
    g_warper_thread.join();
  }

  g_warper_thread = std::thread(warping_loop);
}

static void restore_time() {
  if (!g_time_warped.exchange(false))
    return;

  g_keep_warping.store(false, std::memory_order_relaxed);

  if (g_warper_thread.joinable()) {
    g_warper_thread.join();
  }

  restore_time_instant();
  // hostssil();
  flush_dns_cache();
  std::thread(sync_time).detach();
}

static bool TriggerPendingGatewaySend() {
  if (g_gateway_send_inflight.exchange(true)) {
    return false;
  }

  PendingGatewayRequest request;
  {
    std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
    if (!g_pending_gateway.valid) {
      g_gateway_send_inflight.store(false);
      return false;
    }
    request = g_pending_gateway;
  }

  std::thread([request]() {
    Log("[GUI] Manual gateway send requested");
    bool ok = SendViaLocalServer(request.jwt, request.sid, request.puuid,
                                 request.pid);
    if (ok) {
      Beep(880, 120);
      std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
      if (g_pending_gateway.valid && g_pending_gateway.jwt == request.jwt &&
          g_pending_gateway.sid == request.sid) {
        g_pending_gateway.valid = false;
      }
    } else {
      Log("[GUI] Manual gateway send failed; request kept pending");
    }
    g_gateway_send_inflight.store(false);
  }).detach();

  return true;
}

static bool TriggerGatewayManualAction() {
  constexpr ULONGLONG MANUAL_GATEWAY_COOLDOWN_MS = 10000;
  ULONGLONG now_ms = GetTickCount64();
  ULONGLONG last_trigger_ms = g_gateway_manual_last_trigger_ms.load();
  if (last_trigger_ms != 0 &&
      (now_ms - last_trigger_ms) < MANUAL_GATEWAY_COOLDOWN_MS) {
    ULONGLONG remaining_ms =
        MANUAL_GATEWAY_COOLDOWN_MS - (now_ms - last_trigger_ms);
    Log("[GUI] F1 ignored: manual gateway cooldown " +
        std::to_string((remaining_ms + 999) / 1000) + "s");
    return false;
  }

  bool has_pending_request = false;
  {
    std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
    has_pending_request = g_pending_gateway.valid;
  }
  if (has_pending_request) {
    bool triggered = TriggerPendingGatewaySend();
    if (triggered) {
      g_gateway_manual_last_trigger_ms.store(now_ms);
    }
    return triggered;
  }

  std::string jwt;
  std::string puuid;
  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    jwt = g_cached_jwt;
    puuid = g_cached_puuid;
  }

  if (jwt.empty() || puuid.empty()) {
    Log("[GUI] F1 ignored: no cached gateway session");
    return false;
  }

  if (g_gateway_manual_reauth_inflight.exchange(true)) {
    Log("[GUI] F1 ignored: manual re-auth already in flight");
    return false;
  }

  g_gateway_manual_last_trigger_ms.store(now_ms);

  std::thread([]() {
    Log("[GUI] F1 manual gateway re-auth requested");
    g_gw_reauth_needed.store(true);
    if (GatewayDoReauth()) {
      Beep(880, 120);
    }
    g_gateway_manual_reauth_inflight.store(false);
  }).detach();

  return true;
}

static bool TriggerGatewayAutoRefreshAction() {
  if (!g_gateway_auto_send.load()) {
    return false;
  }

  constexpr ULONGLONG MANUAL_GATEWAY_COOLDOWN_MS = 10000;
  ULONGLONG now_ms = GetTickCount64();
  ULONGLONG last_trigger_ms = g_gateway_manual_last_trigger_ms.load();
  if (last_trigger_ms != 0 &&
      (now_ms - last_trigger_ms) < MANUAL_GATEWAY_COOLDOWN_MS) {
    return false;
  }

  std::string jwt;
  std::string puuid;
  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    jwt = g_cached_jwt;
    puuid = g_cached_puuid;
  }

  if (jwt.empty() || puuid.empty()) {
    Log("[GW-AUTO] skipped: no cached jwt/puuid yet");
    return false;
  }

  if (g_gateway_manual_reauth_inflight.exchange(true)) {
    return false;
  }

  g_gateway_manual_last_trigger_ms.store(now_ms);

  std::thread([]() {
    g_gw_reauth_needed.store(true);
    if (GatewayDoReauth()) {
      Log("[GW] Gateway re-auth successful");
      Beep(880, 120);
    } else {
      Log("[GW] Gateway re-auth failed, keeping game active and retrying in "
          "background");
      restore_time();
      // hostssil();
    }
    g_gateway_manual_reauth_inflight.store(false);
  }).detach();

  return true;
}

static void GatewayHotkeyLoop() {
  Log(("[GUI] F2 / F3 hotkey loop active"));
  while (!g_shutdown.load()) {
    if (GetAsyncKeyState(VK_F2) & 1) {
      TriggerGatewayManualAction();
    }
    if (GetAsyncKeyState(VK_F3) & 1) {
      Log("[HOTKEY] F3 pressed -> Triggering manual session reset");
      g_gw_cooldown_until_sec.store(0.0);
      std::thread([]() {
        AutoResetSession();
        Log("[HOTKEY] F3 session reset completed (SmartGatewayMint handled "
            "inside reset).");
        Beep(880, 120);
      }).detach();
    }
    Sleep(50);
  }
}

static void TryExtractAndSend(const uint8_t *buf, DWORD len) {
  std::string ascii(len, ' ');
  for (DWORD i = 0; i < len; i++)
    if (buf[i] >= 0x20 && buf[i] < 0x7F)
      ascii[i] = (char)buf[i];
  static const std::regex jwt_re(
      R"((eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}))");
  static const std::regex uuid_re(
      R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");

  std::vector<std::string> all_jwts;
  std::sregex_iterator jit(ascii.begin(), ascii.end(), jwt_re), jend;
  for (; jit != jend; ++jit)
    all_jwts.push_back((*jit)[1].str());

  if (all_jwts.empty()) {
    Log("[PIPE] No JWT found in this scan.");
    return;
  }

  std::string jwt = all_jwts[0];
  Log("[PIPE] JWT candidates found=" + std::to_string(all_jwts.size()));

  std::string first_uuid, last_uuid;
  std::sregex_iterator it(ascii.begin(), ascii.end(), uuid_re), end;
  for (; it != end; ++it) {
    if (first_uuid.empty())
      first_uuid = it->str();
    last_uuid = it->str();
  }

  std::string puuid = first_uuid;
  if (puuid.empty())
    puuid = PuuidFromJwt(jwt);
  std::string ext_sid = ResolveNonEmptySid(jwt, last_uuid, puuid, "[PIPE]");
  uint32_t vpid = g_valorant_pid;
  Log("[PIPE] puuid=" + puuid.substr(0, 8) + " sid=" + ext_sid.substr(0, 8) +
      " pid=" + std::to_string(vpid));

  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    if (jwt == g_cached_jwt && ext_sid == g_cached_ext_sid) {
      return;
    }
    g_cached_jwt = jwt;
    g_cached_ext_sid = ext_sid;
    g_cached_sid = ext_sid;
    g_cached_puuid = puuid;
  }

  Log("[PIPE] NEW AUTH_TOKEN captured (length: " + std::to_string(jwt.size()) +
      ")");
  QueuePendingGatewayRequest(jwt, ext_sid, puuid, vpid);

  Log("[PIPE] calling SendViaLocalServer (JWT auth)");
  std::thread([jwt, ext_sid, puuid, vpid]() {
    bool ok = SendViaLocalServer(jwt, ext_sid, puuid, vpid);
    if (!ok) {
      Log("[PIPE] SendViaLocalServer failed, trying SmartGatewayMint");
      SmartGatewayMint(jwt, ext_sid, puuid, vpid);
    }
  }).detach();
}

static uint32_t PipeReadU32(const uint8_t *p) {
  uint32_t v = 0;
  memcpy(&v, p, sizeof(v));
  return v;
}

static void PipeWriteU32(std::vector<uint8_t> &v, size_t off, uint32_t value) {
  if (v.size() >= off + sizeof(value))
    memcpy(v.data() + off, &value, sizeof(value));
}

static void PipeWriteU64(std::vector<uint8_t> &v, size_t off, uint64_t value) {
  if (v.size() >= off + sizeof(value))
    memcpy(v.data() + off, &value, sizeof(value));
}

static bool PipeWriteAndFlush(HANDLE pipe, const std::vector<uint8_t> &data,
                              const std::string &tag) {
  if (data.empty()) {
    Log(tag + " skipped empty write");
    return false;
  }
  DWORD bw = 0;
  BOOL ok = WriteFile(pipe, data.data(), (DWORD)data.size(), &bw, nullptr);
  if (ok)
    FlushFileBuffers(pipe);
  Log(tag + " written=" + std::to_string(bw) + "/" +
      std::to_string(data.size()) +
      (ok ? "" : " err=" + std::to_string(GetLastError())));
  return ok && bw == data.size();
}

static int PipeCompatNextMagic(int magic) {
  static std::mutex magic_mtx;
  static int step = -1;
  std::lock_guard<std::mutex> lk(magic_mtx);
  step = (step + 1) % 5;
  if (step == 0)
    return magic + 1;
  if (step == 1)
    return magic + 3;
  if (step == 2)
    return magic - 1;
  if (step == 3)
    return magic + 2;
  return magic + 5;
}

static std::string PipeExtractFirstUuid(const uint8_t *data, size_t n) {
  std::string ascii((const char *)data, (const char *)data + n);
  static const std::regex uuid_re(
      R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
  std::smatch m;
  if (std::regex_search(ascii, m, uuid_re))
    return m[0].str();
  return "";
}

static bool PipeParseUuidBytes(const std::string &uuid, uint8_t out[16]) {
  if (uuid.size() != 36)
    return false;
  auto hexval = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };

  uint8_t raw[16]{};
  int ri = 0;
  for (size_t i = 0; i < uuid.size();) {
    if (uuid[i] == '-') {
      ++i;
      continue;
    }
    if (i + 1 >= uuid.size() || ri >= 16)
      return false;
    int hi = hexval(uuid[i]);
    int lo = hexval(uuid[i + 1]);
    if (hi < 0 || lo < 0)
      return false;
    raw[ri++] = (uint8_t)((hi << 4) | lo);
    i += 2;
  }
  if (ri != 16)
    return false;

  out[0] = raw[3];
  out[1] = raw[2];
  out[2] = raw[1];
  out[3] = raw[0];
  out[4] = raw[5];
  out[5] = raw[4];
  out[6] = raw[7];
  out[7] = raw[6];
  memcpy(out + 8, raw + 8, 8);
  return true;
}

static std::vector<uint8_t> PipeBuildCompatAuthAck(int magic,
                                                   const std::string &uuid) {
  std::vector<uint8_t> ack(0x3c, 0);
  PipeWriteU32(ack, 0, (uint32_t)(magic + 1));
  PipeWriteU32(ack, 4, 0x40);
  PipeWriteU32(ack, 8, 1);
  PipeWriteU32(ack, 0x18, 0x18);

  uint8_t guid[16]{};
  if (PipeParseUuidBytes(uuid, guid)) {
    memcpy(ack.data() + 0x24, guid, sizeof(guid));
  } else {
    Log("[PIPE][COMPAT] auth ack uuid parse failed, GUID left zero uuid=" +
        uuid);
  }

  uint64_t timestamp =
      (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  PipeWriteU64(ack, 0x34, timestamp);
  return ack;
}

static bool SendPipeDisconnectMessage(HANDLE pipe, const std::string &reason) {
  if (!pipe || pipe == INVALID_HANDLE_VALUE) {
    Log("[PIPE][DISCONNECT] skipped: invalid pipe reason=" + reason);
    return false;
  }

  std::vector<uint8_t> payload(36, 0);
  payload[0] = 0x02;
  payload[4] = 0x24;
  payload[8] = 0x01;
  PipeWriteU32(payload, 24, 0x539);

  Log("[PIPE][DISCONNECT] sending 36-byte payload reason=" + reason);
  return PipeWriteAndFlush(pipe, payload, "[PIPE][DISCONNECT] payload");
}

static bool SendDisconnectMessageToCurrentPipe(const std::string &reason) {
  HANDLE pipe = (HANDLE)g_current_pipe.load();
  return SendPipeDisconnectMessage(pipe, reason);
}

static std::atomic_bool g_vgc_stopped_once{false};

static std::string GetPacketTypeDescription(const uint8_t *buf,
                                            DWORD bytesRead) {
  if (bytesRead == 0)
    return "EMPTY";
  if (buf[0] == 0x60 || (bytesRead == 40 && buf[0] == 0x03))
    return "Heartbeat / ACK (0x60 / 0x03)";
  if (buf[0] == 0x64)
    return "AUTH_REQUEST (0x64)";
  if (buf[0] == 0x65)
    return "TASKS_DATA (0x65)";
  if (buf[0] == 0x66)
    return "MODULES_DATA (0x66)";
  if (buf[0] == 0x67)
    return "VGK_PAYLOAD (0x67)";
  if (buf[0] == 0x68 && bytesRead == 68)
    return "RAW_ECHO_68B (0x68)";
  if (buf[0] == 0x69 || buf[0] == 0x6A || buf[0] == 0x6B || buf[0] == 0x6C) {
    std::ostringstream o;
    o << "ACK_VARIANT (0x" << std::hex << std::setw(2) << std::setfill('0')
      << (int)buf[0] << ")";
    return o.str();
  }
  if (buf[0] == 0x70)
    return "UNKNOWN_RESPONSE (0x70)";
  if (bytesRead >= 36) {
    uint32_t compat_type = PipeReadU32(buf + 8);
    switch (compat_type) {
    case 1:
      return "COMPAT_TYPE_1 (Echo ACK)";
    case 2:
      return "COMPAT_TYPE_2 (ACK)";
    case 4:
      return "COMPAT_TYPE_4 (Auth ACK)";
    case 5:
      return "COMPAT_TYPE_5 (Modules ACK)";
    case 6:
      return "COMPAT_TYPE_6 (Task ACK)";
    }
  }
  if (bytesRead >= 4)
    return "DEFAULT_ECHO";
  return "UNKNOWN_PACKET";
}

static void HandlePipeClient(HANDLE pipe) {
  std::vector<uint8_t> buf(16384);
  DWORD bytesRead;
  int hb_count = 0;
  int packet_count = 0;
  g_current_pipe.store((void *)pipe);
  Log("[PIPE] current pipe handle registered");

  if (!g_vgc_stopped_once.exchange(true)) {
    Log("[PIPE] first client — sc stop vgc");
    std::thread([]() { system("sc stop vgc >nul 2>&1"); }).detach();
  }

  {
    std::vector<uint8_t> challenge(36, 0);
    PipeWriteU64(challenge, 0, 0x24000003e9ULL);
    PipeWriteU64(challenge, 8, 1);
    PipeWriteU32(challenge, 24, 4);
    PipeWriteAndFlush(pipe, challenge,
                      "[PIPE] initial 36-byte challenge handshake");
  }
  while (!g_shutdown.load()) {
    if (!ReadFile(pipe, buf.data(), (DWORD)buf.size(), &bytesRead, nullptr) ||
        bytesRead == 0) {
      if (g_session_reset_in_progress.load()) {
        Log("[PIPE] ReadFile returned error/0 during session reset — keeping "
            "pipe connection alive...");
        Sleep(500);
        continue;
      }
      break;
    }
    packet_count++;
    std::string pkt_desc = GetPacketTypeDescription(buf.data(), bytesRead);
    Log("[PIPE][PACKET] Packet #" + std::to_string(packet_count) +
        " | Type Byte: 0x" +
        [&] {
          std::ostringstream o;
          o << std::hex << std::setw(2) << std::setfill('0') << (int)buf[0];
          return o.str();
        }() +
        " | Size: " + std::to_string(bytesRead) + " bytes | Type: " + pkt_desc);

    // FIX 3: Always scan all incoming pipe packets for credentials
    if (bytesRead > 32) {
      TryExtractAndSend(buf.data(), bytesRead);
    }

    if (buf[0] == 0x60 || (bytesRead == 40 && buf[0] == 0x03)) {
      std::vector<uint8_t> resp(buf.data(), buf.data() + bytesRead);
      if (buf[0] == 0x03 && bytesRead == 40)
        resp[0] = 0x04;
      PipeWriteAndFlush(pipe, resp,
                        "[PIPE][0x60] Heartbeat / ACK #" +
                            std::to_string(++hb_count));
      {
        std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
        for (auto &kv : g_session_mgr.sessions)
          kv.second->last_activity = NowSec();
      }
      continue;
    }

    if (buf[0] == 0x64) {
      std::ostringstream rawHex;
      DWORD logLen = bytesRead < 16 ? bytesRead : 16;
      for (DWORD i = 0; i < logLen; i++)
        rawHex << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i]
               << " ";
      Log("[PIPE][0x64] AUTH_REQUEST bytes=" + std::to_string(bytesRead) +
          " raw=" + rawHex.str());

      if (bytesRead > 40) {
        Log("[PIPE][0x64] scanning for JWT inside auth request...");
        TryExtractAndSend(buf.data(), bytesRead);
      }

      std::string jwt, puuid, sid, region;
      {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt = g_cached_jwt;
        puuid = g_cached_puuid;
        sid = g_cached_sid;
        region = g_cached_region;
      }

      if (jwt.empty()) {
        Log("[PIPE][0x64] JWT not yet available, waiting 2s...");
        Sleep(2000);
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt = g_cached_jwt;
        puuid = g_cached_puuid;
        sid = g_cached_sid;
        region = g_cached_region;
      }

      region = ApplyConfiguredRegion(region, "[PIPE][0x64]");
      Log("[PIPE][0x64] jwt=" +
          (jwt.empty() ? "EMPTY" : jwt.substr(0, 20) + "...") +
          " puuid=" + (puuid.empty() ? "EMPTY" : puuid.substr(0, 8) + "..."));

      auto pkt = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
      auto resp = g_tasks_handler.handle_auth_request(jwt, puuid, sid, region);
      if (!jwt.empty()) {
        std::thread([]() { g_round_tracker.on_round_end(); }).detach();
      }
      PipeWriteAndFlush(pipe, resp, "[PIPE][0x64] AUTH_REQUEST response");
      Log("[PIPE] AUTH_REQUEST (0x64) handled, response sent");
      continue;
    }

    if (bytesRead >= 36) {
      const int compat_type = (int)PipeReadU32(buf.data() + 8);
      if (compat_type == 1 || compat_type == 2 || compat_type == 4 ||
          compat_type == 5 || compat_type == 6) {
        const int magic = (int)PipeReadU32(buf.data());
        std::vector<uint8_t> reply;
        bool inject_type_9 = false;

        Log("[PIPE][COMPAT] struct type=" + std::to_string(compat_type) +
            " magic=0x" +
            [&] {
              std::ostringstream o;
              o << std::hex << magic;
              return o.str();
            }() +
            " bytes=" + std::to_string(bytesRead));

        if (compat_type == 6) {
          // FIX: Proper task ACK for type 6
          reply.assign(40, 0);
          const int reply_magic = PipeCompatNextMagic(magic);
          PipeWriteU32(reply, 0, (uint32_t)reply_magic);
          PipeWriteU32(reply, 4, 40);
          PipeWriteU32(reply, 8, 1);
          PipeWriteU32(reply, 24, 0x539);
          Log("[PIPE][COMPAT] type 6 task ACK magic=0x" + [&] {
            std::ostringstream o;
            o << std::hex << reply_magic;
            return o.str();
          }());
        } else if (compat_type == 5) {
          // FIX: Proper module ACK for type 5
          reply.assign(56, 0);
          const int reply_magic = PipeCompatNextMagic(magic);
          PipeWriteU32(reply, 0, (uint32_t)reply_magic);
          PipeWriteU32(reply, 4, 56);
          PipeWriteU32(reply, 8, 1);
          PipeWriteU32(reply, 24, 16);
          PipeWriteU32(reply, 28, 0x01); // Module status
          PipeWriteU32(reply, 32, 0x01); // Module version
          Log("[PIPE][COMPAT] type 5 modules ACK magic=0x" + [&] {
            std::ostringstream o;
            o << std::hex << reply_magic;
            return o.str();
          }());
        } else if (compat_type == 4) {
          if (bytesRead > 100) {
            Log("[PIPE][COMPAT] type 4 scanning for JWT/SID");
            TryExtractAndSend(buf.data(), bytesRead);
          }

          std::string active_uuid = PipeExtractFirstUuid(buf.data(), bytesRead);
          if (active_uuid.empty()) {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            active_uuid = !g_cached_sid.empty() ? g_cached_sid : g_cached_puuid;
          }
          if (active_uuid.empty())
            active_uuid = "00000000-0000-0000-0000-000000000000";

          reply = PipeBuildCompatAuthAck(magic, active_uuid);
          inject_type_9 = true;
          Log("[PIPE][COMPAT] type 4 auth ACK uuid=" + active_uuid +
              " reply_magic=0x" + [&] {
                std::ostringstream o;
                o << std::hex << (magic + 1);
                return o.str();
              }());
        } else if (compat_type == 1) {
          reply.assign(buf.data(), buf.data() + bytesRead);
          const int reply_magic = PipeCompatNextMagic(magic);
          PipeWriteU32(reply, 0, (uint32_t)reply_magic);
          Log("[PIPE][COMPAT] type 1 echo ACK magic=0x" + [&] {
            std::ostringstream o;
            o << std::hex << reply_magic;
            return o.str();
          }());
        } else if (compat_type == 2) {
          reply.assign(48, 0);
          const int reply_magic = PipeCompatNextMagic(magic);
          PipeWriteU32(reply, 0, (uint32_t)reply_magic);
          PipeWriteU32(reply, 4, 48);
          PipeWriteU32(reply, 8, 1);
          PipeWriteU32(reply, 24, 8);
          Log("[PIPE][COMPAT] type 2 ACK magic=0x" + [&] {
            std::ostringstream o;
            o << std::hex << reply_magic;
            return o.str();
          }());
        }

        PipeWriteAndFlush(pipe, reply,
                          "[PIPE][COMPAT] type " + std::to_string(compat_type) +
                              " reply");

        if (inject_type_9) {
          Sleep(200);
          std::vector<uint8_t> injected(40, 0);
          const int injected_magic = PipeCompatNextMagic(magic);
          PipeWriteU32(injected, 0, (uint32_t)injected_magic);
          PipeWriteU32(injected, 4, 40);
          PipeWriteU32(injected, 8, 9);
          PipeWriteAndFlush(pipe, injected,
                            "[PIPE][COMPAT] injected type 9 session-auth");
        }
        continue;
      }
    }

    if (buf[0] == 0x65 && bytesRead >= 4) {
      auto pkt = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
      auto ack = g_tasks_handler.handle_packet(pkt);
      PipeWriteAndFlush(pipe, ack, "[PIPE][0x65] TASKS ACK");
      Log("[PIPE] TASKS packet (0x65) acked");
      if (bytesRead > 100) {
        Log("[PIPE][0x65] scanning for JWT inside tasks packet...");
        std::string old_jwt;
        {
          std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
          old_jwt = g_cached_jwt;
        }
        TryExtractAndSend(buf.data(), bytesRead);
        std::string new_jwt;
        {
          std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
          new_jwt = g_cached_jwt;
        }
        if (!new_jwt.empty() && new_jwt != old_jwt && !old_jwt.empty()) {
          Log("[LOBBY] JWT changed – previous match ended, new match starting");
          Log("[LOBBY] Triggering gateway re-auth for new match");
          g_gw_reauth_needed.store(true);
          g_gateway_reauth_remaining_sec.store(0);
          UpdateConsoleTitle();
        }
      }
      continue;
    }

    if (buf[0] == 0x66 && bytesRead >= 4) {
      auto pkt = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
      auto ack = g_tasks_handler.handle_packet(pkt);
      PipeWriteAndFlush(pipe, ack, "[PIPE][0x66] MODULES ACK");
      Log("[PIPE] MODULES packet (0x66) acked");
      continue;
    }

    // FIX 2 (IMPORTANT): Only store packet if data size > 100 bytes; if <= 100
    // bytes log as "echo packet ignored"
    if (buf[0] == 0x67 && bytesRead >= 4) {
      if (bytesRead > 100) {
        std::vector<uint8_t> payload(buf.data(), buf.data() + bytesRead);
        {
          std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
          g_vgk_payload = payload;
        }
        Log("[PIPE][IPC] Captured and stored real IPC data packet (type 0x67, "
            "size: " +
            std::to_string(bytesRead) +
            " bytes) into global storage with mutex protection");
      } else {
        Log("[PIPE][IPC] echo packet ignored (type 0x67, size: " +
            std::to_string(bytesRead) + " bytes <= 100 bytes)");
      }
      uint32_t magic;
      memcpy(&magic, buf.data(), 4);
      uint32_t nm = magic + 1;
      std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
      memcpy(echo.data(), &nm, 4);
      PipeWriteAndFlush(pipe, echo, "[PIPE][0x67] echo");
      continue;
    }

    if (buf[0] == 0x68 && bytesRead == 68) {
      Log("[PIPE] echo packet ignored (type 0x68, size: 68 bytes <= 100 "
          "bytes)");
      std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
      PipeWriteAndFlush(pipe, echo, "[PIPE][0x68] 68-byte raw echo");
      continue;
    }

    if ((buf[0] == 0x69 || buf[0] == 0x6A || buf[0] == 0x6B ||
         buf[0] == 0x6C) &&
        bytesRead >= 4) {
      std::ostringstream tag;
      tag << "[PIPE][0x" << std::hex << (int)buf[0] << "] ACK variant";
      uint32_t magic;
      memcpy(&magic, buf.data(), 4);
      uint32_t nm = magic + 1;
      std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
      memcpy(echo.data(), &nm, 4);
      PipeWriteAndFlush(pipe, echo, tag.str());
      continue;
    }

    if (buf[0] == 0x70 && bytesRead >= 4) {
      Log("[PIPE][0x70] Response / Unknown packet received (size: " +
          std::to_string(bytesRead) + " bytes)");
      uint32_t magic;
      memcpy(&magic, buf.data(), 4);
      uint32_t nm = magic + 1;
      std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
      memcpy(echo.data(), &nm, 4);
      PipeWriteAndFlush(pipe, echo, "[PIPE][0x70] response echo");
      continue;
    }

    if (bytesRead >= 4) {
      uint32_t magic;
      memcpy(&magic, buf.data(), 4);
      uint32_t nm = magic + 1;
      std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
      memcpy(echo.data(), &nm, 4);
      PipeWriteAndFlush(pipe, echo, "[PIPE] default echo");
    }
  }
  SendPipeDisconnectMessage(pipe, "pipe thread ending");
  void *expected_pipe = (void *)pipe;
  g_current_pipe.compare_exchange_strong(expected_pipe, nullptr);
  CloseHandle(pipe);
  Log("[PIPE][DISCONNECT] Pipe client disconnected — clearing old session "
      "credentials and waiting for new connection with fresh data.");

  // FIX 5 (IMPORTANT): Handle disconnection properly — clear cached credentials
  // and session manager, do NOT auto-restore old session
  g_session_reset_needed.store(false);
  ClearCachedCredentials();
  g_session_mgr.clear();

  g_round_tracker.on_lobby_return([&]() {});
}

static void PipeServerLoop() {
  while (!g_shutdown.load()) {
    HANDLE pipe = CreateNamedPipeW(
        PIPE_NAME, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 1048576, 1048576, 500, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
      Sleep(1000);
      continue;
    }
    Log(("[PIPE] Waiting for client..."));
    if (ConnectNamedPipe(pipe, nullptr) ||
        GetLastError() == ERROR_PIPE_CONNECTED) {
      Log("[PIPE] Client connected");
      std::thread(HandlePipeClient, pipe).detach();
    } else {
      CloseHandle(pipe);
    }
  }
}

static uint32_t GetValorantPID() {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  uint32_t pid = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pid;
}

struct ActiveSessionInfo {
  std::string puuid;
  std::string region;
  std::string account;
  std::chrono::steady_clock::time_point start_time;
  bool active = false;
};
static ActiveSessionInfo g_active_session;
static std::mutex g_display_mtx;

static void UpdateDisplaySessionState(const std::string &puuid,
                                      const std::string &region,
                                      const std::string &account) {
  std::lock_guard<std::mutex> lk(g_display_mtx);
  g_active_session.puuid = puuid;
  g_active_session.region = region;
  g_active_session.account = account;
  g_active_session.start_time = std::chrono::steady_clock::now();
  g_active_session.active = true;
}

static void ClearConsole() {
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  if (!GetConsoleScreenBufferInfo(h, &csbi))
    return;
  DWORD cells = csbi.dwSize.X * csbi.dwSize.Y, written;
  COORD origin = {0, 0};
  FillConsoleOutputCharacterA(h, ' ', cells, origin, &written);
  FillConsoleOutputAttribute(h, csbi.wAttributes, cells, origin, &written);
  SetConsoleCursorPosition(h, origin);
}

static void ResizeConsoleWindowTall() {
  HWND hwnd = GetConsoleWindow();
  if (!hwnd)
    return;

  RECT rc{};
  if (!GetWindowRect(hwnd, &rc))
    return;

  const int width = rc.right - rc.left;
  const int height = 720;
  SetWindowPos(hwnd, nullptr, rc.left, rc.top, width, height,
               SWP_NOZORDER | SWP_NOACTIVATE);
}

static void SetColor(WORD attr) {
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}

#define COL_CYAN (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COL_WHITE                                                              \
  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COL_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COL_GREEN (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COL_RED (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COL_GRAY (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define COL_ORANGE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COL_DIM (FOREGROUND_BLUE | FOREGROUND_INTENSITY)

static std::string ShortValue(const std::string &value, size_t keep = 8) {
  if (value.empty())
    return "--";
  if (value.size() <= keep)
    return value;
  return value.substr(0, keep) + "...";
}

static std::string UpperAscii(std::string value) {
  for (char &c : value) {
    if (c >= 'a' && c <= 'z')
      c = (char)(c - ('a' - 'A'));
  }
  return value.empty() ? "--" : value;
}

static std::string FormatClock(int total_seconds) {
  if (total_seconds < 0)
    total_seconds = 0;
  int hh = total_seconds / 3600;
  int mm = (total_seconds % 3600) / 60;
  int ss = total_seconds % 60;
  char buf[32];
  sprintf_s(buf, "%02d:%02d:%02d", hh, mm, ss);
  return std::string(buf);
}

static void DrawHorizontalRule(char ch = '=') {
  SetColor(COL_DIM);
  for (int i = 0; i < 78; ++i)
    std::cout << ch;
  std::cout << "\n";
}

static void DrawHorizontalRuleColored(char ch, WORD color) {
  SetColor(color);
  for (int i = 0; i < 78; ++i)
    std::cout << ch;
  std::cout << "\n";
}

static void DrawField(const char *label, const std::string &value,
                      WORD value_color = COL_WHITE) {
  SetColor(COL_GRAY);
  std::cout << "  " << label;
  SetColor(value_color);
  std::cout << value << "\n";
}

static int g_log_counter = 0;

static std::string GetTimestamp() {
  auto now = std::chrono::system_clock::now();
  auto time_now = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;
  std::tm bt{};
  localtime_s(&bt, &time_now);
  char buf[64];
  sprintf_s(buf, "%02d:%02d:%02d.%03d", bt.tm_hour, bt.tm_min, bt.tm_sec,
            (int)ms.count());
  return std::string(buf);
}

static void AddFunnyLog(const std::string &msg) {
  std::lock_guard<std::mutex> lock(g_log_mutex);
  g_log_lines.push_back(("[") + GetTimestamp() + ("] ") + msg);
  if (g_log_lines.size() > 20) {
    g_log_lines.erase(g_log_lines.begin());
  }
}

static std::atomic_bool g_display_running(false);
static void DisplayLoop() {
  while (g_display_running.load()) {
    Sleep(500);
  }
}

void CreateVanguardMutex() {
  if (g_vanguard_mutex == nullptr) {
    g_vanguard_mutex = CreateMutexA(
        NULL, FALSE, "Global\\587203BC-5798-47BA-8BDA-C63D7DE25FCD");
    if (g_vanguard_mutex != nullptr) {
      Log("Created simulated Vanguard mutex.");
    }
  }
}

void CreateVanguardSharedMemory() {
  if (g_vanguard_shared_memory == nullptr) {
    g_vanguard_shared_memory = CreateFileMappingA(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000,
        "Global\\294E088E-E3EF-42A9-AE0C-1EF642412F95");
    if (g_vanguard_shared_memory == nullptr) {
      Log("Failed to create simulated Vanguard shared memory.");
    } else {
      Log("Created simulated Vanguard shared memory (FileMapping).");
    }
  }
}

BOOL WINAPI CtrlHandler(DWORD t) {
  if (t == CTRL_CLOSE_EVENT || t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT ||
      t == CTRL_SHUTDOWN_EVENT) {
    restore_time();
    restore_time();
    TerminateProcessByName(L"VALORANT-Win64-Shipping.exe");
    TerminateProcessByName(L"VALORANT.exe");
    // hostssil();
  }
  return TRUE;
}

std::atomic_bool shutdown_event(false);

// ─── ShooterGame.log Monitor Thread ────────────────────────────────────────
static std::atomic<long long> g_log_last_pos(0);

static std::string get_shooter_log_path() {
  char localapp[MAX_PATH] = {};
  GetEnvironmentVariableA(xorstr_("LOCALAPPDATA"), localapp, MAX_PATH);
  return std::string(localapp) +
         xorstr_("\\VALORANT\\Saved\\Logs\\ShooterGame.log");
}

static void shooter_log_monitor_thread() {
  const std::string log_path = get_shooter_log_path();

  {
    std::ifstream f(log_path, std::ios::binary | std::ios::ate);
    if (f.is_open())
      g_log_last_pos.store((long long)f.tellg());
  }

  static const char *MATCH_END_KW[] = {"MatchDetails",
                                       "match-details",
                                       "postmatch",
                                       "PostMatch",
                                       "GameFinished",
                                       "GameEnd",
                                       "UnregisteringPlayer",
                                       "LeavingMatch",
                                       "MatchHistory",
                                       "game_finished",
                                       "Leaving state: InGame",
                                       "PostGame",
                                       nullptr};

  static const char *DODGE_KW[] = {
      "Pregame_Destroy",    "Pregame_Leave",         "Pregame_Quit",
      "Pregame_Dodge",      "Pregame_State_Destroy", "Leaving state: PreGame",
      "Matchmaking_Cancel", "PreGame -> Lobby",      nullptr};

  static ULONGLONG last_gateway_refresh_ms = 0;

  auto trigger_lobby_gateway_refresh = [](const char *reason) {
    std::string jwt, puuid;
    {
      std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
      jwt = g_cached_jwt;
      puuid = g_cached_puuid;
    }
    if (jwt.empty() || puuid.empty()) {
      return;
    }
    ULONGLONG now = GetTickCount64();
    if (last_gateway_refresh_ms != 0 &&
        (now - last_gateway_refresh_ms) < 15000) {
      return;
    }
    last_gateway_refresh_ms = now;
    Log(std::string("[LOBBY-AUTO] Refreshing gateway session (reason: ") +
        reason + ")");
    restore_time();
    TriggerGatewayAutoRefreshAction();
  };

  while (!shutdown_event.load()) {
    Sleep(500);

    long long cur_size = 0;
    {
      std::ifstream f(log_path, std::ios::binary | std::ios::ate);
      if (!f.is_open())
        continue;
      cur_size = (long long)f.tellg();
    }

    long long last_pos = g_log_last_pos.load();
    if (cur_size < last_pos) {
      g_log_last_pos.store(0);
      last_pos = 0;
    }
    if (cur_size == last_pos)
      continue;

    long long to_read = cur_size - last_pos;
    if (to_read > 512 * 1024) {
      g_log_last_pos.store(cur_size);
      continue;
    }

    std::string raw((size_t)to_read, '\0');
    {
      std::ifstream f(log_path, std::ios::binary);
      if (!f.is_open())
        continue;
      f.seekg(last_pos);
      f.read(&raw[0], to_read);
    }
    g_log_last_pos.store(cur_size);

    std::istringstream iss(raw);
    std::string line;
    while (std::getline(iss, line)) {

      if (line.find(xorstr_("Pregame_LockCharacter")) != std::string::npos) {
        Log("[PREGAME] Agent locked - keeping system clock & DNS clean for "
            "match load");
        restore_time();
        // hostssil();
      }

      for (int i = 0; DODGE_KW[i]; ++i) {
        if (line.find(DODGE_KW[i]) != std::string::npos) {
          trigger_lobby_gateway_refresh("agent select dodge/cancelled");
          break;
        }
      }

      for (int i = 0; MATCH_END_KW[i]; ++i) {
        if (line.find(MATCH_END_KW[i]) != std::string::npos) {
          trigger_lobby_gateway_refresh("match finished");
          break;
        }
      }
    }
  }
}

static void adjust_privileges() {
  HANDLE hToken;
  TOKEN_PRIVILEGES tp;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    return;
  LUID luid;
  if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
    CloseHandle(hToken);
    return;
  }
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
  CloseHandle(hToken);
}

static bool detect_bad_programs() {

  static const char *window_classes[] = {
      "Fiddler",        "Charles",   "HTTPDebuggerUI",
      "Wireshark",      "mitmproxy", "BurpSuiteCommunity",
      "ollydbg",        "OLLYDBG",   "WinDbgFrameClass",
      "x64dbg",         "x32dbg",    "ID_MAIN_WINDOW",
      "Qt5QWindowIcon", nullptr};

  static const wchar_t *process_names[] = {L"httpdebugger.exe",
                                           L"httpdebuggerui.exe",
                                           L"fiddler.exe",
                                           L"fiddler4.exe",
                                           L"fiddlercap.exe",
                                           L"charles.exe",
                                           L"wireshark.exe",
                                           L"mitmproxy.exe",
                                           L"mitmdump.exe",
                                           L"mitmweb.exe",
                                           L"burpsuite.exe",
                                           L"burp.exe",
                                           L"ollydbg.exe",
                                           L"x64dbg.exe",
                                           L"x32dbg.exe",
                                           L"windbg.exe",
                                           L"ida.exe",
                                           L"ida64.exe",
                                           L"idaq.exe",
                                           L"idaq64.exe",
                                           L"idaw.exe",
                                           L"idaw64.exe",
                                           L"cheatengine.exe",
                                           L"cheatengine-x86_64.exe",
                                           L"cheatengine-i386.exe",
                                           L"processhacker.exe",
                                           L"procmon.exe",
                                           L"procmon64.exe",
                                           L"procexp.exe",
                                           L"procexp64.exe",
                                           L"httptoolkit.exe",
                                           L"proxifier.exe",
                                           L"everything.exe",
                                           nullptr};

  for (int i = 0; window_classes[i] != nullptr; ++i) {
    if (FindWindowA(window_classes[i], nullptr) != nullptr)
      return true;
  }

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
      do {
        wchar_t lower[MAX_PATH] = {};
        wcsncpy_s(lower, pe.szExeFile, MAX_PATH - 1);
        for (wchar_t *p = lower; *p; ++p)
          *p = (wchar_t)towlower(*p);
        for (int j = 0; process_names[j] != nullptr; ++j) {
          if (wcscmp(lower, process_names[j]) == 0) {
            CloseHandle(snap);
            return true;
          }
        }
      } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
  }

  if (IsDebuggerPresent())
    return true;

  BOOL remote_dbg = FALSE;
  CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_dbg);
  if (remote_dbg)
    return true;

  return false;
}

static bool detect_virtual_machine() { return false; }

static uint32_t compute_exe_crc32() {
  wchar_t path[MAX_PATH] = {};
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (f == INVALID_HANDLE_VALUE)
    return 0;
  uint32_t crc = 0xFFFFFFFF;
  static const uint32_t table[256] = {
      0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
      0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91B, 0x97D2D988,
      0x09B64C2B, 0x7EB17CBF, 0xE7B82D09, 0x90BF1D3B, 0x1DB71064, 0x6AB020F2,
      0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
      0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
      0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
      0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
      0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
      0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F928, 0x56B3C9BE,
      0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
      0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
      0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
      0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
      0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
      0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
      0x8BBEB8EA, 0xFCB9887C, 0x62DD1D7F, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
      0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
      0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
      0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
      0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
      0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
      0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
      0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
      0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
      0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
      0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
      0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
      0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
      0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
      0x316E2EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
      0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
      0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
      0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
      0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
      0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
      0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
      0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
      0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
      0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
      0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
      0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
      0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
      0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D};
  uint8_t buf[65536];
  DWORD rd;
  while (ReadFile(f, buf, sizeof(buf), &rd, nullptr) && rd > 0) {
    for (DWORD i = 0; i < rd; i++)
      crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
  }
  CloseHandle(f);
  return crc ^ 0xFFFFFFFF;
}

static uint32_t g_exe_crc_baseline = 0;

static void exe_integrity_init() { g_exe_crc_baseline = compute_exe_crc32(); }

static bool exe_integrity_check() {
  if (g_exe_crc_baseline == 0)
    return true;
  uint32_t cur = compute_exe_crc32();
  return cur == g_exe_crc_baseline;
}

static HANDLE g_instance_mutex = nullptr;

static bool ensure_single_instance() {
  g_instance_mutex = CreateMutexW(
      nullptr, TRUE, L"Global\\TechnoVerse_Loader_SingleInstance_7F3A2B");
  if (!g_instance_mutex)
    return false;
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(g_instance_mutex);
    g_instance_mutex = nullptr;
    return false;
  }
  return true;
}

static std::atomic<bool> g_protection_triggered{false};

static void protection_monitor_thread() {
  int check_counter = 0;
  while (!g_shutdown.load()) {
    Sleep(3000);
    check_counter++;

    if (IsDebuggerPresent()) {
      g_protection_triggered.store(true);
      Log("[PROTECT] Debugger detected at runtime - terminating");
      Sleep(500);
      ExitProcess(0);
    }

    ULONG_PTR peb_addr = __readgsqword(0x60);
    if (peb_addr) {
      ULONG ntglobalflag = *(ULONG *)(peb_addr + 0xBC);
      if (ntglobalflag & 0x70) {
        g_protection_triggered.store(true);
        Log("[PROTECT] PEB NtGlobalFlag debugger marker detected - "
            "terminating");
        Sleep(500);
        ExitProcess(0);
      }
    }

    BOOL remote_dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_dbg);
    if (remote_dbg) {
      g_protection_triggered.store(true);
      Log("[PROTECT] Remote debugger detected - terminating");
      Sleep(500);
      ExitProcess(0);
    }

    {
      ULONG_PTR peb_addr2 = __readgsqword(0x60);
      if (peb_addr2) {
        ULONG ntgf2 = *reinterpret_cast<ULONG *>(peb_addr2 + 0xBC);
        if (ntgf2 & 0x70) {
          g_protection_triggered.store(true);
          Log("[PROTECT] PEB NtGlobalFlag debugger marker detected - "
              "terminating");
          Sleep(500);
          ExitProcess(0);
        }
      }
    }

    if (check_counter % 5 == 0) {
      if (detect_bad_programs()) {
        g_protection_triggered.store(true);
        Log("[PROTECT] Hostile tool detected at runtime - terminating");
        Sleep(500);
        ExitProcess(0);
      }
    }

    if (check_counter % 20 == 0 && g_exe_crc_baseline != 0) {
      if (!exe_integrity_check()) {
        g_protection_triggered.store(true);
        Log("[PROTECT] EXE integrity violation detected - file was patched");
        Sleep(500);
        ExitProcess(0);
      }
    }
  }
}

static std::string g_serial_key_used;

#include <iostream>

static bool do_auth() { return true; }
static std::string winhttp_get(const wchar_t *host, INTERNET_PORT port,
                               const wchar_t *path, bool tls) {
  HINTERNET hS =
      WinHttpOpen(L"vanguard/1.18.5.11", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hS)
    return {};
  WinHttpSetTimeouts(hS, 5000, 10000, 10000, 10000);
  HINTERNET hC = WinHttpConnect(hS, host, port, 0);
  if (!hC) {
    WinHttpCloseHandle(hS);
    return {};
  }
  HINTERNET hR = WinHttpOpenRequest(
      hC, L"GET", path, nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES, tls ? WINHTTP_FLAG_SECURE : 0);
  if (!hR) {
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return {};
  }
  if (!WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0,
                          0)) {
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return {};
  }
  if (!WinHttpReceiveResponse(hR, nullptr)) {
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return {};
  }
  std::string resp;
  DWORD avail = 0;
  while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
    std::vector<char> chunk(avail);
    DWORD rd = 0;
    if (WinHttpReadData(hR, chunk.data(), (DWORD)chunk.size(), &rd) && rd > 0)
      resp.append(chunk.data(), rd);
  }
  WinHttpCloseHandle(hR);
  WinHttpCloseHandle(hC);
  WinHttpCloseHandle(hS);
  return resp;
}

static void vgm_killer_thread() {
  while (!shutdown_event.load()) {
    system("taskkill /f /im vgm.exe >nul 2>&1");
    Sleep(1000);
  }
}

static std::string SelectRegionMenu() {
  ClearConsole();
  SetColor(COL_CYAN);
  std::cout << "\n  ==============================" << std::endl;
  std::cout << "      SELECT YOUR REGION" << std::endl;
  std::cout << "          TechnoVerse" << std::endl;
  std::cout << "  ==============================\n" << std::endl;
  SetColor(COL_ORANGE);
  std::cout << "  [0] MFA Bypass (Account Verify)" << std::endl;
  SetColor(COL_WHITE);
  std::cout << "  [1] AP     (Asia Pacific)" << std::endl;
  std::cout << "  [2] BR     (Brazil)" << std::endl;
  std::cout << "  [3] EU     (Europe)" << std::endl;
  std::cout << "  [4] KR     (Korea)" << std::endl;
  std::cout << "  [5] LATAM  (Latin America)" << std::endl;
  std::cout << "  [6] NA     (North America)" << std::endl;
  SetColor(COL_CYAN);
  std::cout << "\n  ==============================\n" << std::endl;
  SetColor(COL_GRAY);
  std::cout << "  Enter choice (0-6): ";
  SetColor(COL_WHITE);

  int choice = 0;
  std::string input;
  std::getline(std::cin, input);
  if (!input.empty())
    choice = atoi(input.c_str());

  if (choice == 0) {
    mfa::on_msg = [](int type, const char *s) {
      if (type == 1) {
        SetColor(COL_GREEN);
        std::cout << "\n  [MFA] " << s << "\n";
      } else if (type == 2) {
        SetColor(COL_RED);
        std::cout << "\n  [MFA] " << s << "\n";
      } else {
        SetColor(COL_GRAY);
        std::cout << "\n  [MFA] " << s << "\n";
      }
      SetColor(COL_WHITE);
    };
    SetColor(COL_ORANGE);
    std::cout << "\n  MFA Bypass starting...\n";
    SetColor(COL_WHITE);
    mfa::RequestRun();
    Sleep(3000);
    return SelectRegionMenu();
  }

  switch (choice) {
  case 1:
    return "ap";
  case 2:
    return "br";
  case 3:
    return "eu";
  case 4:
    return "kr";
  case 5:
    return "la";
  case 6:
    return "na";
  default:
    SetColor(COL_RED);
    std::cout << "\n  Invalid choice, defaulting to EU.\n";
    Sleep(1500);
    return "eu";
  }
}

static std::string RegionDisplayName(const std::string &r) {
  if (r == "ap")
    return "AP";
  if (r == "br")
    return "BR";
  if (r == "eu")
    return "EU";
  if (r == "kr")
    return "KR";
  if (r == "la")
    return "LATAM";
  if (r == "na")
    return "NA";
  return "UNKNOWN";
}

static bool VerifyLicenseKey() { return true; }

static bool g_console_visible = false;

static void ToggleConsoleWindowVisibility(bool show) {
  HWND hConsole = GetConsoleWindow();
  if (!hConsole)
    return;

  HWND hTop = GetAncestor(hConsole, GA_ROOT);
  if (!hTop)
    hTop = hConsole;

  // On Windows 11 Windows Terminal, GetAncestor(hConsole, GA_ROOT) might return
  // the Terminal host window which houses tabs. Hide all owner/parent windows up the tree.
  HWND hCur = hConsole;
  while (hCur) {
    LONG_PTR exStyle = GetWindowLongPtr(hCur, GWL_EXSTYLE);
    if (!show) {
      SetWindowLongPtr(hCur, GWL_EXSTYLE, (exStyle | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW);
      ShowWindow(hCur, SW_HIDE);
    } else {
      SetWindowLongPtr(hCur, GWL_EXSTYLE, (exStyle & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW);
      ShowWindow(hCur, SW_SHOW);
    }
    HWND hOwner = GetWindow(hCur, GW_OWNER);
    HWND hParent = GetParent(hCur);
    if (!hOwner && !hParent) break;
    hCur = hOwner ? hOwner : hParent;
  }

  HRESULT hrCo = CoInitialize(nullptr);
  ITaskbarList *pTaskList = nullptr;
  HRESULT hrTB = CoCreateInstance(CLSID_TaskbarList, nullptr,
                                 CLSCTX_INPROC_SERVER, IID_ITaskbarList,
                                 (void **)&pTaskList);
  if (SUCCEEDED(hrTB) && pTaskList) {
    pTaskList->HrInit();
    if (!show) {
      pTaskList->DeleteTab(hTop);
      pTaskList->DeleteTab(hConsole);
    } else {
      pTaskList->AddTab(hTop);
      pTaskList->AddTab(hConsole);
    }
    pTaskList->Release();
  }
  if (SUCCEEDED(hrCo)) {
    CoUninitialize();
  }
}

static ID3D11Device *g_pd3dDevice = nullptr;
static ID3D11DeviceContext *g_pd3dDeviceContext = nullptr;
static IDXGISwapChain *g_pSwapChain = nullptr;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView *g_mainRenderTargetView = nullptr;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI ImGuiWndProc(HWND hWnd, UINT msg, WPARAM wParam,
                                   LPARAM lParam);

static void SetupTechnoVerseImGuiStyle() {
  ImGuiStyle &style = ImGui::GetStyle();
  ImVec4 *colors = style.Colors;

  style.WindowRounding = 12.0f;
  style.ChildRounding = 10.0f;
  style.FrameRounding = 8.0f;
  style.PopupRounding = 8.0f;
  style.ScrollbarRounding = 8.0f;
  style.GrabRounding = 8.0f;
  style.TabRounding = 8.0f;
  style.WindowPadding = ImVec2(18.0f, 18.0f);
  style.FramePadding = ImVec2(12.0f, 8.0f);
  style.ItemSpacing = ImVec2(12.0f, 10.0f);

  colors[ImGuiCol_Text] = ImVec4(0.96f, 0.94f, 1.00f, 1.00f);
  colors[ImGuiCol_TextDisabled] = ImVec4(0.58f, 0.52f, 0.72f, 1.00f);
  colors[ImGuiCol_WindowBg] = ImVec4(0.04f, 0.03f, 0.08f, 0.98f);
  colors[ImGuiCol_ChildBg] = ImVec4(0.07f, 0.05f, 0.14f, 1.00f);
  colors[ImGuiCol_PopupBg] = ImVec4(0.07f, 0.05f, 0.14f, 0.98f);
  colors[ImGuiCol_Border] = ImVec4(0.40f, 0.16f, 0.68f, 0.55f);
  colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
  colors[ImGuiCol_FrameBg] = ImVec4(0.11f, 0.07f, 0.20f, 1.00f);
  colors[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.12f, 0.38f, 1.00f);
  colors[ImGuiCol_FrameBgActive] = ImVec4(0.28f, 0.16f, 0.50f, 1.00f);
  colors[ImGuiCol_TitleBg] = ImVec4(0.05f, 0.03f, 0.10f, 1.00f);
  colors[ImGuiCol_TitleBgActive] = ImVec4(0.09f, 0.06f, 0.18f, 1.00f);
  colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.04f, 0.03f, 0.08f, 0.75f);
  colors[ImGuiCol_MenuBarBg] = ImVec4(0.07f, 0.05f, 0.14f, 1.00f);
  colors[ImGuiCol_ScrollbarBg] = ImVec4(0.04f, 0.03f, 0.08f, 0.50f);
  colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.25f, 0.14f, 0.45f, 1.00f);
  colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.38f, 0.20f, 0.65f, 1.00f);
  colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.52f, 0.25f, 0.85f, 1.00f);
  colors[ImGuiCol_CheckMark] = ImVec4(0.75f, 0.32f, 0.98f, 1.00f);
  colors[ImGuiCol_SliderGrab] = ImVec4(0.65f, 0.25f, 0.95f, 1.00f);
  colors[ImGuiCol_SliderGrabActive] = ImVec4(0.80f, 0.38f, 1.00f, 1.00f);
  colors[ImGuiCol_Button] = ImVec4(0.18f, 0.10f, 0.35f, 1.00f);
  colors[ImGuiCol_ButtonHovered] = ImVec4(0.32f, 0.16f, 0.58f, 1.00f);
  colors[ImGuiCol_ButtonActive] = ImVec4(0.52f, 0.22f, 0.88f, 1.00f);
  colors[ImGuiCol_Header] = ImVec4(0.18f, 0.10f, 0.35f, 1.00f);
  colors[ImGuiCol_HeaderHovered] = ImVec4(0.32f, 0.16f, 0.58f, 1.00f);
  colors[ImGuiCol_HeaderActive] = ImVec4(0.52f, 0.22f, 0.88f, 1.00f);
  colors[ImGuiCol_Separator] = ImVec4(0.32f, 0.16f, 0.58f, 1.00f);
  colors[ImGuiCol_SeparatorHovered] = ImVec4(0.52f, 0.22f, 0.88f, 1.00f);
  colors[ImGuiCol_SeparatorActive] = ImVec4(0.72f, 0.32f, 0.98f, 1.00f);
}

static void RunImGuiWindowThread() {
  WNDCLASSEXW wc = {sizeof(wc),
                    CS_CLASSDC,
                    ImGuiWndProc,
                    0L,
                    0L,
                    GetModuleHandle(nullptr),
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    L"TechnoVerseImGuiClass",
                    nullptr};
  RegisterClassExW(&wc);
  HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"TechnoVerse",
                              WS_OVERLAPPEDWINDOW, 100, 100, 860, 410, nullptr,
                              nullptr, wc.hInstance, nullptr);

  if (!CreateDeviceD3D(hwnd)) {
    CleanupDeviceD3D();
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return;
  }

  ShowWindow(hwnd, SW_SHOWDEFAULT);
  UpdateWindow(hwnd);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  (void)io;
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

  SetupTechnoVerseImGuiStyle();

  ImGui_ImplWin32_Init(hwnd);
  ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

  while (!g_shutdown.load()) {
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
      if (msg.message == WM_QUIT) {
        g_shutdown.store(true);
        break;
      }
    }
    if (g_shutdown.load())
      break;

    if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
      CleanupRenderTarget();
      g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight,
                                  DXGI_FORMAT_UNKNOWN, 0);
      g_ResizeWidth = g_ResizeHeight = 0;
      CreateRenderTarget();
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::Begin("TechnoVerse Controller", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

    ImGui::BeginChild("StatusPanel", ImVec2(0, 75), true);
    {
      ImGui::Columns(4, "StatusCols", false);

      ImGui::TextDisabled("VALORANT PID");
      if (g_valorant_pid != 0) {
        ImGui::TextColored(ImVec4(0.25f, 0.92f, 0.50f, 1.0f), "[ RUNNING: %d ]",
                           g_valorant_pid);
      } else {
        ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.45f, 1.0f), "[ WAITING... ]");
      }
      ImGui::NextColumn();

      ImGui::TextDisabled("ACTIVE REGION");
      ImGui::TextColored(ImVec4(0.75f, 0.40f, 1.00f, 1.0f), "[ %s ]",
                         RegionDisplayName(g_selected_region).c_str());
      ImGui::NextColumn();

      ImGui::TextDisabled("GATEWAY");
      if (g_gateway_auto_send.load()) {
        ImGui::TextColored(ImVec4(0.25f, 0.92f, 0.50f, 1.0f),
                           "[ AUTO-SEND ON ]");
      } else {
        ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "[ OFF ]");
      }
      ImGui::NextColumn();

      ImGui::TextDisabled("SESSION");
      {
        std::lock_guard<std::mutex> lk(g_display_mtx);
        if (g_active_session.active) {
          ImGui::TextColored(ImVec4(0.25f, 0.92f, 0.50f, 1.0f),
                             "[ CONNECTED ]");
        } else {
          ImGui::TextColored(ImVec4(0.65f, 0.60f, 0.75f, 1.0f), "[ IDLE ]");
        }
      }
      ImGui::Columns(1);
    }
    ImGui::EndChild();

    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.88f, 0.82f, 1.00f, 1.0f),
                       "SELECT SERVER REGION");
    ImGui::BeginChild("RegionGrid", ImVec2(0, 62), true);
    {
      struct RegionBtnInfo {
        const char *code;
        const char *label;
      };
      static const RegionBtnInfo regions[] = {{"ap", "AP"},    {"br", "BR"},
                                              {"eu", "EU"},    {"kr", "KR"},
                                              {"la", "LATAM"}, {"na", "NA"}};

      for (int i = 0; i < 6; i++) {
        bool isSelected = (g_selected_region == regions[i].code);

        if (isSelected) {
          ImGui::PushStyleColor(ImGuiCol_Button,
                                ImVec4(0.55f, 0.18f, 0.92f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                                ImVec4(0.68f, 0.25f, 0.98f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                                ImVec4(0.45f, 0.12f, 0.80f, 1.0f));
        } else {
          ImGui::PushStyleColor(ImGuiCol_Button,
                                ImVec4(0.16f, 0.10f, 0.32f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                                ImVec4(0.28f, 0.16f, 0.52f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                                ImVec4(0.55f, 0.18f, 0.92f, 1.0f));
        }

        if (ImGui::Button(regions[i].label, ImVec2(125, 38))) {
          g_selected_region = regions[i].code;
          {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            g_region_override = g_selected_region;
            g_cached_region = g_selected_region;
          }
          std::string title_cmd = "title TechnoVerse - " +
                                  RegionDisplayName(g_selected_region) +
                                  " VERSION";
          system(title_cmd.c_str());
          Log("[REGION] Selected region updated to: " + g_selected_region +
              " (" + RegionDisplayName(g_selected_region) + ")");
        }

        ImGui::PopStyleColor(3);

        if (i < 5) {
          ImGui::SameLine();
        }
      }
    }
    ImGui::EndChild();

    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.88f, 0.82f, 1.00f, 1.0f), "QUICK ACTIONS");
    ImGui::BeginChild("ActionButtons", ImVec2(0, 75), true);
    {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.72f, 0.18f, 0.82f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                            ImVec4(0.85f, 0.25f, 0.95f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                            ImVec4(0.60f, 0.12f, 0.70f, 1.0f));
      if (ImGui::Button("MFA Bypass (Account Verify)", ImVec2(240, 40))) {
        Log("[MFA] Triggering MFA Bypass...");
        mfa::RequestRun();
      }
      ImGui::PopStyleColor(3);

      ImGui::SameLine();

      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.38f, 0.18f, 0.82f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                            ImVec4(0.50f, 0.25f, 0.95f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                            ImVec4(0.28f, 0.12f, 0.70f, 1.0f));
      if (ImGui::Button("Restart VGC Service", ImVec2(180, 40))) {
        Log("[SERVICE] Restarting VGC service...");
        std::thread([]() {
          system("sc stop vgc >nul 2>&1");
          Sleep(300);
          system("sc start vgc >nul 2>&1");
          Log("[SERVICE] VGC service restarted successfully.");
        }).detach();
      }
      ImGui::PopStyleColor(3);

      ImGui::SameLine();

      bool autoSend = g_gateway_auto_send.load();
      if (autoSend) {
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImVec4(0.10f, 0.65f, 0.45f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.15f, 0.78f, 0.55f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                              ImVec4(0.08f, 0.52f, 0.35f, 1.0f));
      } else {
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImVec4(0.24f, 0.14f, 0.40f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.34f, 0.20f, 0.55f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                              ImVec4(0.18f, 0.10f, 0.30f, 1.0f));
      }
      if (ImGui::Button(autoSend ? "Auto-Send: ON" : "Auto-Send: OFF",
                        ImVec2(160, 40))) {
        g_gateway_auto_send.store(!autoSend);
        Log(std::string("[GATEWAY] Auto-Send toggled to: ") +
            (!autoSend ? "ENABLED" : "DISABLED"));
      }
      ImGui::PopStyleColor(3);

      ImGui::SameLine();

      if (g_console_visible) {
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImVec4(0.58f, 0.22f, 0.88f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.70f, 0.30f, 0.98f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                              ImVec4(0.45f, 0.15f, 0.75f, 1.0f));
      } else {
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImVec4(0.20f, 0.14f, 0.38f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.30f, 0.20f, 0.52f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                              ImVec4(0.14f, 0.08f, 0.28f, 1.0f));
      }
      if (ImGui::Button(g_console_visible ? "Hide CMD Log" : "Show CMD Log",
                        ImVec2(160, 40))) {
        g_console_visible = !g_console_visible;
        ToggleConsoleWindowVisibility(g_console_visible);
        Log(std::string("[UI] CMD console window ") +
            (g_console_visible ? "shown" : "hidden"));
      }
      ImGui::PopStyleColor(3);

      ImGui::SameLine();

      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.80f, 0.18f, 0.22f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                            ImVec4(0.92f, 0.28f, 0.32f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                            ImVec4(0.65f, 0.12f, 0.16f, 1.0f));
      if (ImGui::Button("Reset Session", ImVec2(160, 40))) {
        Log("[UI] Reset Session button clicked");
        std::thread([]() { AutoResetSession(); }).detach();
      }
      ImGui::PopStyleColor(3);
    }
    ImGui::EndChild();

    ImGui::End();

    ImGui::Render();
    const float clear_color_with_alpha[4] = {0.04f, 0.03f, 0.08f, 1.00f};
    g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView,
                                            nullptr);
    g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView,
                                               clear_color_with_alpha);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

    g_pSwapChain->Present(1, 0);
  }

  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();

  CleanupDeviceD3D();
  DestroyWindow(hwnd);
  UnregisterClassW(wc.lpszClassName, wc.hInstance);
}

static bool CreateDeviceD3D(HWND hWnd) {
  DXGI_SWAP_CHAIN_DESC sd;
  ZeroMemory(&sd, sizeof(sd));
  sd.BufferCount = 2;
  sd.BufferDesc.Width = 0;
  sd.BufferDesc.Height = 0;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferDesc.RefreshRate.Numerator = 60;
  sd.BufferDesc.RefreshRate.Denominator = 1;
  sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = hWnd;
  sd.SampleDesc.Count = 1;
  sd.SampleDesc.Quality = 0;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

  UINT createDeviceFlags = 0;
  D3D_FEATURE_LEVEL featureLevel;
  const D3D_FEATURE_LEVEL featureLevelArray[2] = {
      D3D_FEATURE_LEVEL_11_0,
      D3D_FEATURE_LEVEL_10_0,
  };
  HRESULT res = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
      featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
      &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
  if (res == DXGI_ERROR_UNSUPPORTED)
    res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
  if (res != S_OK)
    return false;

  CreateRenderTarget();
  return true;
}

static void CleanupDeviceD3D() {
  CleanupRenderTarget();
  if (g_pSwapChain) {
    g_pSwapChain->Release();
    g_pSwapChain = nullptr;
  }
  if (g_pd3dDeviceContext) {
    g_pd3dDeviceContext->Release();
    g_pd3dDeviceContext = nullptr;
  }
  if (g_pd3dDevice) {
    g_pd3dDevice->Release();
    g_pd3dDevice = nullptr;
  }
}

static void CreateRenderTarget() {
  ID3D11Texture2D *pBackBuffer = nullptr;
  if (g_pSwapChain) {
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
      g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr,
                                           &g_mainRenderTargetView);
      pBackBuffer->Release();
    }
  }
}

static void CleanupRenderTarget() {
  if (g_mainRenderTargetView) {
    g_mainRenderTargetView->Release();
    g_mainRenderTargetView = nullptr;
  }
}

static LRESULT WINAPI ImGuiWndProc(HWND hWnd, UINT msg, WPARAM wParam,
                                   LPARAM lParam) {
  if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
    return true;

  switch (msg) {
  case WM_SIZE:
    if (wParam != SIZE_MINIMIZED) {
      g_ResizeWidth = (UINT)LOWORD(lParam);
      g_ResizeHeight = (UINT)HIWORD(lParam);
    }
    return 0;
  case WM_SYSCOMMAND:
    if ((wParam & 0xfff0) == SC_KEYMENU)
      return 0;
    break;
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int MainCMDUI(int argc, char *argv[]) {
  ToggleConsoleWindowVisibility(false);

  system("title TechnoVerse");
  SetConsoleCtrlHandler(CtrlHandler, TRUE);
  adjust_privileges();

  if (!ensure_single_instance()) {
    MessageBoxW(nullptr,
                L"TechnoVerse zaten calistirilmakta. Lutfen once mevcut "
                L"pencereyi kapatin.",
                L"TechnoVerse - Zaten Acik", MB_OK | MB_ICONWARNING);
    return 1;
  }

  if (IsDebuggerPresent()) {
    ExitProcess(0);
  }
  {
    BOOL rd = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &rd);
    if (rd)
      ExitProcess(0);
  }
  if (detect_bad_programs()) {
    SetColor(COL_RED);
    std::cout << "\n  [SECURITY] Hostile tool detected. Close all "
                 "debugging/proxy tools and restart.\n";
    Sleep(3000);
    ExitProcess(0);
  }
  if (detect_virtual_machine()) {
    SetColor(COL_RED);
    std::cout << "\n  [SECURITY] Virtual machine environment detected. Run on "
                 "a physical machine.\n";
    Sleep(3000);
    ExitProcess(0);
  }

  exe_integrity_init();

  std::thread(protection_monitor_thread).detach();

  // hostssil();

  VerifyLicenseKey();

  std::thread(RunImGuiWindowThread).detach();

  g_selected_region = "ap";
  {
    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
    g_region_override = "ap";
    g_cached_region = "ap";
  }
  std::string title_cmd = "title TechnoVerse - " +
                          RegionDisplayName(g_selected_region) + " VERSION";
  system(title_cmd.c_str());
  Log("[REGION] Default region display initialized to AP (pending JWT "
      "auto-detection).");

  // hostssil();
  std::thread(shooter_log_monitor_thread).detach();

  std::thread killer_thread(vgm_killer_thread);
  killer_thread.detach();

  Log(xorstr_("=== START ==="));
  Log(xorstr_("Build: ") + std::string(__DATE__) + " " + __TIME__);

  g_gateway_auto_send.store(true);
  ClearConsole();
  SetColor(COL_WHITE);
  std::cout << "\n  Do not turn off.\n";

  g_display_running = true;
  std::thread(DisplayLoop).detach();

  g_session_mgr.on_session_created =
      [](const std::string &sid, const std::string &puuid,
         const std::string &region, const std::string &account) {
        std::lock_guard<std::mutex> lk(g_display_mtx);
        g_active_session.puuid = puuid;
        g_active_session.region = region;
        g_active_session.account = account;
        g_active_session.start_time = std::chrono::steady_clock::now();
        g_active_session.active = true;
      };
  g_session_mgr.on_session_destroyed = [](const std::string &) {
    std::lock_guard<std::mutex> lk(g_display_mtx);
    g_active_session.active = false;
    g_active_session.puuid = "";
    g_active_session.region = "";
  };

  mfa::on_msg = [](int type, const char *s) {};

  g_server_running = true;
  std::thread([]() { RunServer(); }).detach();
  Sleep(300);

  system("sc stop vgc >nul 2>&1");
  Sleep(300);
  system("sc start vgc >nul 2>&1");
  Sleep(500);

  HANDLE h = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    CloseHandle(h);
  }

  std::thread(PipeServerLoop).detach();
  std::thread(GatewayHotkeyLoop).detach();
  std::thread(HealthCheck).detach();

  CreateVanguardMutex();
  CreateVanguardSharedMemory();

  while (!g_shutdown.load()) {
    if (g_session_reset_needed.load()) {
      AutoResetSession();
    }
    g_valorant_pid = GetValorantPID();
    if (g_valorant_pid) {
      g_valorant_pid_fwd = g_valorant_pid;
      break;
    }
    Sleep(500);
  }

  bool disconnect_sent_after_valorant_exit = false;
  while (!g_shutdown.load()) {
    Sleep(500);
    if (g_session_reset_needed.load()) {
      AutoResetSession();
    }
    if (GetAsyncKeyState(VK_F8) & 1) {
      mfa::RequestRun();
    }
    uint32_t current_val_pid = GetValorantPID();
    if (current_val_pid == 0 && g_valorant_pid != 0 &&
        !disconnect_sent_after_valorant_exit) {
      Log("[PIPE][DISCONNECT] Valorant process ended, notifying pipe");
      SendDisconnectMessageToCurrentPipe("valorant process ended");
      disconnect_sent_after_valorant_exit = true;
    }
    if (current_val_pid != 0 && current_val_pid != g_valorant_pid) {
      g_valorant_pid = current_val_pid;
      g_valorant_pid_fwd = current_val_pid;
      disconnect_sent_after_valorant_exit = false;
    }
  }

  system("sc stop vgc >nul 2>&1");
  return 0;
}

int main(int argc, char *argv[]) { return MainCMDUI(argc, argv); }