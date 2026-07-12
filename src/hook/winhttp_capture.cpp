#include "hook/winhttp_capture.h"
#include "MinHook.h"
#include "hook/capture_writer.h"
#include "hook/redact.h"
#include <Windows.h>
#include <winhttp.h>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace face_capture {
namespace {

HookConfig g_cfg;
std::mutex g_mu;

struct ConnCtx {
  std::string host;
  int port = 0;
};

struct ReqCtx {
  HINTERNET connect = nullptr;
  std::string host;
  std::string method;
  std::string path;
  std::string headers;
  std::vector<uint8_t> body;
  std::vector<uint8_t> response_body;
  int response_status = 0;
  bool capture = false;
};

std::map<HINTERNET, ConnCtx> g_connects;
std::map<HINTERNET, ReqCtx> g_requests;

using WinHttpConnect_fn = HINTERNET(WINAPI *)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
using WinHttpOpenRequest_fn = HINTERNET(WINAPI *)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR,
                                                    LPCWSTR *, DWORD);
using WinHttpAddRequestHeaders_fn = BOOL(WINAPI *)(HINTERNET, LPCWSTR, DWORD, DWORD);
using WinHttpSendRequest_fn = BOOL(WINAPI *)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD,
                                               DWORD_PTR);
using WinHttpWriteData_fn = BOOL(WINAPI *)(HINTERNET, LPCVOID, DWORD, LPDWORD);
using WinHttpReceiveResponse_fn = BOOL(WINAPI *)(HINTERNET, LPVOID);
using WinHttpReadData_fn = BOOL(WINAPI *)(HINTERNET, LPVOID, DWORD, LPDWORD);
using WinHttpQueryHeaders_fn = BOOL(WINAPI *)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
using WinHttpCloseHandle_fn = BOOL(WINAPI *)(HINTERNET);

WinHttpConnect_fn oConnect = nullptr;
WinHttpOpenRequest_fn oOpenRequest = nullptr;
WinHttpAddRequestHeaders_fn oAddHeaders = nullptr;
WinHttpSendRequest_fn oSendRequest = nullptr;
WinHttpWriteData_fn oWriteData = nullptr;
WinHttpReceiveResponse_fn oReceiveResponse = nullptr;
WinHttpReadData_fn oReadData = nullptr;
WinHttpQueryHeaders_fn oQueryHeaders = nullptr;
WinHttpCloseHandle_fn oCloseHandle = nullptr;

constexpr size_t kMaxBody = 1024 * 1024;

void AppendBody(std::vector<uint8_t> &buf, const void *p, size_t n) {
  if (!p || n == 0)
    return;
  size_t room = kMaxBody > buf.size() ? kMaxBody - buf.size() : 0;
  size_t take = n < room ? n : room;
  if (!take)
    return;
  const uint8_t *b = (const uint8_t *)p;
  buf.insert(buf.end(), b, b + take);
}

std::string RegionFromHost(const std::string &host) {
  if (host.find("easebar") != std::string::npos)
    return "GLOBAL";
  if (host.find("netease") != std::string::npos)
    return "CN";
  return "UNKNOWN";
}

std::string HeadersToJson(const std::string &h) {
  std::string hdrJson = "{";
  bool first = true;
  size_t pos = 0;
  while (pos < h.size()) {
    size_t nl = h.find("\r\n", pos);
    if (nl == std::string::npos)
      nl = h.size();
    std::string line = h.substr(pos, nl - pos);
    pos = (nl == h.size()) ? h.size() : nl + 2;
    size_t c = line.find(':');
    if (c == std::string::npos)
      continue;
    std::string name = line.substr(0, c);
    std::string val = line.substr(c + 1);
    while (!val.empty() && val[0] == ' ')
      val.erase(val.begin());
    if (!first)
      hdrJson += ",";
    hdrJson += JsonString(name) + ":" + JsonString(RedactHeaderValue(name, val, true));
    first = false;
  }
  hdrJson += "}";
  return hdrJson;
}

void EmitRequestComplete(ReqCtx &r) {
  if (!r.capture)
    return;
  std::string bodySum =
      SummarizeBodyJson(r.body.empty() ? nullptr : r.body.data(), r.body.size(),
                        g_cfg.capture_full_face_data);
  std::string respSum = SummarizeBodyJson(
      r.response_body.empty() ? nullptr : r.response_body.data(), r.response_body.size(), false);

  std::string data = "{";
  data += "\"method\":" + JsonString(r.method) + ",";
  data += "\"host\":" + JsonString(r.host) + ",";
  data += "\"path\":" + JsonString(r.path) + ",";
  data += "\"headers\":" + HeadersToJson(r.headers) + ",";
  data += "\"request_body\":" + bodySum + ",";
  data += "\"response_status\":" + std::to_string(r.response_status) + ",";
  data += "\"response_body\":" + respSum;

  if (!r.response_body.empty()) {
    std::string rt((const char *)r.response_body.data(), r.response_body.size());
    size_t p = rt.find("pict_url");
    if (p != std::string::npos) {
      size_t colon = rt.find(':', p);
      size_t q1 = rt.find('"', colon);
      if (q1 != std::string::npos) {
        size_t q2 = rt.find('"', q1 + 1);
        if (q2 != std::string::npos) {
          std::string pict = rt.substr(q1 + 1, q2 - q1 - 1);
          data += ",\"pict_url\":" + JsonString(pict);
          data += ",\"object_key\":" + JsonString(ParseObjectKeyFromUrl(pict));
        }
      }
    }
  }
  data += "}";
  WriteCaptureEvent("winhttp", "http_exchange", data, "", RegionFromHost(r.host));
}

HINTERNET WINAPI Detour_Connect(HINTERNET hSession, LPCWSTR pswzServerName,
                                INTERNET_PORT nServerPort, DWORD dwReserved) {
  HINTERNET h = oConnect(hSession, pswzServerName, nServerPort, dwReserved);
  if (h && pswzServerName) {
    ConnCtx c;
    c.host = WideToUtf8(pswzServerName);
    c.port = (int)nServerPort;
    std::lock_guard<std::mutex> lock(g_mu);
    g_connects[h] = c;
  }
  return h;
}

HINTERNET WINAPI Detour_OpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
                                    LPCWSTR pwszVersion, LPCWSTR pwszReferrer,
                                    LPCWSTR *ppwszAcceptTypes, DWORD dwFlags) {
  HINTERNET h = oOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer,
                             ppwszAcceptTypes, dwFlags);
  if (!h)
    return h;
  ReqCtx r;
  r.connect = hConnect;
  {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_connects.find(hConnect);
    if (it != g_connects.end())
      r.host = it->second.host;
  }
  r.method = pwszVerb ? WideToUtf8(pwszVerb) : "GET";
  r.path = pwszObjectName ? WideToUtf8(pwszObjectName) : "";
  r.capture = ShouldCaptureRequest(r.host, r.path, g_cfg.capture_only_filepicker);
  std::lock_guard<std::mutex> lock(g_mu);
  g_requests[h] = std::move(r);
  return h;
}

BOOL WINAPI Detour_AddRequestHeaders(HINTERNET hRequest, LPCWSTR lpszHeaders,
                                     DWORD dwHeadersLength, DWORD dwModifiers) {
  if (lpszHeaders) {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_requests.find(hRequest);
    if (it != g_requests.end() && it->second.capture) {
      size_t n = dwHeadersLength == (DWORD)-1 ? wcslen(lpszHeaders) : dwHeadersLength;
      it->second.headers += WideToUtf8(lpszHeaders, n);
      if (it->second.headers.empty() || it->second.headers.back() != '\n')
        it->second.headers += "\r\n";
    }
  }
  return oAddHeaders(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
}

BOOL WINAPI Detour_SendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
                               LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
                               DWORD_PTR dwContext) {
  {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_requests.find(hRequest);
    if (it != g_requests.end() && it->second.capture) {
      if (lpszHeaders && dwHeadersLength) {
        size_t n = dwHeadersLength == (DWORD)-1 ? wcslen(lpszHeaders) : dwHeadersLength;
        it->second.headers += WideToUtf8(lpszHeaders, n);
      }
      AppendBody(it->second.body, lpOptional, dwOptionalLength);
    }
  }
  return oSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength,
                      dwTotalLength, dwContext);
}

BOOL WINAPI Detour_WriteData(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite,
                             LPDWORD lpdwNumberOfBytesWritten) {
  BOOL ok = oWriteData(hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
  if (ok && lpBuffer && dwNumberOfBytesToWrite) {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_requests.find(hRequest);
    if (it != g_requests.end() && it->second.capture)
      AppendBody(it->second.body, lpBuffer, dwNumberOfBytesToWrite);
  }
  return ok;
}

BOOL WINAPI Detour_ReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) {
  BOOL ok = oReceiveResponse(hRequest, lpReserved);
  if (ok && oQueryHeaders) {
    DWORD status = 0, sz = sizeof(status);
    if (oQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX)) {
      std::lock_guard<std::mutex> lock(g_mu);
      auto it = g_requests.find(hRequest);
      if (it != g_requests.end())
        it->second.response_status = (int)status;
    }
  }
  return ok;
}

BOOL WINAPI Detour_ReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead,
                            LPDWORD lpdwNumberOfBytesRead) {
  BOOL ok = oReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
  if (ok && lpdwNumberOfBytesRead && *lpdwNumberOfBytesRead && lpBuffer) {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_requests.find(hRequest);
    if (it != g_requests.end() && it->second.capture)
      AppendBody(it->second.response_body, lpBuffer, *lpdwNumberOfBytesRead);
  }
  return ok;
}

BOOL WINAPI Detour_CloseHandle(HINTERNET hInternet) {
  ReqCtx done;
  bool emit = false;
  {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_requests.find(hInternet);
    if (it != g_requests.end()) {
      if (it->second.capture &&
          (it->second.method == "POST" ||
           it->second.path.find("file/new") != std::string::npos ||
           !it->second.body.empty() || !it->second.response_body.empty())) {
        done = std::move(it->second);
        emit = true;
      }
      g_requests.erase(it);
    }
    g_connects.erase(hInternet);
  }
  if (emit)
    EmitRequestComplete(done);
  return oCloseHandle(hInternet);
}

bool HookOne(HMODULE h, const char *name, LPVOID detour, LPVOID *orig) {
  void *p = (void *)GetProcAddress(h, name);
  if (!p)
    return false;
  // Create only first; enable all together below — fewer Freeze/Unfreeze races.
  if (MH_CreateHook(p, detour, orig) != MH_OK)
    return false;
  return true;
}

} // namespace

bool InstallWinHttpCapture(const HookConfig &cfg) {
  g_cfg = cfg;
  // Do not LoadLibrary winhttp if the game never loaded it — injecting a new
  // network DLL mid-run can trip AC. Only hook if already mapped.
  HMODULE h = GetModuleHandleA("winhttp.dll");
  if (!h)
    return false;

  oQueryHeaders = (WinHttpQueryHeaders_fn)GetProcAddress(h, "WinHttpQueryHeaders");

  bool any = false;
  any |= HookOne(h, "WinHttpConnect", (LPVOID)&Detour_Connect, (LPVOID *)&oConnect);
  any |= HookOne(h, "WinHttpOpenRequest", (LPVOID)&Detour_OpenRequest, (LPVOID *)&oOpenRequest);
  any |= HookOne(h, "WinHttpAddRequestHeaders", (LPVOID)&Detour_AddRequestHeaders,
                 (LPVOID *)&oAddHeaders);
  any |= HookOne(h, "WinHttpSendRequest", (LPVOID)&Detour_SendRequest, (LPVOID *)&oSendRequest);
  any |= HookOne(h, "WinHttpWriteData", (LPVOID)&Detour_WriteData, (LPVOID *)&oWriteData);
  any |= HookOne(h, "WinHttpReceiveResponse", (LPVOID)&Detour_ReceiveResponse,
                 (LPVOID *)&oReceiveResponse);
  any |= HookOne(h, "WinHttpReadData", (LPVOID)&Detour_ReadData, (LPVOID *)&oReadData);
  any |= HookOne(h, "WinHttpCloseHandle", (LPVOID)&Detour_CloseHandle, (LPVOID *)&oCloseHandle);

  if (!any)
    return false;

  // Single enable pass for all pending hooks.
  if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    return false;

  WriteCaptureEvent("winhttp", "winhttp_hooks_installed",
                    std::string("{\"ok\":true,\"capture_only_filepicker\":") +
                        (cfg.capture_only_filepicker ? "true" : "false") + "}");
  return true;
}

void UninstallWinHttpCapture() {
  std::lock_guard<std::mutex> lock(g_mu);
  g_requests.clear();
  g_connects.clear();
}

} // namespace face_capture
