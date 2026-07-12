#include "hook/capture_writer.h"
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <io.h>
#include <fcntl.h>
#include <string>

namespace face_capture {
namespace {

CRITICAL_SECTION g_cs;
volatile LONG g_csInit = 0;
std::string g_path;
FILE *g_file = nullptr;

void EnsureCs() {
  if (InterlockedCompareExchange(&g_csInit, 1, 0) == 0) {
    InitializeCriticalSection(&g_cs);
    InterlockedExchange(&g_csInit, 2);
  } else {
    while (g_csInit != 2)
      Sleep(0);
  }
}

void EnsureDirForFile(const char *path) {
  if (!path || !*path)
    return;
  char dir[MAX_PATH] = {};
  strncpy_s(dir, path, _TRUNCATE);
  char *slash = strrchr(dir, '\\');
  if (!slash)
    slash = strrchr(dir, '/');
  if (!slash)
    return;
  *slash = '\0';

  // Create intermediate directories (best-effort).
  for (char *p = dir; *p; ++p) {
    if (*p == '\\' || *p == '/') {
      char save = *p;
      *p = '\0';
      if (dir[0])
        CreateDirectoryA(dir, nullptr);
      *p = save;
    }
  }
  if (dir[0])
    CreateDirectoryA(dir, nullptr);
}

} // namespace

std::string EscapeJson(const std::string &s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
    case '"':
      o += "\\\"";
      break;
    case '\\':
      o += "\\\\";
      break;
    case '\n':
      o += "\\n";
      break;
    case '\r':
      o += "\\r";
      break;
    case '\t':
      o += "\\t";
      break;
    default:
      if (c < 0x20) {
        char buf[8];
        sprintf_s(buf, "\\u%04x", c);
        o += buf;
      } else
        o += (char)c;
    }
  }
  return o;
}

std::string JsonString(const std::string &s) {
  return "\"" + EscapeJson(s) + "\"";
}
std::string JsonNumber(long long n) { return std::to_string(n); }
std::string JsonBool(bool b) { return b ? "true" : "false"; }

// Open append with FILE_SHARE_READ so external tools can tail the log.
static FILE *OpenCaptureFileShared(const char *path) {
  HANDLE h = CreateFileA(path, FILE_APPEND_DATA,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return nullptr;
  int fd = _open_osfhandle((intptr_t)h, 0);
  if (fd == -1) {
    CloseHandle(h);
    return nullptr;
  }
  FILE *f = _fdopen(fd, "ab");
  if (!f) {
    _close(fd);
    return nullptr;
  }
  return f;
}

void InitCaptureWriter(const std::string &outputPath) {
  EnsureCs();
  EnterCriticalSection(&g_cs);
  g_path = outputPath;
  if (!g_path.empty()) {
    EnsureDirForFile(g_path.c_str());
    if (g_file) {
      fclose(g_file);
      g_file = nullptr;
    }
    g_file = OpenCaptureFileShared(g_path.c_str());
    if (g_file) {
      fputs("{\"schema_version\":1,\"event\":\"capture_writer_open\",\"source\":\"native\"}\n",
            g_file);
      fflush(g_file);
    }
  }
  LeaveCriticalSection(&g_cs);
}

void WriteCaptureEvent(const std::string &source, const std::string &event,
                       const std::string &dataJson, const std::string &shareId,
                       const std::string &region) {
  EnsureCs();
  EnterCriticalSection(&g_cs);
  // Re-open per event if closed; keep share-read friendly handle.
  if (!g_file && !g_path.empty())
    g_file = OpenCaptureFileShared(g_path.c_str());
  if (g_file) {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    long long ms =
        (long long)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);

    std::string line = "{\"schema_version\":1,\"timestamp_ms\":" +
                       std::to_string(ms) + ",\"source\":" + JsonString(source) +
                       ",\"event\":" + JsonString(event) +
                       ",\"share_id\":" + JsonString(shareId) +
                       ",\"thread_id\":" + std::to_string(GetCurrentThreadId()) +
                       ",\"region\":" + JsonString(region) +
                       ",\"data\":" + (dataJson.empty() ? "{}" : dataJson) +
                       "}\n";
    fputs(line.c_str(), g_file);
    fflush(g_file);
  }
  LeaveCriticalSection(&g_cs);
}

void ShutdownCaptureWriter() {
  if (g_csInit != 2)
    return;
  EnterCriticalSection(&g_cs);
  if (g_file) {
    fclose(g_file);
    g_file = nullptr;
  }
  LeaveCriticalSection(&g_cs);
}

} // namespace face_capture
