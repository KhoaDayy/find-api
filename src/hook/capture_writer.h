#pragma once
#include <string>

namespace face_capture {

void InitCaptureWriter(const std::string &outputPath);
void WriteCaptureEvent(const std::string &source, const std::string &event,
                       const std::string &dataJson, const std::string &shareId = "",
                       const std::string &region = "UNKNOWN");
void ShutdownCaptureWriter();

std::string EscapeJson(const std::string &s);
std::string JsonString(const std::string &s);
std::string JsonNumber(long long n);
std::string JsonBool(bool b);

} // namespace face_capture
