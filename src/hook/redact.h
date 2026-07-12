#pragma once
#include <string>
#include <vector>

namespace face_capture {

bool IsSecretHeaderName(const std::string &name);
std::string RedactHeaderValue(const std::string &name, const std::string &value,
                              bool computeHash = true);

// Summarize body for capture: never full R67/token.
// Returns JSON object string for "data" field content about body.
std::string SummarizeBodyJson(const void *data, size_t len, bool captureFullFaceData);

// Classify host/path as face FilePicker traffic.
bool IsFilePickerHost(const std::string &host);
bool IsFilePickerPath(const std::string &path);
bool ShouldCaptureRequest(const std::string &host, const std::string &path,
                          bool captureOnlyFilepicker);

std::string ParseObjectKeyFromUrl(const std::string &url);
std::string WideToUtf8(const wchar_t *w, size_t nchars = (size_t)-1);

} // namespace face_capture
