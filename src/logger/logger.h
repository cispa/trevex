// Copyright [2026] <Daniel Weber>

#ifndef COMMON_LOGGER_H
#define COMMON_LOGGER_H

#include <string>

namespace trevex {

enum LogLevel {ERROR = 1, WARNING = 2, INFO = 3, DEBUG = 4};

void SetLogLevel(LogLevel log_level);

class Logger {
 public:
  Logger();
  void LogDebug(const std::string &message, const char* filename,
      int sourceline);
  void LogInfo(const std::string &message);
  void LogWarning(const std::string &message);
  void LogError(const std::string &message);
  void SetLogLevel(LogLevel log_level);

 private:
  LogLevel log_level_;
  void AddTimestamp(std::stringstream &msg_stream);
};

#define LOG_ERROR(msg) trevex::global_logger_instance.LogError(msg)
#define LOG_WARNING(msg) trevex::global_logger_instance.LogWarning(msg)
#define LOG_INFO(msg) trevex::global_logger_instance.LogInfo(msg)
#define LOG_DEBUG(msg) trevex::global_logger_instance.LogDebug(msg,  __FILE__,  __LINE__)

// make global logger instance visible
extern Logger global_logger_instance;

}  // namespace trevex

#endif // COMMON_LOGGER_H
