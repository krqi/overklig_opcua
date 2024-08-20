
#ifndef UA_LOG_SYSLOG_H_
#define UA_LOG_SYSLOG_H_

#include <opcua/plugin/log.h>

_UA_BEGIN_DECLS


#if defined(__linux__) || defined(__unix__)

UA_EXPORT UA_Logger
UA_Log_Syslog_withLevel(UA_LogLevel minlevel);


UA_EXPORT UA_Logger *
UA_Log_Syslog_new(UA_LogLevel minlevel);

UA_EXPORT UA_Logger
UA_Log_Syslog(void);

#endif

_UA_END_DECLS

#endif 
