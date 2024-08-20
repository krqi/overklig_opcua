
#ifndef UA_LOG_STDOUT_H_
#define UA_LOG_STDOUT_H_

#include <opcua/plugin/log.h>

_UA_BEGIN_DECLS

extern UA_EXPORT const UA_Logger UA_Log_Stdout_; 
extern UA_EXPORT const UA_Logger *UA_Log_Stdout; 


UA_EXPORT UA_Logger
UA_Log_Stdout_withLevel(UA_LogLevel minlevel);


UA_EXPORT UA_Logger *
UA_Log_Stdout_new(UA_LogLevel minlevel);

_UA_END_DECLS

#endif 
