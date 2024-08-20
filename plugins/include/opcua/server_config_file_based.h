
#ifndef UA_SERVER_CONFIG_FILE_BASED_H
#define UA_SERVER_CONFIG_FILE_BASED_H

#include <opcua/server.h>
#include <stdio.h>
#include <errno.h>

_UA_BEGIN_DECLS

UA_EXPORT UA_Server *
UA_Server_newFromFile(const UA_ByteString json_config);

UA_EXPORT UA_StatusCode
UA_ServerConfig_updateFromFile(UA_ServerConfig *config, const UA_ByteString json_config);

_UA_END_DECLS

#endif //UA_SERVER_CONFIG_FILE_BASED_H
