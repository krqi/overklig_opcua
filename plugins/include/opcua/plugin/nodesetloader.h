
#ifndef UA_NODESET_LOADER_DEFAULT_H_
#define UA_NODESET_LOADER_DEFAULT_H_

#include <opcua/util.h>

_UA_BEGIN_DECLS

typedef void UA_NodeSetLoaderOptions;

UA_EXPORT UA_StatusCode
UA_Server_loadNodeset(UA_Server *server, const char *nodeset2XmlFilePath,
                      UA_NodeSetLoaderOptions *options);

_UA_END_DECLS

#endif 
