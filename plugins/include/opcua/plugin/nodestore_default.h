
#ifndef UA_NODESTORE_DEFAULT_H_
#define UA_NODESTORE_DEFAULT_H_

#include <opcua/plugin/nodestore.h>

_UA_BEGIN_DECLS

UA_EXPORT UA_StatusCode
UA_Nodestore_HashMap(UA_Nodestore *ns);

UA_EXPORT UA_StatusCode
UA_Nodestore_ZipTree(UA_Nodestore *ns);

_UA_END_DECLS

#endif 
