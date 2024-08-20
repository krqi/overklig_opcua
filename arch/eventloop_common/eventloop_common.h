
#ifndef UA_EVENTLOOP_COMMON_H_
#define UA_EVENTLOOP_COMMON_H_

#include <opcua/plugin/eventloop.h>


_UA_BEGIN_DECLS


typedef struct {
    UA_QualifiedName name;
    const UA_DataType *type;
    UA_Boolean required;
    UA_Boolean scalar;
    UA_Boolean array;
} UA_KeyValueRestriction;

UA_StatusCode
UA_KeyValueRestriction_validate(const UA_Logger *logger,
                                const char *logprefix,
                                const UA_KeyValueRestriction *restrictions,
                                size_t restrictionsSize,
                                const UA_KeyValueMap *map);

_UA_END_DECLS

#endif 
