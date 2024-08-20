
#ifndef UA_TYPES_ENCODING_XML_H_
#define UA_TYPES_ENCODING_XML_H_

#include <opcua/types.h>

#include "util/ua_util_internal.h"

_UA_BEGIN_DECLS

#define UA_XML_ENCODING_MAX_RECURSION 100

typedef struct {
    uint8_t *pos;
    const uint8_t *end;

    uint16_t depth; 
    UA_Boolean calcOnly; 
    UA_Boolean prettyPrint;

    const UA_DataTypeArray *customTypes;
} CtxXml;

typedef struct {
    const char* data;
    size_t length;

    uint16_t depth; 

    const UA_DataTypeArray *customTypes;
} ParseCtxXml;

typedef UA_StatusCode
(*encodeXmlSignature)(CtxXml *ctx, const void *src, const UA_DataType *type);

typedef UA_StatusCode
(*decodeXmlSignature)(ParseCtxXml *ctx, void *dst, const UA_DataType *type);


extern const encodeXmlSignature encodeXmlJumpTable[UA_DATATYPEKINDS];
extern const decodeXmlSignature decodeXmlJumpTable[UA_DATATYPEKINDS];

_UA_END_DECLS

#endif 
