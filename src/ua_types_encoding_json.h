
#ifndef UA_TYPES_ENCODING_JSON_H_
#define UA_TYPES_ENCODING_JSON_H_

#include <opcua/types.h>

#include "util/ua_util_internal.h"

#include "../deps/cj5.h"

_UA_BEGIN_DECLS

#define UA_JSON_MAXTOKENCOUNT 256
#define UA_JSON_ENCODING_MAX_RECURSION 100

typedef struct {
    uint8_t *pos;
    const uint8_t *end;

    uint16_t depth; 
    UA_Boolean commaNeeded[UA_JSON_ENCODING_MAX_RECURSION];
    UA_Boolean useReversible;
    UA_Boolean calcOnly; 

    size_t namespacesSize;
    const UA_String *namespaces;

    size_t serverUrisSize;
    const UA_String *serverUris;

    UA_Boolean prettyPrint;
    UA_Boolean unquotedKeys;
    UA_Boolean stringNodeIds;
} CtxJson;

UA_StatusCode writeJsonObjStart(CtxJson *ctx);
UA_StatusCode writeJsonObjElm(CtxJson *ctx, const char *key,
                              const void *value, const UA_DataType *type);
UA_StatusCode writeJsonObjEnd(CtxJson *ctx);

UA_StatusCode writeJsonArrStart(CtxJson *ctx);
UA_StatusCode writeJsonArrElm(CtxJson *ctx, const void *value,
                              const UA_DataType *type);
UA_StatusCode writeJsonArrEnd(CtxJson *ctx);

UA_StatusCode writeJsonKey(CtxJson *ctx, const char* key);

UA_StatusCode writeJsonBeforeElement(CtxJson *ctx, UA_Boolean distinct);

typedef struct {
    const char *json5;
    cj5_token *tokens;
    size_t tokensSize;
    size_t index;
    UA_Byte depth;

    size_t namespacesSize;
    const UA_String *namespaces;

    size_t serverUrisSize;
    const UA_String *serverUris;

    const UA_DataTypeArray *customTypes;

    size_t numCustom;
    void * custom;
    size_t currentCustomIndex;
} ParseCtx;

typedef UA_StatusCode
(*encodeJsonSignature)(CtxJson *ctx, const void *src, const UA_DataType *type);

typedef UA_StatusCode
(*decodeJsonSignature)(ParseCtx *ctx, void *dst, const UA_DataType *type);

typedef struct {
    const char *fieldName;
    void *fieldPointer;
    decodeJsonSignature function;
    UA_Boolean found;
} DecodeEntry;

UA_StatusCode decodeFields(ParseCtx *ctx, DecodeEntry *entries, size_t entryCount);


extern const encodeJsonSignature encodeJsonJumpTable[UA_DATATYPEKINDS];
extern const decodeJsonSignature decodeJsonJumpTable[UA_DATATYPEKINDS];

UA_StatusCode lookAheadForKey(ParseCtx *ctx, const char *search, size_t *resultIndex);
UA_StatusCode tokenize(ParseCtx *ctx, const UA_ByteString *src, size_t tokensSize,
                       size_t *decodedLength);

static UA_INLINE
cj5_token_type currentTokenType(const ParseCtx *ctx) {
    return ctx->tokens[ctx->index].type;
}

static UA_INLINE
size_t getTokenLength(const cj5_token *t) {
    return (size_t)(1u + t->end - t->start);
}

_UA_END_DECLS

#endif 
