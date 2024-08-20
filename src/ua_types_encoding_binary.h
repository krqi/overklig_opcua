
#ifndef UA_TYPES_ENCODING_BINARY_H_
#define UA_TYPES_ENCODING_BINARY_H_

#include <opcua/types.h>

_UA_BEGIN_DECLS

typedef UA_StatusCode (*UA_exchangeEncodeBuffer)(void *handle, UA_Byte **bufPos,
                                                 const UA_Byte **bufEnd);

typedef struct {
    
    UA_Byte *pos;
    const UA_Byte *end;

    
    UA_Byte depth;

    UA_DecodeBinaryOptions opts;

    UA_exchangeEncodeBuffer exchangeBufferCallback;
    void *exchangeBufferCallbackHandle;
} Ctx;

void * ctxCalloc(Ctx *ctx, size_t nelem, size_t elsize);
void ctxFree(Ctx *ctx, void *p);
void ctxClear(Ctx *ctx, void *p, const UA_DataType *type);

typedef UA_StatusCode
(*encodeBinarySignature)(Ctx *UA_RESTRICT ctx, const void *UA_RESTRICT src,
                         const UA_DataType *type);
typedef UA_StatusCode
(*decodeBinarySignature)(Ctx *UA_RESTRICT ctx, void *UA_RESTRICT dst,
                         const UA_DataType *type);
extern const encodeBinarySignature encodeBinaryJumpTable[UA_DATATYPEKINDS];
extern const decodeBinarySignature decodeBinaryJumpTable[UA_DATATYPEKINDS];

#define DECODE_BINARY(VAR, TYPE)                                    \
    decodeBinaryJumpTable[UA_DATATYPEKIND_##TYPE](ctx, VAR, NULL);

#define ENCODE_BINARY(VAR, TYPE)                                    \
    encodeBinaryJumpTable[UA_DATATYPEKIND_##TYPE](ctx, VAR, NULL);

UA_StatusCode
UA_encodeBinaryInternal(const void *src, const UA_DataType *type,
                        UA_Byte **bufPos, const UA_Byte **bufEnd,
                        UA_exchangeEncodeBuffer exchangeCallback,
                        void *exchangeHandle)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

UA_StatusCode
UA_decodeBinaryInternal(const UA_ByteString *src, size_t *offset,
                        void *dst, const UA_DataType *type,
                        const UA_DecodeBinaryOptions *options)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

const UA_DataType *
UA_findDataTypeByBinary(const UA_NodeId *typeId);

_UA_END_DECLS

#endif 
