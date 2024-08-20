
#include <opcua/types.h>

#include "ua_types_encoding_binary.h"
#include "util/ua_util_internal.h"



#define UA_ENCODING_MAX_RECURSION 100

void *
ctxCalloc(Ctx *ctx, size_t nelem, size_t elsize) {
    if(ctx->opts.calloc)
        return ctx->opts.calloc(ctx->opts.callocContext, nelem, elsize);
    return UA_calloc(nelem, elsize);
}

void
ctxFree(Ctx *ctx, void *p) {
    if(ctx->opts.calloc)
        return;
    UA_free(p);
}

void
ctxClear(Ctx *ctx, void *p, const UA_DataType *type) {
    if(!ctx->opts.calloc)
        UA_clear(p, type);
    else
        memset(p, 0, type->memSize);
}

static void
ctxClearNodeId(Ctx *ctx, UA_NodeId *p) {
    if((p->identifierType == UA_NODEIDTYPE_STRING ||
        p->identifierType == UA_NODEIDTYPE_BYTESTRING) &&
       !ctx->opts.calloc && p->identifier.string.data > (u8*)UA_EMPTY_ARRAY_SENTINEL)
        UA_free(p->identifier.string.data);
    memset(p, 0, sizeof(UA_NodeId));
}

#define FUNC_ENCODE_BINARY(TYPE) static status                          \
    TYPE##_encodeBinary(Ctx *UA_RESTRICT ctx,                           \
                        const UA_##TYPE *UA_RESTRICT src,               \
                        const UA_DataType *type)
#define FUNC_DECODE_BINARY(TYPE) static status                          \
    TYPE##_decodeBinary(Ctx *UA_RESTRICT ctx,                           \
                        UA_##TYPE *UA_RESTRICT dst,                     \
                        const UA_DataType *type)
#define ENCODE_DIRECT(SRC, TYPE) TYPE##_encodeBinary(ctx, (const UA_##TYPE*)SRC, NULL)
#define DECODE_DIRECT(DST, TYPE) TYPE##_decodeBinary(ctx, (UA_##TYPE*)DST, NULL)

#define IF_CHECK_BUFSIZE(check)                             \
    if(!UA_LIKELY(check)) {                                 \
        if(ctx->end != NULL)                                \
            return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED; \
    } else                                                  \


static status exchangeBuffer(Ctx *ctx) {
    if(!ctx->exchangeBufferCallback)
        return UA_STATUSCODE_BADENCODINGERROR;
    return ctx->exchangeBufferCallback(ctx->exchangeBufferCallbackHandle,
                                       &ctx->pos, &ctx->end);
}


static status
encodeWithExchangeBuffer(Ctx *ctx, const void *ptr, const UA_DataType *type) {
    u8 *oldpos = ctx->pos; 
#ifdef UA_DEBUG
    const u8 *oldend = ctx->end;
    (void)oldend; 
#endif
    status ret = encodeBinaryJumpTable[type->typeKind](ctx, ptr, type);
    if(ret == UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED) {
        UA_assert(ctx->end == oldend);
        ctx->pos = oldpos; 
        ret = exchangeBuffer(ctx);
        UA_CHECK_STATUS(ret, return ret);
        ret = encodeBinaryJumpTable[type->typeKind](ctx, ptr, type);
    }
    return ret;
}





#if !UA_BINARY_OVERLAYABLE_INTEGER

#pragma message "Integer endianness could not be detected to be little endian. Use slow generic encoding."


static void
UA_encode16(const u16 v, u8 buf[2]) {
    buf[0] = (u8)v;
    buf[1] = (u8)(v >> 8);
}

static void
UA_decode16(const u8 buf[2], u16 *v) {
    *v = (u16)((u16)buf[0] + (((u16)buf[1]) << 8));
}

static void
UA_encode32(const u32 v, u8 buf[4]) {
    buf[0] = (u8)v;
    buf[1] = (u8)(v >> 8);
    buf[2] = (u8)(v >> 16);
    buf[3] = (u8)(v >> 24);
}

static void
UA_decode32(const u8 buf[4], u32 *v) {
    *v = (u32)((u32)buf[0] + (((u32)buf[1]) << 8) +
             (((u32)buf[2]) << 16) + (((u32)buf[3]) << 24));
}

static void
UA_encode64(const u64 v, u8 buf[8]) {
    buf[0] = (u8)v;
    buf[1] = (u8)(v >> 8);
    buf[2] = (u8)(v >> 16);
    buf[3] = (u8)(v >> 24);
    buf[4] = (u8)(v >> 32);
    buf[5] = (u8)(v >> 40);
    buf[6] = (u8)(v >> 48);
    buf[7] = (u8)(v >> 56);
}

static void
UA_decode64(const u8 buf[8], u64 *v) {
    *v = (u64)((u64)buf[0] + (((u64)buf[1]) << 8) +
             (((u64)buf[2]) << 16) + (((u64)buf[3]) << 24) +
             (((u64)buf[4]) << 32) + (((u64)buf[5]) << 40) +
             (((u64)buf[6]) << 48) + (((u64)buf[7]) << 56));
}

#endif 


FUNC_ENCODE_BINARY(Boolean) {
    IF_CHECK_BUFSIZE(ctx->pos + 1 <= ctx->end) {
        *ctx->pos = *(const u8*)src;
    }
    ++ctx->pos;
    return UA_STATUSCODE_GOOD;
}

FUNC_DECODE_BINARY(Boolean) {
    UA_CHECK(ctx->pos + 1 <= ctx->end, return UA_STATUSCODE_BADDECODINGERROR);
    *dst = (*ctx->pos > 0) ? true : false;
    ++ctx->pos;
    return UA_STATUSCODE_GOOD;
}


FUNC_ENCODE_BINARY(Byte) {
    IF_CHECK_BUFSIZE(ctx->pos + sizeof(u8) <= ctx->end) {
        *ctx->pos = *(const u8*)src;
    }
    ++ctx->pos;
    return UA_STATUSCODE_GOOD;
}

FUNC_DECODE_BINARY(Byte) {
    UA_CHECK(ctx->pos + sizeof(u8) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);
    *dst = *ctx->pos;
    ++ctx->pos;
    return UA_STATUSCODE_GOOD;
}


FUNC_ENCODE_BINARY(UInt16) {
    IF_CHECK_BUFSIZE(ctx->pos + sizeof(u16) <= ctx->end) {
#if UA_BINARY_OVERLAYABLE_INTEGER
        memcpy(ctx->pos, src, sizeof(u16));
#else
        UA_encode16(*src, ctx->pos);
#endif
    }
    ctx->pos += 2;
    return UA_STATUSCODE_GOOD;
}

FUNC_DECODE_BINARY(UInt16) {
    UA_CHECK(ctx->pos + sizeof(u16) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);
#if UA_BINARY_OVERLAYABLE_INTEGER
    memcpy(dst, ctx->pos, sizeof(u16));
#else
    UA_decode16(ctx->pos, dst);
#endif
    ctx->pos += 2;
    return UA_STATUSCODE_GOOD;
}


FUNC_ENCODE_BINARY(UInt32) {
    IF_CHECK_BUFSIZE(ctx->pos + sizeof(u32) <= ctx->end) {
#if UA_BINARY_OVERLAYABLE_INTEGER
        memcpy(ctx->pos, src, sizeof(u32));
#else
        UA_encode32(*src, ctx->pos);
#endif
    }
    ctx->pos += 4;
    return UA_STATUSCODE_GOOD;
}

FUNC_DECODE_BINARY(UInt32) {
    UA_CHECK(ctx->pos + sizeof(u32) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);
#if UA_BINARY_OVERLAYABLE_INTEGER
    memcpy(dst, ctx->pos, sizeof(u32));
#else
    UA_decode32(ctx->pos, dst);
#endif
    ctx->pos += 4;
    return UA_STATUSCODE_GOOD;
}


FUNC_ENCODE_BINARY(UInt64) {
    IF_CHECK_BUFSIZE(ctx->pos + sizeof(u64) <= ctx->end) {
#if UA_BINARY_OVERLAYABLE_INTEGER
        memcpy(ctx->pos, src, sizeof(u64));
#else
        UA_encode64(*src, ctx->pos);
#endif
    }
    ctx->pos += 8;
    return UA_STATUSCODE_GOOD;
}

FUNC_DECODE_BINARY(UInt64) {
    UA_CHECK(ctx->pos + sizeof(u64) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);
#if UA_BINARY_OVERLAYABLE_INTEGER
    memcpy(dst, ctx->pos, sizeof(u64));
#else
    UA_decode64(ctx->pos, dst);
#endif
    ctx->pos += 8;
    return UA_STATUSCODE_GOOD;
}





#if (UA_FLOAT_IEEE754 == 1) && (UA_LITTLE_ENDIAN == UA_FLOAT_LITTLE_ENDIAN)
# define Float_encodeBinary UInt32_encodeBinary
# define Float_decodeBinary UInt32_decodeBinary
# define Double_encodeBinary UInt64_encodeBinary
# define Double_decodeBinary UInt64_decodeBinary
#else

#include <math.h>

#pragma message "No native IEEE 754 format detected. Use slow generic encoding."

static uint64_t
pack754(long double f, unsigned bits, unsigned expbits) {
    unsigned significandbits = bits - expbits - 1;
    long double fnorm;
    long long sign;
    if(f < 0) { sign = 1; fnorm = -f; }
    else { sign = 0; fnorm = f; }
    int shift = 0;
    while(fnorm >= 2.0) { fnorm /= 2.0; ++shift; }
    while(fnorm < 1.0) { fnorm *= 2.0; --shift; }
    fnorm = fnorm - 1.0;
    long long significand = (long long)(fnorm * ((float)(1LL<<significandbits) + 0.5f));
    long long exponent = shift + ((1<<(expbits-1)) - 1);
    return (uint64_t)((sign<<(bits-1)) | (exponent<<(bits-expbits-1)) | significand);
}

static long double
unpack754(uint64_t i, unsigned bits, unsigned expbits) {
    unsigned significandbits = bits - expbits - 1;
    long double result = (long double)(i&(uint64_t)((1LL<<significandbits)-1));
    result /= (long double)(1LL<<significandbits);
    result += 1.0f;
    unsigned bias = (unsigned)(1<<(expbits-1)) - 1;
    long long shift = (long long)((i>>significandbits) & (uint64_t)((1LL<<expbits)-1)) - bias;
    while(shift > 0) { result *= 2.0; --shift; }
    while(shift < 0) { result /= 2.0; ++shift; }
    result *= ((i>>(bits-1))&1)? -1.0: 1.0;
    return result;
}


#define FLOAT_NAN 0xffc00000
#define FLOAT_INF 0x7f800000
#define FLOAT_NEG_INF 0xff800000
#define FLOAT_NEG_ZERO 0x80000000

FUNC_ENCODE_BINARY(Float) {
    UA_Float f = *src;
    u32 encoded;
    
    if(f != f) encoded = FLOAT_NAN;
    else if(f == 0.0f) encoded = signbit(f) ? FLOAT_NEG_ZERO : 0;
    else if(f/f != f/f) encoded = f > 0 ? FLOAT_INF : FLOAT_NEG_INF;
    else encoded = (u32)pack754(f, 32, 8);
    return ENCODE_DIRECT(&encoded, UInt32);
}

FUNC_DECODE_BINARY(Float) {
    u32 decoded;
    status ret = DECODE_DIRECT(&decoded, UInt32);
    if(ret != UA_STATUSCODE_GOOD)
        return ret;
    if(decoded == 0) *dst = 0.0f;
    else if(decoded == FLOAT_NEG_ZERO) *dst = -0.0f;
    else if(decoded == FLOAT_INF) *dst = INFINITY;
    else if(decoded == FLOAT_NEG_INF) *dst = -INFINITY;
    else if((decoded >= 0x7f800001 && decoded <= 0x7fffffff) ||
       (decoded >= 0xff800001)) *dst = NAN;
    else *dst = (UA_Float)unpack754(decoded, 32, 8);
    return UA_STATUSCODE_GOOD;
}


#define DOUBLE_NAN 0xfff8000000000000L
#define DOUBLE_INF 0x7ff0000000000000L
#define DOUBLE_NEG_INF 0xfff0000000000000L
#define DOUBLE_NEG_ZERO 0x8000000000000000L

FUNC_ENCODE_BINARY(Double) {
    UA_Double d = *src;
    u64 encoded;
    
    if(d != d) encoded = DOUBLE_NAN;
    else if(d == 0.0) encoded = signbit(d) ? DOUBLE_NEG_ZERO : 0;
    else if(d/d != d/d) encoded = d > 0 ? DOUBLE_INF : DOUBLE_NEG_INF;
    else encoded = pack754(d, 64, 11);
    return ENCODE_DIRECT(&encoded, UInt64);
}

FUNC_DECODE_BINARY(Double) {
    u64 decoded;
    status ret = DECODE_DIRECT(&decoded, UInt64);
    UA_CHECK_STATUS(ret, return ret);
    if(decoded == 0) *dst = 0.0;
    else if(decoded == DOUBLE_NEG_ZERO) *dst = -0.0;
    else if(decoded == DOUBLE_INF) *dst = INFINITY;
    else if(decoded == DOUBLE_NEG_INF) *dst = -INFINITY;
    else if((decoded >= 0x7ff0000000000001L && decoded <= 0x7fffffffffffffffL) ||
       (decoded >= 0xfff0000000000001L)) *dst = NAN;
    else *dst = (UA_Double)unpack754(decoded, 64, 11);
    return UA_STATUSCODE_GOOD;
}

#endif





static status
Array_encodeBinaryOverlayable(Ctx *ctx, uintptr_t ptr, size_t memSize) {
    
    if(ctx->end == NULL) {
        ctx->pos += memSize;
        return UA_STATUSCODE_GOOD;
    }

    
    while(ctx->end < ctx->pos + memSize) {
        size_t possible = ((uintptr_t)ctx->end - (uintptr_t)ctx->pos);
        memcpy(ctx->pos, (void*)ptr, possible);
        ctx->pos += possible;
        ptr += possible;
        status ret = exchangeBuffer(ctx);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        UA_CHECK_STATUS(ret, return ret);
        memSize -= possible;
    }

    
    memcpy(ctx->pos, (void*)ptr, memSize);
    ctx->pos += memSize;
    return UA_STATUSCODE_GOOD;
}

static status
Array_encodeBinaryComplex(Ctx *ctx, uintptr_t ptr, size_t length,
                          const UA_DataType *type) {
    
    for(size_t i = 0; i < length; ++i) {
        status ret = encodeWithExchangeBuffer(ctx, (const void*)ptr, type);
        ptr += type->memSize;
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        UA_CHECK_STATUS(ret, return ret); 
    }
    return UA_STATUSCODE_GOOD;
}

static status
Array_encodeBinary(Ctx *ctx, const void *src, size_t length, const UA_DataType *type) {
    
    i32 signed_length = -1;
    if(length > UA_INT32_MAX)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(length > 0)
        signed_length = (i32)length;
    else if(src == UA_EMPTY_ARRAY_SENTINEL)
        signed_length = 0;

    
    status ret = encodeWithExchangeBuffer(ctx, &signed_length, &UA_TYPES[UA_TYPES_INT32]);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    UA_CHECK_STATUS(ret, return ret);

    
    if(length > 0) {
        if(type->overlayable)
            ret = Array_encodeBinaryOverlayable(ctx, (uintptr_t)src, length * type->memSize);
        else
            ret = Array_encodeBinaryComplex(ctx, (uintptr_t)src, length, type);
    }
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    return ret;
}

static status
Array_decodeBinary(Ctx *ctx, void *UA_RESTRICT *UA_RESTRICT dst,
                   size_t *out_length, const UA_DataType *type) {
    
    i32 signed_length;
    status ret = DECODE_DIRECT(&signed_length, UInt32); 
    UA_CHECK_STATUS(ret, return ret);

    
    if(signed_length <= 0) {
        *out_length = 0;
        if(signed_length < 0)
            *dst = NULL;
        else
            *dst = UA_EMPTY_ARRAY_SENTINEL;
        return UA_STATUSCODE_GOOD;
    }

    size_t length = (size_t)signed_length;
    UA_CHECK(ctx->pos + ((type->memSize * length) / 128) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);

    
    *dst = ctxCalloc(ctx, length, type->memSize);
    UA_CHECK_MEM(*dst, return UA_STATUSCODE_BADOUTOFMEMORY);

    if(type->overlayable) {
        
        if(ctx->pos + (type->memSize * length) > ctx->end){
            ctxFree(ctx, *dst);
            *dst = NULL;
            return UA_STATUSCODE_BADDECODINGERROR;
        }
        memcpy(*dst, ctx->pos, type->memSize * length);
        ctx->pos += type->memSize * length;
    } else {
        
        uintptr_t ptr = (uintptr_t)*dst;
        for(size_t i = 0; i < length; ++i) {
            ret = decodeBinaryJumpTable[type->typeKind](ctx, (void*)ptr, type);
            if(ret != UA_STATUSCODE_GOOD) {
                if(!ctx->opts.calloc) {
                    
                    UA_Array_delete(*dst, i + 1, type);
                }
                *dst = NULL;
                return ret;
            }
            ptr += type->memSize;
        }
    }
    *out_length = length;
    return UA_STATUSCODE_GOOD;
}





FUNC_ENCODE_BINARY(String) {
    return Array_encodeBinary(ctx, src->data, src->length, &UA_TYPES[UA_TYPES_BYTE]);
}

FUNC_DECODE_BINARY(String) {
    return Array_decodeBinary(ctx, (void**)&dst->data, &dst->length, &UA_TYPES[UA_TYPES_BYTE]);
}


FUNC_ENCODE_BINARY(Guid) {
    status ret = UA_STATUSCODE_GOOD;
    ret |= ENCODE_DIRECT(&src->data1, UInt32);
    ret |= ENCODE_DIRECT(&src->data2, UInt16);
    ret |= ENCODE_DIRECT(&src->data3, UInt16);
    IF_CHECK_BUFSIZE(ctx->pos + (8*sizeof(u8)) <= ctx->end) {
        memcpy(ctx->pos, src->data4, 8*sizeof(u8));
    }
    ctx->pos += 8;
    return ret;
}

FUNC_DECODE_BINARY(Guid) {
    status ret = UA_STATUSCODE_GOOD;
    ret |= DECODE_DIRECT(&dst->data1, UInt32);
    ret |= DECODE_DIRECT(&dst->data2, UInt16);
    ret |= DECODE_DIRECT(&dst->data3, UInt16);
    UA_CHECK(ctx->pos + (8*sizeof(u8)) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);
    memcpy(dst->data4, ctx->pos, 8*sizeof(u8));
    ctx->pos += 8;
    return ret;
}


#define UA_NODEIDTYPE_NUMERIC_TWOBYTE 0u
#define UA_NODEIDTYPE_NUMERIC_FOURBYTE 1u
#define UA_NODEIDTYPE_NUMERIC_COMPLETE 2u

#define UA_EXPANDEDNODEID_SERVERINDEX_FLAG 0x40u
#define UA_EXPANDEDNODEID_NAMESPACEURI_FLAG 0x80u


static status
NodeId_encodeBinaryWithEncodingMask(Ctx *ctx, UA_NodeId const *src, u8 encoding) {
    status ret = UA_STATUSCODE_GOOD;
    switch(src->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
        if(src->identifier.numeric > UA_UINT16_MAX || src->namespaceIndex > UA_BYTE_MAX) {
            encoding |= UA_NODEIDTYPE_NUMERIC_COMPLETE;
            ret |= ENCODE_DIRECT(&encoding, Byte);
            ret |= ENCODE_DIRECT(&src->namespaceIndex, UInt16);
            ret |= ENCODE_DIRECT(&src->identifier.numeric, UInt32);
        } else if(src->identifier.numeric > UA_BYTE_MAX || src->namespaceIndex > 0) {
            encoding |= UA_NODEIDTYPE_NUMERIC_FOURBYTE;
            ret |= ENCODE_DIRECT(&encoding, Byte);
            u8 nsindex = (u8)src->namespaceIndex;
            ret |= ENCODE_DIRECT(&nsindex, Byte);
            u16 identifier16 = (u16)src->identifier.numeric;
            ret |= ENCODE_DIRECT(&identifier16, UInt16);
        } else {
            encoding |= UA_NODEIDTYPE_NUMERIC_TWOBYTE;
            ret |= ENCODE_DIRECT(&encoding, Byte);
            u8 identifier8 = (u8)src->identifier.numeric;
            ret |= ENCODE_DIRECT(&identifier8, Byte);
        }
        break;
    case UA_NODEIDTYPE_STRING:
        encoding |= (u8)UA_NODEIDTYPE_STRING;
        ret |= ENCODE_DIRECT(&encoding, Byte);
        ret |= ENCODE_DIRECT(&src->namespaceIndex, UInt16);
        UA_CHECK_STATUS(ret, return ret);
        
        ret = ENCODE_DIRECT(&src->identifier.string, String);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        break;
    case UA_NODEIDTYPE_GUID:
        encoding |= (u8)UA_NODEIDTYPE_GUID;
        ret |= ENCODE_DIRECT(&encoding, Byte);
        ret |= ENCODE_DIRECT(&src->namespaceIndex, UInt16);
        ret |= ENCODE_DIRECT(&src->identifier.guid, Guid);
        break;
    case UA_NODEIDTYPE_BYTESTRING:
        encoding |= (u8)UA_NODEIDTYPE_BYTESTRING;
        ret |= ENCODE_DIRECT(&encoding, Byte);
        ret |= ENCODE_DIRECT(&src->namespaceIndex, UInt16);
        UA_CHECK_STATUS(ret, return ret);
        
        ret = ENCODE_DIRECT(&src->identifier.byteString, String); 
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        break;
    default:
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return ret;
}

FUNC_ENCODE_BINARY(NodeId) {
    return NodeId_encodeBinaryWithEncodingMask(ctx, src, 0);
}

FUNC_DECODE_BINARY(NodeId) {
    u8 dstByte = 0, encodingByte = 0;
    u16 dstUInt16 = 0;

    
    status ret = DECODE_DIRECT(&encodingByte, Byte);
    UA_CHECK_STATUS(ret, return ret);

    
    encodingByte &= (u8)~(u8)(UA_EXPANDEDNODEID_SERVERINDEX_FLAG |
                              UA_EXPANDEDNODEID_NAMESPACEURI_FLAG);

    
    switch(encodingByte) {
    case UA_NODEIDTYPE_NUMERIC_TWOBYTE:
        dst->identifierType = UA_NODEIDTYPE_NUMERIC;
        ret = DECODE_DIRECT(&dstByte, Byte);
        dst->identifier.numeric = dstByte;
        dst->namespaceIndex = 0;
        break;
    case UA_NODEIDTYPE_NUMERIC_FOURBYTE:
        dst->identifierType = UA_NODEIDTYPE_NUMERIC;
        ret |= DECODE_DIRECT(&dstByte, Byte);
        dst->namespaceIndex = dstByte;
        ret |= DECODE_DIRECT(&dstUInt16, UInt16);
        dst->identifier.numeric = dstUInt16;
        break;
    case UA_NODEIDTYPE_NUMERIC_COMPLETE:
        dst->identifierType = UA_NODEIDTYPE_NUMERIC;
        ret |= DECODE_DIRECT(&dst->namespaceIndex, UInt16);
        ret |= DECODE_DIRECT(&dst->identifier.numeric, UInt32);
        break;
    case UA_NODEIDTYPE_STRING:
        dst->identifierType = UA_NODEIDTYPE_STRING;
        ret |= DECODE_DIRECT(&dst->namespaceIndex, UInt16);
        ret |= DECODE_DIRECT(&dst->identifier.string, String);
        break;
    case UA_NODEIDTYPE_GUID:
        dst->identifierType = UA_NODEIDTYPE_GUID;
        ret |= DECODE_DIRECT(&dst->namespaceIndex, UInt16);
        ret |= DECODE_DIRECT(&dst->identifier.guid, Guid);
        break;
    case UA_NODEIDTYPE_BYTESTRING:
        dst->identifierType = UA_NODEIDTYPE_BYTESTRING;
        ret |= DECODE_DIRECT(&dst->namespaceIndex, UInt16);
        ret |= DECODE_DIRECT(&dst->identifier.byteString, String); 
        break;
    default:
        ret |= UA_STATUSCODE_BADINTERNALERROR;
        break;
    }
    return ret;
}


FUNC_ENCODE_BINARY(ExpandedNodeId) {
    
    u8 encoding = 0;
    if((void*)src->namespaceUri.data > UA_EMPTY_ARRAY_SENTINEL)
        encoding |= UA_EXPANDEDNODEID_NAMESPACEURI_FLAG;
    if(src->serverIndex > 0)
        encoding |= UA_EXPANDEDNODEID_SERVERINDEX_FLAG;

    
    status ret = NodeId_encodeBinaryWithEncodingMask(ctx, &src->nodeId, encoding);
    UA_CHECK_STATUS(ret, return ret);

    if((void*)src->namespaceUri.data > UA_EMPTY_ARRAY_SENTINEL) {
        ret = ENCODE_DIRECT(&src->namespaceUri, String);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        UA_CHECK_STATUS(ret, return ret);
    }

    
    if(src->serverIndex > 0)
        ret = encodeWithExchangeBuffer(ctx, &src->serverIndex, &UA_TYPES[UA_TYPES_UINT32]);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    return ret;
}

FUNC_DECODE_BINARY(ExpandedNodeId) {
    
    UA_CHECK(ctx->pos + 1 <= ctx->end, return UA_STATUSCODE_BADDECODINGERROR);
    u8 encoding = *ctx->pos;

    
    status ret = DECODE_DIRECT(&dst->nodeId, NodeId);

    
    if(encoding & UA_EXPANDEDNODEID_NAMESPACEURI_FLAG) {
        dst->nodeId.namespaceIndex = 0;
        ret |= DECODE_DIRECT(&dst->namespaceUri, String);
    }

    
    if(encoding & UA_EXPANDEDNODEID_SERVERINDEX_FLAG)
        ret |= DECODE_DIRECT(&dst->serverIndex, UInt32);
    return ret;
}


FUNC_ENCODE_BINARY(QualifiedName) {
    status ret = ENCODE_DIRECT(&src->namespaceIndex, UInt16);
    
    UA_CHECK_STATUS(ret, return ret);
    ret |= ENCODE_DIRECT(&src->name, String);
    return ret;
}

FUNC_DECODE_BINARY(QualifiedName) {
    status ret = DECODE_DIRECT(&dst->namespaceIndex, UInt16);
    ret |= DECODE_DIRECT(&dst->name, String);
    return ret;
}


#define UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_LOCALE 0x01u
#define UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_TEXT 0x02u

FUNC_ENCODE_BINARY(LocalizedText) {
    
    u8 encoding = 0;
    if(src->locale.data)
        encoding |= UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_LOCALE;
    if(src->text.data)
        encoding |= UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_TEXT;

    
    status ret = ENCODE_DIRECT(&encoding, Byte);
    
    UA_CHECK_STATUS(ret, return ret);

    
    if(encoding & UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_LOCALE)
        ret |= ENCODE_DIRECT(&src->locale, String);
    if(encoding & UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_TEXT)
        ret |= ENCODE_DIRECT(&src->text, String);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    return ret;
}

FUNC_DECODE_BINARY(LocalizedText) {
    
    u8 encoding = 0;
    status ret = DECODE_DIRECT(&encoding, Byte);

    
    if(encoding & UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_LOCALE)
        ret |= DECODE_DIRECT(&dst->locale, String);
    if(encoding & UA_LOCALIZEDTEXT_ENCODINGMASKTYPE_TEXT)
        ret |= DECODE_DIRECT(&dst->text, String);
    return ret;
}

static const UA_DataType *
UA_findDataTypeByBinaryInternal(Ctx *ctx, const UA_NodeId *typeId) {
    if(typeId->identifierType == UA_NODEIDTYPE_NUMERIC) {
        for(size_t i = 0; i < UA_TYPES_COUNT; ++i) {
            if(UA_TYPES[i].binaryEncodingId.identifier.numeric == typeId->identifier.numeric &&
               UA_TYPES[i].binaryEncodingId.namespaceIndex == typeId->namespaceIndex)
                return &UA_TYPES[i];
        }
    }

    const UA_DataTypeArray *customTypes = ctx->opts.customTypes;
    while(customTypes) {
        for(size_t i = 0; i < customTypes->typesSize; ++i) {
            if(UA_NodeId_equal(typeId, &customTypes->types[i].binaryEncodingId))
                return &customTypes->types[i];
        }
        customTypes = customTypes->next;
    }

    return NULL;
}

const UA_DataType *
UA_findDataTypeByBinary(const UA_NodeId *typeId) {
    Ctx ctx;
    ctx.opts.customTypes = NULL;
    return UA_findDataTypeByBinaryInternal(&ctx, typeId);
}


FUNC_ENCODE_BINARY(ExtensionObject) {
    u8 encoding = (u8)src->encoding;

    
    if(encoding <= UA_EXTENSIONOBJECT_ENCODED_XML) {
        
        status ret = ENCODE_DIRECT(&src->content.encoded.typeId, NodeId);
        UA_CHECK_STATUS(ret, return ret);
        ret = encodeWithExchangeBuffer(ctx, &encoding, &UA_TYPES[UA_TYPES_BYTE]);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        UA_CHECK_STATUS(ret, return ret);
        switch(src->encoding) {
        case UA_EXTENSIONOBJECT_ENCODED_NOBODY:
            break;
        case UA_EXTENSIONOBJECT_ENCODED_BYTESTRING:
        case UA_EXTENSIONOBJECT_ENCODED_XML:
            
            ret = ENCODE_DIRECT(&src->content.encoded.body, String);
            break;
        default:
            ret = UA_STATUSCODE_BADINTERNALERROR;
        }
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        return ret;
    }

    
    if(!src->content.decoded.type || !src->content.decoded.data)
        return UA_STATUSCODE_BADENCODINGERROR;

    status ret = ENCODE_DIRECT(&src->content.decoded.type->binaryEncodingId, NodeId);
    UA_CHECK_STATUS(ret, return ret);

    
    encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
    ret = encodeWithExchangeBuffer(ctx, &encoding, &UA_TYPES[UA_TYPES_BYTE]);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    UA_CHECK_STATUS(ret, return ret);

    const UA_DataType *contentType = src->content.decoded.type;

    i32 signed_len = 0;
    if(ctx->end != NULL) {
        size_t len = UA_calcSizeBinary(src->content.decoded.data, contentType);
        UA_CHECK(len <= UA_INT32_MAX, return UA_STATUSCODE_BADENCODINGERROR);
        signed_len = (i32)len;
    }
    ret = encodeWithExchangeBuffer(ctx, &signed_len, &UA_TYPES[UA_TYPES_INT32]);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    UA_CHECK_STATUS(ret, return ret);

    
    ret = encodeWithExchangeBuffer(ctx, src->content.decoded.data, contentType);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    return ret;
}

static status
ExtensionObject_decodeBinaryContent(Ctx *ctx, UA_ExtensionObject *dst,
                                    const UA_NodeId *typeId) {
    
    const UA_DataType *type = UA_findDataTypeByBinaryInternal(ctx, typeId);

    
    if(!type) {
        dst->encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
        UA_NodeId_copy(typeId, &dst->content.encoded.typeId);
        return DECODE_DIRECT(&dst->content.encoded.body, String); 
    }

    
    dst->content.decoded.data = ctxCalloc(ctx, 1, type->memSize);
    UA_CHECK_MEM(dst->content.decoded.data, return UA_STATUSCODE_BADOUTOFMEMORY);

    
    ctx->pos += 4;

    
    dst->encoding = UA_EXTENSIONOBJECT_DECODED;
    dst->content.decoded.type = type;
    return decodeBinaryJumpTable[type->typeKind](ctx, dst->content.decoded.data, type);
}

FUNC_DECODE_BINARY(ExtensionObject) {
    u8 encoding = 0;
    UA_NodeId binTypeId;
    UA_NodeId_init(&binTypeId);

    status ret = UA_STATUSCODE_GOOD;
    ret |= DECODE_DIRECT(&binTypeId, NodeId);
    ret |= DECODE_DIRECT(&encoding, Byte);
    UA_CHECK_STATUS(ret, ctxClearNodeId(ctx, &binTypeId); return ret);

    switch(encoding) {
    case UA_EXTENSIONOBJECT_ENCODED_BYTESTRING:
        ret = ExtensionObject_decodeBinaryContent(ctx, dst, &binTypeId);
        ctxClearNodeId(ctx, &binTypeId);
        break;
    case UA_EXTENSIONOBJECT_ENCODED_NOBODY:
        dst->encoding = (UA_ExtensionObjectEncoding)encoding;
        dst->content.encoded.typeId = binTypeId; 
        dst->content.encoded.body = UA_BYTESTRING_NULL;
        break;
    case UA_EXTENSIONOBJECT_ENCODED_XML:
        dst->encoding = (UA_ExtensionObjectEncoding)encoding;
        dst->content.encoded.typeId = binTypeId; 
        ret = DECODE_DIRECT(&dst->content.encoded.body, String); 
        UA_CHECK_STATUS(ret, ctxClearNodeId(ctx, &dst->content.encoded.typeId));
        break;
    default:
        ctxClearNodeId(ctx, &binTypeId);
        ret = UA_STATUSCODE_BADDECODINGERROR;
        break;
    }

    return ret;
}



static status
Variant_encodeBinaryWrapExtensionObject(Ctx *ctx, const UA_Variant *src,
                                        const UA_Boolean isArray) {
    size_t length = 1; 

    
    status ret = UA_STATUSCODE_GOOD;
    if(isArray) {
        UA_CHECK(src->arrayLength <= UA_INT32_MAX, return UA_STATUSCODE_BADENCODINGERROR);
        length = src->arrayLength;

        i32 encodedLength = (i32)src->arrayLength;
        ret = encodeWithExchangeBuffer(ctx, &encodedLength, &UA_TYPES[UA_TYPES_INT32]);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        UA_CHECK_STATUS(ret, return ret);
    }

    
    UA_ExtensionObject eo;
    UA_ExtensionObject_init(&eo);
    eo.encoding = UA_EXTENSIONOBJECT_DECODED;
    eo.content.decoded.type = src->type;
    const u16 memSize = src->type->memSize;
    uintptr_t ptr = (uintptr_t)src->data;

    
    for(size_t i = 0; i < length && ret == UA_STATUSCODE_GOOD; ++i) {
        eo.content.decoded.data = (void*)ptr;
        ret = encodeWithExchangeBuffer(ctx, &eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        ptr += memSize;
    }
    return ret;
}

enum UA_VARIANT_ENCODINGMASKTYPE {
    UA_VARIANT_ENCODINGMASKTYPE_TYPEID_MASK = 0x3Fu,        
    UA_VARIANT_ENCODINGMASKTYPE_DIMENSIONS = (u8)(0x01u << 6u), 
    UA_VARIANT_ENCODINGMASKTYPE_ARRAY = (u8)(0x01u << 7u)  
};

FUNC_ENCODE_BINARY(Variant) {
    
    u8 encoding = 0;
    if(!src->type)
        return ENCODE_DIRECT(&encoding, Byte);

    
    const UA_Boolean isBuiltin = (src->type->typeKind <= UA_DATATYPEKIND_DIAGNOSTICINFO);
    const UA_Boolean isEnum = (src->type->typeKind == UA_DATATYPEKIND_ENUM);
    if(isBuiltin)
        encoding = (u8)(encoding | (u8)((u8)UA_VARIANT_ENCODINGMASKTYPE_TYPEID_MASK & (u8)(src->type->typeKind + 1u)));
    else if(isEnum)
        encoding = (u8)(encoding | (u8)((u8)UA_VARIANT_ENCODINGMASKTYPE_TYPEID_MASK & (u8)(UA_TYPES_INT32 + 1u)));
    else
        encoding = (u8)(encoding | (u8)((u8)UA_VARIANT_ENCODINGMASKTYPE_TYPEID_MASK & (u8)(UA_TYPES_EXTENSIONOBJECT + 1u)));

    
    const UA_Boolean isArray = src->arrayLength > 0 || src->data <= UA_EMPTY_ARRAY_SENTINEL;
    const UA_Boolean hasDimensions = isArray && src->arrayDimensionsSize > 0;
    if(isArray) {
        encoding |= (u8)UA_VARIANT_ENCODINGMASKTYPE_ARRAY;
        if(hasDimensions) {
            encoding |= (u8)UA_VARIANT_ENCODINGMASKTYPE_DIMENSIONS;
            size_t totalRequiredSize = 1;
            for(size_t i = 0; i < src->arrayDimensionsSize; ++i)
                totalRequiredSize *= src->arrayDimensions[i];
            if(totalRequiredSize != src->arrayLength) return UA_STATUSCODE_BADENCODINGERROR;
        }
    }

    
    status ret = ENCODE_DIRECT(&encoding, Byte);
    UA_CHECK_STATUS(ret, return ret);

    
    if(!isBuiltin && !isEnum) {
        ret = Variant_encodeBinaryWrapExtensionObject(ctx, src, isArray);
    } else if(!isArray) {
        ret = encodeWithExchangeBuffer(ctx, src->data, src->type);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    } else {
        ret = Array_encodeBinary(ctx, src->data, src->arrayLength, src->type);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    }
    UA_CHECK_STATUS(ret, return ret);

    
    if(hasDimensions && ret == UA_STATUSCODE_GOOD)
        ret = Array_encodeBinary(ctx, src->arrayDimensions, src->arrayDimensionsSize,
                                 &UA_TYPES[UA_TYPES_INT32]);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    return ret;
}

static status
Variant_decodeBinaryUnwrapExtensionObject(Ctx *ctx, UA_Variant *dst) {
    u8 *old_pos = ctx->pos;

    
    UA_NodeId typeId;
    UA_NodeId_init(&typeId);
    status ret = DECODE_DIRECT(&typeId, NodeId);
    UA_CHECK_STATUS(ret, return ret);

    
    u8 encoding;
    ret = DECODE_DIRECT(&encoding, Byte);
    UA_CHECK_STATUS(ret, ctxClearNodeId(ctx, &typeId); return ret);

    
    if(encoding == UA_EXTENSIONOBJECT_ENCODED_BYTESTRING &&
       (dst->type = UA_findDataTypeByBinaryInternal(ctx, &typeId)) != NULL) {
        
        ctx->pos += 4;
    } else {
        
        dst->type = &UA_TYPES[UA_TYPES_EXTENSIONOBJECT];
        ctx->pos = old_pos;
    }
    ctxClearNodeId(ctx, &typeId);

    
    dst->data = ctxCalloc(ctx, 1, dst->type->memSize);
    UA_CHECK_MEM(dst->data, return UA_STATUSCODE_BADOUTOFMEMORY);

    
    return decodeBinaryJumpTable[dst->type->typeKind](ctx, dst->data, dst->type);
}

static status
Variant_decodeBinaryUnwrapExtensionObjectArray(Ctx *ctx, void *UA_RESTRICT *UA_RESTRICT dst,
                                               size_t *out_length, const UA_DataType **type) {
    u8 *orig_pos = ctx->pos;

    
    i32 signed_length;
    status ret = DECODE_DIRECT(&signed_length, UInt32); 
    UA_CHECK_STATUS(ret, return ret);

    
    if(signed_length <= 0) {
        *out_length = 0;
        if(signed_length < 0)
            *dst = NULL;
        else
            *dst = UA_EMPTY_ARRAY_SENTINEL;
        return UA_STATUSCODE_GOOD;
    }

    size_t length = (size_t)signed_length;
    UA_CHECK(ctx->pos + ((4 * length) / 32) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);

    
    UA_NodeId binTypeId;
    UA_NodeId_init(&binTypeId);
    ret |= DECODE_DIRECT(&binTypeId, NodeId);
    UA_CHECK_STATUS(ret, return ret);

    
    const UA_DataType *contentType = UA_findDataTypeByBinaryInternal(ctx, &binTypeId);
    ctxClearNodeId(ctx, &binTypeId);
    if(!contentType) {
        
        ctx->pos = orig_pos;
        return Array_decodeBinary(ctx, dst, out_length, *type);
    }

    
    u8 encoding = 0;
    ret |= DECODE_DIRECT(&encoding, Byte);
    UA_CHECK_STATUS(ret, return ret);
    if(encoding != UA_EXTENSIONOBJECT_ENCODED_BYTESTRING) {
        ctx->pos = orig_pos;
        return Array_decodeBinary(ctx, dst, out_length, *type);
    }

    
    UA_ByteString header = {(uintptr_t)ctx->pos - (uintptr_t)orig_pos - 4, &orig_pos[4]};
    UA_ByteString compare_header = header;
    ctx->pos = &orig_pos[4];

    for(size_t i = 0; i < length; i++) {
        compare_header.data = ctx->pos;
        UA_CHECK(compare_header.data + compare_header.length <= ctx->end,
                 return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        if(!UA_ByteString_equal(&header, &compare_header)) {
            
            ctx->pos = orig_pos;
            return Array_decodeBinary(ctx, dst, out_length, *type);
        }

        
        ctx->pos += header.length;
        u32 member_length = 0;
        ret = DECODE_DIRECT(&member_length, UInt32);
        UA_CHECK_STATUS(ret, return ret);
        ctx->pos += member_length;
    }

    
    *dst = ctxCalloc(ctx, length, contentType->memSize);
    UA_CHECK_MEM(*dst, return UA_STATUSCODE_BADOUTOFMEMORY);
    *out_length = length;
    *type = contentType;

    
    uintptr_t array_pos = (uintptr_t)*dst;
    ctx->pos = &orig_pos[4];
    for(size_t i = 0; i < length && ret == UA_STATUSCODE_GOOD; i++) {
        ctx->pos += header.length + 4; 
        ret = decodeBinaryJumpTable[contentType->typeKind]
            (ctx, (void*)array_pos, contentType);
        array_pos += contentType->memSize;
    }
    return ret;
}


FUNC_DECODE_BINARY(Variant) {
    
    u8 encodingByte;
    status ret = DECODE_DIRECT(&encodingByte, Byte);
    UA_CHECK_STATUS(ret, return ret);

    
    if(encodingByte == 0)
        return UA_STATUSCODE_GOOD;

    
    const UA_Boolean isArray = (encodingByte & (u8)UA_VARIANT_ENCODINGMASKTYPE_ARRAY) > 0;

    size_t typeKind = (size_t)((encodingByte & (u8)UA_VARIANT_ENCODINGMASKTYPE_TYPEID_MASK) - 1);
    UA_CHECK(typeKind <= UA_DATATYPEKIND_DIAGNOSTICINFO, return UA_STATUSCODE_BADDECODINGERROR);

    UA_CHECK(typeKind != UA_DATATYPEKIND_VARIANT || isArray,
             return UA_STATUSCODE_BADDECODINGERROR);

    
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION, return UA_STATUSCODE_BADENCODINGERROR);
    ctx->depth++;

    
    dst->type = &UA_TYPES[typeKind];
    if(!isArray) {
        
        if(typeKind != UA_DATATYPEKIND_EXTENSIONOBJECT) {
            dst->data = ctxCalloc(ctx, 2, dst->type->memSize);
            UA_CHECK_MEM(dst->data, ctx->depth--; return UA_STATUSCODE_BADOUTOFMEMORY);
            ret = decodeBinaryJumpTable[typeKind](ctx, dst->data, dst->type);
        } else {
            ret = Variant_decodeBinaryUnwrapExtensionObject(ctx, dst);
        }
    } else {
        
        if(typeKind != UA_DATATYPEKIND_EXTENSIONOBJECT) {
            ret = Array_decodeBinary(ctx, &dst->data, &dst->arrayLength, dst->type);
        } else {
            ret = Variant_decodeBinaryUnwrapExtensionObjectArray(ctx, &dst->data,
                                                                 &dst->arrayLength, &dst->type);
        }

        
        if((encodingByte & (u8)UA_VARIANT_ENCODINGMASKTYPE_DIMENSIONS) > 0)
            ret |= Array_decodeBinary(ctx, (void **)&dst->arrayDimensions,
                                      &dst->arrayDimensionsSize, &UA_TYPES[UA_TYPES_INT32]);
    }

    ctx->depth--;
    return ret;
}


FUNC_ENCODE_BINARY(DataValue) {
    
    u8 encodingMask = src->hasValue;
    encodingMask |= (u8)(src->hasStatus << 1u);
    encodingMask |= (u8)(src->hasSourceTimestamp << 2u);
    encodingMask |= (u8)(src->hasServerTimestamp << 3u);
    encodingMask |= (u8)(src->hasSourcePicoseconds << 4u);
    encodingMask |= (u8)(src->hasServerPicoseconds << 5u);

    
    status ret = ENCODE_DIRECT(&encodingMask, Byte);
    UA_CHECK_STATUS(ret, return ret);

    
    if(src->hasValue) {
        ret = ENCODE_DIRECT(&src->value, Variant);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(src->hasStatus)
        ret |= encodeWithExchangeBuffer(ctx, &src->status, &UA_TYPES[UA_TYPES_STATUSCODE]);
    if(src->hasSourceTimestamp)
        ret |= encodeWithExchangeBuffer(ctx, &src->sourceTimestamp, &UA_TYPES[UA_TYPES_DATETIME]);
    if(src->hasSourcePicoseconds)
        ret |= encodeWithExchangeBuffer(ctx, &src->sourcePicoseconds, &UA_TYPES[UA_TYPES_UINT16]);
    if(src->hasServerTimestamp)
        ret |= encodeWithExchangeBuffer(ctx, &src->serverTimestamp, &UA_TYPES[UA_TYPES_DATETIME]);
    if(src->hasServerPicoseconds)
        ret |= encodeWithExchangeBuffer(ctx, &src->serverPicoseconds, &UA_TYPES[UA_TYPES_UINT16]);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    return ret;
}

#define MAX_PICO_SECONDS 9999

FUNC_DECODE_BINARY(DataValue) {
    
    u8 encodingMask;
    status ret = DECODE_DIRECT(&encodingMask, Byte);
    UA_CHECK_STATUS(ret, return ret);

    
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION, return UA_STATUSCODE_BADENCODINGERROR);
    ctx->depth++;

    
    if(encodingMask & 0x01u) {
        dst->hasValue = true;
        ret |= DECODE_DIRECT(&dst->value, Variant);
    }
    if(encodingMask & 0x02u) {
        dst->hasStatus = true;
        ret |= DECODE_DIRECT(&dst->status, UInt32); 
    }
    if(encodingMask & 0x04u) {
        dst->hasSourceTimestamp = true;
        ret |= DECODE_DIRECT(&dst->sourceTimestamp, UInt64); 
    }
    if(encodingMask & 0x10u) {
        dst->hasSourcePicoseconds = true;
        ret |= DECODE_DIRECT(&dst->sourcePicoseconds, UInt16);
        if(dst->sourcePicoseconds > MAX_PICO_SECONDS)
            dst->sourcePicoseconds = MAX_PICO_SECONDS;
    }
    if(encodingMask & 0x08u) {
        dst->hasServerTimestamp = true;
        ret |= DECODE_DIRECT(&dst->serverTimestamp, UInt64); 
    }
    if(encodingMask & 0x20u) {
        dst->hasServerPicoseconds = true;
        ret |= DECODE_DIRECT(&dst->serverPicoseconds, UInt16);
        if(dst->serverPicoseconds > MAX_PICO_SECONDS)
            dst->serverPicoseconds = MAX_PICO_SECONDS;
    }

    ctx->depth--;
    return ret;
}


FUNC_ENCODE_BINARY(DiagnosticInfo) {
    
    u8 encodingMask = src->hasSymbolicId;
    encodingMask |= (u8)(src->hasNamespaceUri << 1u);
    encodingMask |= (u8)(src->hasLocalizedText << 2u);
    encodingMask |= (u8)(src->hasLocale << 3u);
    encodingMask |= (u8)(src->hasAdditionalInfo << 4u);
    encodingMask |= (u8)(src->hasInnerStatusCode << 5u);
    encodingMask |= (u8)(src->hasInnerDiagnosticInfo << 6u);

    
    status ret = ENCODE_DIRECT(&encodingMask, Byte);
    if(src->hasSymbolicId)
        ret |= ENCODE_DIRECT(&src->symbolicId, UInt32); 
    if(src->hasNamespaceUri)
        ret |= ENCODE_DIRECT(&src->namespaceUri, UInt32); 
    if(src->hasLocale)
        ret |= ENCODE_DIRECT(&src->locale, UInt32); 
    if(src->hasLocalizedText)
        ret |= ENCODE_DIRECT(&src->localizedText, UInt32); 
    if(ret != UA_STATUSCODE_GOOD)
        return ret;

    
    if(src->hasAdditionalInfo) {
        ret = ENCODE_DIRECT(&src->additionalInfo, String);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        UA_CHECK_STATUS(ret, return ret);
    }

    
    if(src->hasInnerStatusCode) {
        ret = encodeWithExchangeBuffer(ctx, &src->innerStatusCode, &UA_TYPES[UA_TYPES_UINT32]);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        UA_CHECK_STATUS(ret, return ret);
    }

    
    if(src->hasInnerDiagnosticInfo) {
        ret = encodeWithExchangeBuffer(ctx, src->innerDiagnosticInfo,
                                       &UA_TYPES[UA_TYPES_DIAGNOSTICINFO]);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
    }

    return ret;
}

FUNC_DECODE_BINARY(DiagnosticInfo) {
    
    u8 encodingMask;
    status ret = DECODE_DIRECT(&encodingMask, Byte);
    UA_CHECK_STATUS(ret, return ret);

    
    if(encodingMask & 0x01u) {
        dst->hasSymbolicId = true;
        ret |= DECODE_DIRECT(&dst->symbolicId, UInt32); 
    }
    if(encodingMask & 0x02u) {
        dst->hasNamespaceUri = true;
        ret |= DECODE_DIRECT(&dst->namespaceUri, UInt32); 
    }
    if(encodingMask & 0x08u) {
        dst->hasLocale = true;
        ret |= DECODE_DIRECT(&dst->locale, UInt32); 
    }
    if(encodingMask & 0x04u) {
        dst->hasLocalizedText = true;
        ret |= DECODE_DIRECT(&dst->localizedText, UInt32); 
    }
    if(encodingMask & 0x10u) {
        dst->hasAdditionalInfo = true;
        ret |= DECODE_DIRECT(&dst->additionalInfo, String);
    }
    if(encodingMask & 0x20u) {
        dst->hasInnerStatusCode = true;
        ret |= DECODE_DIRECT(&dst->innerStatusCode, UInt32); 
    }
    if(encodingMask & 0x40u) {
        
        dst->innerDiagnosticInfo = (UA_DiagnosticInfo*)
            ctxCalloc(ctx, 1, sizeof(UA_DiagnosticInfo));
        UA_CHECK_MEM(dst->innerDiagnosticInfo, return UA_STATUSCODE_BADOUTOFMEMORY);
        dst->hasInnerDiagnosticInfo = true;

        
        UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION,
                 return UA_STATUSCODE_BADENCODINGERROR);

        ctx->depth++;
        ret |= DECODE_DIRECT(dst->innerDiagnosticInfo, DiagnosticInfo);
        ctx->depth--;
    }
    return ret;
}





static status
encodeBinaryStruct(Ctx *ctx, const void *src, const UA_DataType *type) {
    
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION,
             return UA_STATUSCODE_BADENCODINGERROR);
    ctx->depth++;

    
    uintptr_t ptr = (uintptr_t)src;
    status ret = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < type->membersSize && ret == UA_STATUSCODE_GOOD; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        ptr += m->padding;

        
        if(m->isArray) {
            const size_t length = *((const size_t*)ptr);
            ptr += sizeof(size_t);
            ret = Array_encodeBinary(ctx, *(void *UA_RESTRICT const *)ptr, length, mt);
            UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
            ptr += sizeof(void*);
            continue;
        }

        
        ret = encodeWithExchangeBuffer(ctx, (const void*)ptr, mt);
        UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);
        ptr += mt->memSize;
    }

    ctx->depth--;
    return ret;
}

static status
encodeBinaryStructWithOptFields(Ctx *ctx, const void *src, const UA_DataType *type) {
    
    if(ctx->depth > UA_ENCODING_MAX_RECURSION)
        return UA_STATUSCODE_BADENCODINGERROR;
    ctx->depth++;

    
    uintptr_t ptr = (uintptr_t)src;
    size_t optFieldCounter = 0;
    UA_UInt32 encodingMask = 0;
    for(size_t j = 0; j < type->membersSize; ++j) {
        const UA_DataTypeMember *m = &type->members[j];
        const UA_DataType *mt = m->memberType;
        ptr += m->padding;
        if(m->isOptional) {
            if(m->isArray)
                ptr += sizeof(size_t);
            if(*(void* const*)ptr != NULL)
                encodingMask |= (UA_UInt32) 1 << optFieldCounter;
            ptr += sizeof(void *);
            optFieldCounter++;
        } else if (m->isArray) {
            ptr += sizeof(size_t);
            ptr += sizeof(void *);
        } else {
            ptr += mt->memSize;
        }
    }

    
    status ret = ENCODE_DIRECT(&encodingMask, UInt32);
    UA_CHECK_STATUS(ret, ctx->depth--; return ret);

    
    ptr = (uintptr_t)src;
    for(size_t i = 0, o = 0; i < type->membersSize && UA_LIKELY(ret == UA_STATUSCODE_GOOD); ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        ptr += m->padding;

        if(m->isOptional) {
            if(!(encodingMask & (UA_UInt32) ( (UA_UInt32) 1<<(o++)))) {
                
                if(m->isArray)
                    ptr += sizeof(size_t);
            } else if(m->isArray) {
                
                const size_t length = *((const size_t *) ptr);
                ptr += sizeof(size_t);
                ret = Array_encodeBinary(ctx, *(void *UA_RESTRICT const *) ptr, length, mt);
            } else {
                
                ret = encodeWithExchangeBuffer(ctx, *(void* const*) ptr, mt);
            }
            ptr += sizeof(void *);
            continue;
        }

        
        if(m->isArray) {
            const size_t length = *((const size_t *) ptr);
            ptr += sizeof(size_t);
            ret = Array_encodeBinary(ctx, *(void *UA_RESTRICT const *) ptr, length, mt);
            ptr += sizeof(void *);
            continue;
        }

        
        ret = encodeWithExchangeBuffer(ctx, (const void*)ptr, mt);
        ptr += mt->memSize;
    }
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);

    ctx->depth--;
    return ret;
}

static status
encodeBinaryUnion(Ctx *ctx, const void *src, const UA_DataType *type) {
    
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION,
             return UA_STATUSCODE_BADENCODINGERROR);
    ctx->depth++;

    
    const UA_UInt32 selection = *(const UA_UInt32*)src;
    status ret = ENCODE_DIRECT(&selection, UInt32);
    if(UA_UNLIKELY(ret != UA_STATUSCODE_GOOD) || selection == 0) {
        ctx->depth--;
        return ret;
    }

    
    const UA_DataTypeMember *m = &type->members[selection-1];
    const UA_DataType *mt = m->memberType;

    
    uintptr_t ptr = ((uintptr_t)src) + m->padding; 
    if(!m->isArray) {
        ret = encodeWithExchangeBuffer(ctx, (const void*)ptr, mt);
    } else {
        const size_t length = *((const size_t*)ptr);
        ptr += sizeof(size_t);
        ret = Array_encodeBinary(ctx, *(void *UA_RESTRICT const *)ptr, length, mt);
    }

    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);

    ctx->depth--;
    return ret;
}

static status
encodeBinaryNotImplemented(Ctx *ctx, const void *src, const UA_DataType *type) {
    (void)src, (void)type, (void)ctx;
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

const encodeBinarySignature encodeBinaryJumpTable[UA_DATATYPEKINDS] = {
    (encodeBinarySignature)Boolean_encodeBinary,
    (encodeBinarySignature)Byte_encodeBinary, 
    (encodeBinarySignature)Byte_encodeBinary,
    (encodeBinarySignature)UInt16_encodeBinary, 
    (encodeBinarySignature)UInt16_encodeBinary,
    (encodeBinarySignature)UInt32_encodeBinary, 
    (encodeBinarySignature)UInt32_encodeBinary,
    (encodeBinarySignature)UInt64_encodeBinary, 
    (encodeBinarySignature)UInt64_encodeBinary,
    (encodeBinarySignature)Float_encodeBinary,
    (encodeBinarySignature)Double_encodeBinary,
    (encodeBinarySignature)String_encodeBinary,
    (encodeBinarySignature)UInt64_encodeBinary, 
    (encodeBinarySignature)Guid_encodeBinary,
    (encodeBinarySignature)String_encodeBinary, 
    (encodeBinarySignature)String_encodeBinary, 
    (encodeBinarySignature)NodeId_encodeBinary,
    (encodeBinarySignature)ExpandedNodeId_encodeBinary,
    (encodeBinarySignature)UInt32_encodeBinary, 
    (encodeBinarySignature)QualifiedName_encodeBinary,
    (encodeBinarySignature)LocalizedText_encodeBinary,
    (encodeBinarySignature)ExtensionObject_encodeBinary,
    (encodeBinarySignature)DataValue_encodeBinary,
    (encodeBinarySignature)Variant_encodeBinary,
    (encodeBinarySignature)DiagnosticInfo_encodeBinary,
    (encodeBinarySignature)encodeBinaryNotImplemented, 
    (encodeBinarySignature)UInt32_encodeBinary, 
    (encodeBinarySignature)encodeBinaryStruct,
    (encodeBinarySignature)encodeBinaryStructWithOptFields, 
    (encodeBinarySignature)encodeBinaryUnion, 
    (encodeBinarySignature)encodeBinaryStruct 
};

status
UA_encodeBinaryInternal(const void *src, const UA_DataType *type,
                        u8 **bufPos, const u8 **bufEnd,
                        UA_exchangeEncodeBuffer exchangeCallback,
                        void *exchangeHandle) {
    if(!type || !src)
        return UA_STATUSCODE_BADENCODINGERROR;

    
    Ctx ctx;
    ctx.pos = *bufPos;
    ctx.end = *bufEnd;
    ctx.depth = 0;
    ctx.exchangeBufferCallback = exchangeCallback;
    ctx.exchangeBufferCallbackHandle = exchangeHandle;

    
    status ret = encodeWithExchangeBuffer(&ctx, src, type);
    UA_assert(ret != UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED);

    *bufPos = ctx.pos;
    *bufEnd = ctx.end;
    return ret;
}

UA_StatusCode
UA_encodeBinary(const void *p, const UA_DataType *type,
                UA_ByteString *outBuf) {
    
    UA_Boolean allocated = false;
    status res = UA_STATUSCODE_GOOD;
    if(outBuf->length == 0) {
        size_t len = UA_calcSizeBinary(p, type);
        res = UA_ByteString_allocBuffer(outBuf, len);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        allocated = true;
    }

    
    u8 *pos = outBuf->data;
    const u8 *posEnd = &outBuf->data[outBuf->length];
    res = UA_encodeBinaryInternal(p, type, &pos, &posEnd, NULL, NULL);

    
    if(res == UA_STATUSCODE_GOOD) {
        outBuf->length = (size_t)((uintptr_t)pos - (uintptr_t)outBuf->data);
    } else if(allocated) {
        UA_ByteString_clear(outBuf);
    }
    return res;
}

static status
decodeBinaryNotImplemented(Ctx *ctx, void *dst, const UA_DataType *type) {
    (void)dst, (void)type, (void)ctx;
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

static status
decodeBinaryStructure(Ctx *ctx, void *dst, const UA_DataType *type) {
    
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION,
             return UA_STATUSCODE_BADENCODINGERROR);
    ctx->depth++;

    uintptr_t ptr = (uintptr_t)dst;
    status ret = UA_STATUSCODE_GOOD;
    u8 membersSize = type->membersSize;

    
    for(size_t i = 0; i < membersSize && ret == UA_STATUSCODE_GOOD; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        ptr += m->padding;

        
        if(m->isArray) {
            size_t *length = (size_t*)ptr;
            ptr += sizeof(size_t);
            ret = Array_decodeBinary(ctx, (void *UA_RESTRICT *UA_RESTRICT)ptr, length, mt);
            ptr += sizeof(void*);
            continue;
        }

        
        ret = decodeBinaryJumpTable[mt->typeKind](ctx, (void *UA_RESTRICT)ptr, mt);
        ptr += mt->memSize;
    }

    ctx->depth--;
    return ret;
}

static status
decodeBinaryStructureWithOptFields(Ctx *ctx, void *dst, const UA_DataType *type) {
    
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION, return UA_STATUSCODE_BADENCODINGERROR);
    ctx->depth++;

    uintptr_t ptr = (uintptr_t)dst;
    UA_UInt32 encodingMask = 0;
    status ret = UInt32_decodeBinary(ctx, &encodingMask, &UA_TYPES[UA_TYPES_UINT32]);
    UA_CHECK_STATUS(ret, ctx->depth--; return ret);

    
    for(size_t i = 0, o = 0; i < type->membersSize && ret == UA_STATUSCODE_GOOD; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        ptr += m->padding;
        if(m->isOptional) {
            if(!(encodingMask & (UA_UInt32) ( (UA_UInt32) 1<<(o++)))) {
                
                if(m->isArray)
                    ptr += sizeof(size_t);
            } else if(m->isArray) {
                
                size_t *length = (size_t*)ptr;
                ptr += sizeof(size_t);
                ret = Array_decodeBinary(ctx, (void *UA_RESTRICT *UA_RESTRICT)ptr, length, mt);
            } else {
                
                *(void *UA_RESTRICT *UA_RESTRICT) ptr = ctxCalloc(ctx, 1, mt->memSize);
                UA_CHECK_MEM(*(void *UA_RESTRICT *UA_RESTRICT) ptr, return UA_STATUSCODE_BADOUTOFMEMORY);
                ret = decodeBinaryJumpTable[mt->typeKind](ctx, *(void *UA_RESTRICT *UA_RESTRICT)ptr, mt);
            }
            ptr += sizeof(void *);
            continue;
        }

        
        if(m->isArray) {
            size_t *length = (size_t *)ptr;
            ptr += sizeof(size_t);
            ret = Array_decodeBinary(ctx, (void *UA_RESTRICT *UA_RESTRICT)ptr, length, mt);
            ptr += sizeof(void *);
            continue;
        }

        
        ret = decodeBinaryJumpTable[mt->typeKind](ctx, (void *UA_RESTRICT)ptr, mt);
        ptr += mt->memSize;
    }
    ctx->depth--;
    return ret;
}

static status
decodeBinaryUnion(Ctx *ctx, void *UA_RESTRICT dst, const UA_DataType *type) {
    
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION,
             return UA_STATUSCODE_BADENCODINGERROR);

    
    status ret = DECODE_DIRECT(dst, UInt32);
    UA_CHECK_STATUS(ret, return ret);

    
    UA_UInt32 selection = *(UA_UInt32*)dst;
    if(selection == 0)
        return UA_STATUSCODE_GOOD;

    
    UA_CHECK(selection-1 < type->membersSize,
             return UA_STATUSCODE_BADDECODINGERROR);

    
    const UA_DataTypeMember *m = &type->members[selection-1];
    const UA_DataType *mt = m->memberType;

    
    ctx->depth++;
    uintptr_t ptr = ((uintptr_t)dst) + m->padding; 
    if(!m->isArray) {
        ret = decodeBinaryJumpTable[mt->typeKind](ctx, (void *UA_RESTRICT)ptr, mt);
    } else {
        size_t *length = (size_t *)ptr;
        ptr += sizeof(size_t);
        ret = Array_decodeBinary(ctx, (void *UA_RESTRICT *UA_RESTRICT)ptr, length, mt);
    }
    ctx->depth--;
    return ret;
}

const decodeBinarySignature decodeBinaryJumpTable[UA_DATATYPEKINDS] = {
    (decodeBinarySignature)Boolean_decodeBinary,
    (decodeBinarySignature)Byte_decodeBinary, 
    (decodeBinarySignature)Byte_decodeBinary,
    (decodeBinarySignature)UInt16_decodeBinary, 
    (decodeBinarySignature)UInt16_decodeBinary,
    (decodeBinarySignature)UInt32_decodeBinary, 
    (decodeBinarySignature)UInt32_decodeBinary,
    (decodeBinarySignature)UInt64_decodeBinary, 
    (decodeBinarySignature)UInt64_decodeBinary,
    (decodeBinarySignature)Float_decodeBinary,
    (decodeBinarySignature)Double_decodeBinary,
    (decodeBinarySignature)String_decodeBinary,
    (decodeBinarySignature)UInt64_decodeBinary, 
    (decodeBinarySignature)Guid_decodeBinary,
    (decodeBinarySignature)String_decodeBinary, 
    (decodeBinarySignature)String_decodeBinary, 
    (decodeBinarySignature)NodeId_decodeBinary,
    (decodeBinarySignature)ExpandedNodeId_decodeBinary,
    (decodeBinarySignature)UInt32_decodeBinary, 
    (decodeBinarySignature)QualifiedName_decodeBinary,
    (decodeBinarySignature)LocalizedText_decodeBinary,
    (decodeBinarySignature)ExtensionObject_decodeBinary,
    (decodeBinarySignature)DataValue_decodeBinary,
    (decodeBinarySignature)Variant_decodeBinary,
    (decodeBinarySignature)DiagnosticInfo_decodeBinary,
    (decodeBinarySignature)decodeBinaryNotImplemented, 
    (decodeBinarySignature)UInt32_decodeBinary, 
    (decodeBinarySignature)decodeBinaryStructure,
    (decodeBinarySignature)decodeBinaryStructureWithOptFields, 
    (decodeBinarySignature)decodeBinaryUnion, 
    (decodeBinarySignature)decodeBinaryNotImplemented 
};

status
UA_decodeBinaryInternal(const UA_ByteString *src, size_t *offset,
                        void *dst, const UA_DataType *type,
                        const UA_DecodeBinaryOptions *options) {
    
    Ctx ctx;
    ctx.pos = &src->data[*offset];
    ctx.end = &src->data[src->length];
    ctx.depth = 0;
    if(options)
        ctx.opts = *options;
    else
        memset(&ctx.opts, 0, sizeof(UA_DecodeBinaryOptions));

    
    memset(dst, 0, type->memSize); 
    status ret = decodeBinaryJumpTable[type->typeKind](&ctx, dst, type);

    if(UA_LIKELY(ret == UA_STATUSCODE_GOOD)) {
        
        *offset = (size_t)(ctx.pos - src->data) / sizeof(u8);
    } else {
        
        ctxClear(&ctx, dst, type);
    }
    return ret;
}

UA_StatusCode
UA_decodeBinary(const UA_ByteString *inBuf,
                void *p, const UA_DataType *type,
                const UA_DecodeBinaryOptions *options) {
    size_t offset = 0;
    return UA_decodeBinaryInternal(inBuf, &offset, p, type, options);
}


size_t
UA_calcSizeBinary(const void *p, const UA_DataType *type) {
    u8 *pos = NULL;
    const u8 *posEnd = NULL;
    UA_StatusCode res = UA_encodeBinaryInternal(p, type, &pos, &posEnd, NULL, NULL);
    if(res != UA_STATUSCODE_GOOD)
        return 0;
    return (size_t)(uintptr_t)pos;
}
