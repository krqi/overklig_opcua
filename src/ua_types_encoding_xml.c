
#include <opcua/config.h>
#include <opcua/types.h>

#include "ua_types_encoding_xml.h"

#include "../deps/itoa.h"
#include "../deps/parse_num.h"
#include "../deps/libc_time.h"
#include "../deps/dtoa.h"

#ifndef UA_ENABLE_PARSING
#error UA_ENABLE_PARSING required for XML encoding
#endif

#ifndef UA_ENABLE_TYPEDESCRIPTION
#error UA_ENABLE_TYPEDESCRIPTION required for XML encoding
#endif


#ifndef INFINITY
# define INFINITY ((UA_Double)(DBL_MAX+DBL_MAX))
#endif
#ifndef NAN
# define NAN ((UA_Double)(INFINITY-INFINITY))
#endif


#define UA_XML_DATETIME_LENGTH 40





#define ENCODE_XML(TYPE) static status \
    TYPE##_encodeXml(CtxXml *ctx, const UA_##TYPE *src, const UA_DataType *type)

static status UA_FUNC_ATTR_WARN_UNUSED_RESULT
xmlEncodeWriteChars(CtxXml *ctx, const char *c, size_t len) {
    if(ctx->pos + len > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(!ctx->calcOnly)
        memcpy(ctx->pos, c, len);
    ctx->pos += len;
    return UA_STATUSCODE_GOOD;
}


ENCODE_XML(Boolean) {
    if(*src == true)
        return xmlEncodeWriteChars(ctx, "true", 4);
    return xmlEncodeWriteChars(ctx, "false", 5);
}

static status encodeSigned(CtxXml *ctx, UA_Int64 value, char* buffer) {
    UA_UInt16 digits = itoaSigned(value, buffer);
    return xmlEncodeWriteChars(ctx, buffer, digits);
}

static status encodeUnsigned(CtxXml *ctx, UA_UInt64 value, char* buffer) {
    UA_UInt16 digits = itoaUnsigned(value, buffer, 10);
    return xmlEncodeWriteChars(ctx, buffer, digits);
}


ENCODE_XML(SByte) {
    char buf[5];
    return encodeSigned(ctx, *src, buf);
}


ENCODE_XML(Byte) {
    char buf[4];
    return encodeUnsigned(ctx, *src, buf);
}


ENCODE_XML(Int16) {
    char buf[7];
    return encodeSigned(ctx, *src, buf);
}


ENCODE_XML(UInt16) {
    char buf[6];
    return encodeUnsigned(ctx, *src, buf);
}


ENCODE_XML(Int32) {
    char buf[12];
    return encodeSigned(ctx, *src, buf);
}


ENCODE_XML(UInt32) {
    char buf[11];
    return encodeUnsigned(ctx, *src, buf);
}


ENCODE_XML(Int64) {
    char buf[23];
    return encodeSigned(ctx, *src, buf);
}


ENCODE_XML(UInt64) {
    char buf[23];
    return encodeUnsigned(ctx, *src, buf);
}


ENCODE_XML(Float) {
    char buffer[32];
    size_t len;
    if(*src != *src) {
        strcpy(buffer, "NaN");
        len = strlen(buffer);
    } else if(*src == INFINITY) {
        strcpy(buffer, "INF");
        len = strlen(buffer);
    } else if(*src == -INFINITY) {
        strcpy(buffer, "-INF");
        len = strlen(buffer);
    } else {
        len = dtoa((UA_Double)*src, buffer);
    }
    return xmlEncodeWriteChars(ctx, buffer, len);
}


ENCODE_XML(Double) {
    char buffer[32];
    size_t len;
    if(*src != *src) {
        strcpy(buffer, "NaN");
        len = strlen(buffer);
    } else if(*src == INFINITY) {
        strcpy(buffer, "INF");
        len = strlen(buffer);
    } else if(*src == -INFINITY) {
        strcpy(buffer, "-INF");
        len = strlen(buffer);
    } else {
        len = dtoa(*src, buffer);
    }
    return xmlEncodeWriteChars(ctx, buffer, len);
}


ENCODE_XML(String) {
    if(!src->data)
        return xmlEncodeWriteChars(ctx, "null", 4);
    return xmlEncodeWriteChars(ctx, (const char*)src->data, src->length);
}


ENCODE_XML(Guid) {
    if(ctx->pos + 36 > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(!ctx->calcOnly)
        UA_Guid_to_hex(src, ctx->pos, false);
    ctx->pos += 36;
    return UA_STATUSCODE_GOOD;
}


static u8
xmlEncodePrintNumber(i32 n, char *pos, u8 min_digits) {
    char digits[10];
    u8 len = 0;
    
    if(n < 0) {
        pos[len++] = '-';
        n = -n;
    }

    
    u8 i = 0;
    for(; i < min_digits || n > 0; i++) {
        digits[i] = (char)((n % 10) + '0');
        n /= 10;
    }

    
    for(; i > 0; i--)
        pos[len++] = digits[i-1];
    return len;
}

ENCODE_XML(DateTime) {
    UA_DateTimeStruct tSt = UA_DateTime_toStruct(*src);

    char buffer[UA_XML_DATETIME_LENGTH];
    char *pos = buffer;
    pos += xmlEncodePrintNumber(tSt.year, pos, 4);
    *(pos++) = '-';
    pos += xmlEncodePrintNumber(tSt.month, pos, 2);
    *(pos++) = '-';
    pos += xmlEncodePrintNumber(tSt.day, pos, 2);
    *(pos++) = 'T';
    pos += xmlEncodePrintNumber(tSt.hour, pos, 2);
    *(pos++) = ':';
    pos += xmlEncodePrintNumber(tSt.min, pos, 2);
    *(pos++) = ':';
    pos += xmlEncodePrintNumber(tSt.sec, pos, 2);
    *(pos++) = '.';
    pos += xmlEncodePrintNumber(tSt.milliSec, pos, 3);
    pos += xmlEncodePrintNumber(tSt.microSec, pos, 3);
    pos += xmlEncodePrintNumber(tSt.nanoSec, pos, 3);

    UA_assert(pos <= &buffer[UA_XML_DATETIME_LENGTH]);

    
    pos--;
    while(*pos == '0')
        pos--;
    if(*pos == '.')
        pos--;

    *(++pos) = 'Z';
    UA_String str = {((uintptr_t)pos - (uintptr_t)buffer)+1, (UA_Byte*)buffer};

    return xmlEncodeWriteChars(ctx, (const char*)str.data, str.length);
}


ENCODE_XML(NodeId) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    UA_String out = UA_STRING_NULL;

    ret |= UA_NodeId_print(src, &out);
    ret |= encodeXmlJumpTable[UA_DATATYPEKIND_STRING](ctx, &out, NULL);

    UA_String_clear(&out);
    return ret;
}


ENCODE_XML(ExpandedNodeId) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    UA_String out = UA_STRING_NULL;

    ret |= UA_ExpandedNodeId_print(src, &out);
    ret |= encodeXmlJumpTable[UA_DATATYPEKIND_STRING](ctx, &out, NULL);

    UA_String_clear(&out);
    return ret;
}

static status
encodeXmlNotImplemented(CtxXml *ctx, const void *src, const UA_DataType *type) {
    (void)ctx, (void)src, (void)type;
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

const encodeXmlSignature encodeXmlJumpTable[UA_DATATYPEKINDS] = {
    (encodeXmlSignature)Boolean_encodeXml,          
    (encodeXmlSignature)SByte_encodeXml,            
    (encodeXmlSignature)Byte_encodeXml,             
    (encodeXmlSignature)Int16_encodeXml,            
    (encodeXmlSignature)UInt16_encodeXml,           
    (encodeXmlSignature)Int32_encodeXml,            
    (encodeXmlSignature)UInt32_encodeXml,           
    (encodeXmlSignature)Int64_encodeXml,            
    (encodeXmlSignature)UInt64_encodeXml,           
    (encodeXmlSignature)Float_encodeXml,            
    (encodeXmlSignature)Double_encodeXml,           
    (encodeXmlSignature)String_encodeXml,           
    (encodeXmlSignature)DateTime_encodeXml,         
    (encodeXmlSignature)Guid_encodeXml,             
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)NodeId_encodeXml,           
    (encodeXmlSignature)ExpandedNodeId_encodeXml,   
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented,    
    (encodeXmlSignature)encodeXmlNotImplemented     
};

UA_StatusCode
UA_encodeXml(const void *src, const UA_DataType *type, UA_ByteString *outBuf,
             const UA_EncodeXmlOptions *options) {
    if(!src || !type)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    UA_Boolean allocated = false;
    status res = UA_STATUSCODE_GOOD;
    if(outBuf->length == 0) {
        size_t len = UA_calcSizeXml(src, type, options);
        res = UA_ByteString_allocBuffer(outBuf, len);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        allocated = true;
    }

    
    CtxXml ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pos = outBuf->data;
    ctx.end = &outBuf->data[outBuf->length];
    ctx.depth = 0;
    ctx.calcOnly = false;
    if(options)
        ctx.prettyPrint = options->prettyPrint;

    
    res = encodeXmlJumpTable[type->typeKind](&ctx, src, type);

    
    if(res == UA_STATUSCODE_GOOD)
        outBuf->length = (size_t)((uintptr_t)ctx.pos - (uintptr_t)outBuf->data);
    else if(allocated)
        UA_ByteString_clear(outBuf);
    return res;
}





size_t
UA_calcSizeXml(const void *src, const UA_DataType *type,
               const UA_EncodeXmlOptions *options) {
    if(!src || !type)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    CtxXml ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pos = NULL;
    ctx.end = (const UA_Byte*)(uintptr_t)SIZE_MAX;
    ctx.depth = 0;
    if(options) {
        ctx.prettyPrint = options->prettyPrint;
    }

    ctx.calcOnly = true;

    
    status ret = encodeXmlJumpTable[type->typeKind](&ctx, src, type);
    if(ret != UA_STATUSCODE_GOOD)
        return 0;
    return (size_t)ctx.pos;
}





#define CHECK_TOKEN_BOUNDS do {                   \
    if(ctx->index >= ctx->tokensSize)             \
        return UA_STATUSCODE_BADDECODINGERROR;    \
    } while(0)


#define DECODE_XML(TYPE) static status                   \
    TYPE##_decodeXml(ParseCtxXml *ctx, UA_##TYPE *dst,  \
                      const UA_DataType *type)

DECODE_XML(Boolean) {
    if(ctx->length == 4 &&
       ctx->data[0] == 't' && ctx->data[1] == 'r' &&
       ctx->data[2] == 'u' && ctx->data[3] == 'e') {
        *dst = true;
    } else if(ctx->length == 5 &&
              ctx->data[0] == 'f' && ctx->data[1] == 'a' &&
              ctx->data[2] == 'l' && ctx->data[3] == 's' &&
              ctx->data[4] == 'e') {
        *dst = false;
    } else {
        return UA_STATUSCODE_BADDECODINGERROR;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
decodeSigned(const char *data, size_t dataSize, UA_Int64 *dst) {
    size_t len = parseInt64(data, dataSize, dst);
    if(len == 0)
        return UA_STATUSCODE_BADDECODINGERROR;

    for(size_t i = len; i < dataSize; i++) {
        if(data[i] != ' ' && data[i] - '\t' >= 5)
            return UA_STATUSCODE_BADDECODINGERROR;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
decodeUnsigned(const char *data, size_t dataSize, UA_UInt64 *dst) {
    size_t len = parseUInt64(data, dataSize, dst);
    if(len == 0)
        return UA_STATUSCODE_BADDECODINGERROR;

    for(size_t i = len; i < dataSize; i++) {
        if(data[i] != ' ' && data[i] - '\t' >= 5)
            return UA_STATUSCODE_BADDECODINGERROR;
    }

    return UA_STATUSCODE_GOOD;
}

DECODE_XML(SByte) {
    UA_Int64 out = 0;
    UA_StatusCode s = decodeSigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD || out < UA_SBYTE_MIN || out > UA_SBYTE_MAX)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_SByte)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(Byte) {
    UA_UInt64 out = 0;
    UA_StatusCode s = decodeUnsigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD || out > UA_BYTE_MAX)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_Byte)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(Int16) {
    UA_Int64 out = 0;
    UA_StatusCode s = decodeSigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD || out < UA_INT16_MIN || out > UA_INT16_MAX)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_Int16)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(UInt16) {
    UA_UInt64 out = 0;
    UA_StatusCode s = decodeUnsigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD || out > UA_UINT16_MAX)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_UInt16)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(Int32) {
    UA_Int64 out = 0;
    UA_StatusCode s = decodeSigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD || out < UA_INT32_MIN || out > UA_INT32_MAX)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_Int32)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(UInt32) {
    UA_UInt64 out = 0;
    UA_StatusCode s = decodeUnsigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD || out > UA_UINT32_MAX)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_UInt32)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(Int64) {
    UA_Int64 out = 0;
    UA_StatusCode s = decodeSigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_Int64)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(UInt64) {
    UA_UInt64 out = 0;
    UA_StatusCode s = decodeUnsigned(ctx->data, ctx->length, &out);

    if(s != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = (UA_UInt64)out;
    return UA_STATUSCODE_GOOD;
}

DECODE_XML(Double) {

    if(ctx->length > 1075)
        return UA_STATUSCODE_BADDECODINGERROR;

    if(ctx->length == 3 && memcmp(ctx->data, "INF", 3) == 0) {
        *dst = INFINITY;
        return UA_STATUSCODE_GOOD;
    }

    if(ctx->length == 4 && memcmp(ctx->data, "-INF", 4) == 0) {
        *dst = -INFINITY;
        return UA_STATUSCODE_GOOD;
    }

    if(ctx->length == 3 && memcmp(ctx->data, "NaN", 3) == 0) {
        *dst = NAN;
        return UA_STATUSCODE_GOOD;
    }

    size_t len = parseDouble(ctx->data, ctx->length, dst);
    if(len == 0)
        return UA_STATUSCODE_BADDECODINGERROR;

    for(size_t i = len; i < ctx->length; i++) {
        if(ctx->data[i] != ' ' && ctx->data[i] -'\t' >= 5)
            return UA_STATUSCODE_BADDECODINGERROR;
    }

    return UA_STATUSCODE_GOOD;
}

DECODE_XML(Float) {
    UA_Double v = 0.0;
    UA_StatusCode res = Double_decodeXml(ctx, &v, NULL);
    *dst = (UA_Float)v;
    return res;
}

DECODE_XML(String) {
    
    if(ctx->length == 0) {
        dst->data = (UA_Byte*)UA_EMPTY_ARRAY_SENTINEL;
        dst->length = 0;
        return UA_STATUSCODE_GOOD;
    }

    
    dst->length = ctx->length;
    if(dst->length > 0) {
        dst->data = (UA_Byte*)(uintptr_t)ctx->data;
    } else {
        dst->data = (UA_Byte*)UA_EMPTY_ARRAY_SENTINEL;
    }

    return UA_STATUSCODE_GOOD;
}

DECODE_XML(DateTime) {
    if(ctx->length == 0 || ctx->data[ctx->length - 1] != 'Z')
        return UA_STATUSCODE_BADDECODINGERROR;

    struct mytm dts;
    memset(&dts, 0, sizeof(dts));

    size_t pos = 0;
    size_t len;

    if(ctx->data[0] == '-' || ctx->data[0] == '+')
        pos++;
    UA_Int64 year = 0;
    len = parseInt64(&ctx->data[pos], 5, &year);
    pos += len;
    if(len != 4 && ctx->data[pos] != '-')
        return UA_STATUSCODE_BADDECODINGERROR;
    if(ctx->data[0] == '-')
        year = -year;
    dts.tm_year = (UA_Int16)year - 1900;
    if(ctx->data[pos] == '-')
        pos++;

    
    UA_UInt64 month = 0;
    len = parseUInt64(&ctx->data[pos], 2, &month);
    pos += len;
    UA_CHECK(len == 2, return UA_STATUSCODE_BADDECODINGERROR);
    dts.tm_mon = (UA_UInt16)month - 1;
    if(ctx->data[pos] == '-')
        pos++;

    
    UA_UInt64 day = 0;
    len = parseUInt64(&ctx->data[pos], 2, &day);
    pos += len;
    UA_CHECK(len == 2 || ctx->data[pos] != 'T',
             return UA_STATUSCODE_BADDECODINGERROR);
    dts.tm_mday = (UA_UInt16)day;
    pos++;

    
    UA_UInt64 hour = 0;
    len = parseUInt64(&ctx->data[pos], 2, &hour);
    pos += len;
    UA_CHECK(len == 2, return UA_STATUSCODE_BADDECODINGERROR);
    dts.tm_hour = (UA_UInt16)hour;
    if(ctx->data[pos] == ':')
        pos++;

    
    UA_UInt64 min = 0;
    len = parseUInt64(&ctx->data[pos], 2, &min);
    pos += len;
    UA_CHECK(len == 2, return UA_STATUSCODE_BADDECODINGERROR);
    dts.tm_min = (UA_UInt16)min;
    if(ctx->data[pos] == ':')
        pos++;

    
    UA_UInt64 sec = 0;
    len = parseUInt64(&ctx->data[pos], 2, &sec);
    pos += len;
    UA_CHECK(len == 2, return UA_STATUSCODE_BADDECODINGERROR);
    dts.tm_sec = (UA_UInt16)sec;

    
    long long sinceunix = __tm_to_secs(&dts);

    
    long long sinceunix_min =
        (long long)(UA_INT64_MIN / UA_DATETIME_SEC) -
        (long long)(UA_DATETIME_UNIX_EPOCH / UA_DATETIME_SEC) -
        (long long)1; 
    long long sinceunix_max = (long long)
        ((UA_INT64_MAX - UA_DATETIME_UNIX_EPOCH) / UA_DATETIME_SEC);
    if(sinceunix < sinceunix_min || sinceunix > sinceunix_max)
        return UA_STATUSCODE_BADDECODINGERROR;

    sinceunix -= (sinceunix > 0) ? 1 : -1;
    UA_DateTime dt = (UA_DateTime)
        (sinceunix + (UA_DATETIME_UNIX_EPOCH / UA_DATETIME_SEC)) * UA_DATETIME_SEC;

    
    if(ctx->data[pos] == ',' || ctx->data[pos] == '.') {
        pos++;
        double frac = 0.0;
        double denom = 0.1;
        while(pos < ctx->length && ctx->data[pos] >= '0' && ctx->data[pos] <= '9') {
            frac += denom * (ctx->data[pos] - '0');
            denom *= 0.1;
            pos++;
        }
        frac += 0.00000005; 
        dt += (UA_DateTime)(frac * UA_DATETIME_SEC);
    }

    
    if(sinceunix > 0) {
        if(dt > UA_INT64_MAX - UA_DATETIME_SEC)
            return UA_STATUSCODE_BADDECODINGERROR;
        dt += UA_DATETIME_SEC;
    } else {
        if(dt < UA_INT64_MIN + UA_DATETIME_SEC)
            return UA_STATUSCODE_BADDECODINGERROR;
        dt -= UA_DATETIME_SEC;
    }

    
    if(pos != ctx->length - 1)
        return UA_STATUSCODE_BADDECODINGERROR;

    *dst = dt;

    return UA_STATUSCODE_GOOD;
}

DECODE_XML(Guid) {
    UA_String str = {ctx->length, (UA_Byte*)(uintptr_t)ctx->data};
    return UA_Guid_parse(dst, str);
}

DECODE_XML(NodeId) {
    UA_String str = {ctx->length, (UA_Byte*)(uintptr_t)ctx->data};
    return UA_NodeId_parse(dst, str);
}

DECODE_XML(ExpandedNodeId) {
    UA_String str = {ctx->length, (UA_Byte*)(uintptr_t)ctx->data};
    return UA_ExpandedNodeId_parse(dst, str);
}

static status
decodeXmlNotImplemented(ParseCtxXml *ctx, void *dst, const UA_DataType *type) {
    (void)dst, (void)type, (void)ctx;
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

const decodeXmlSignature decodeXmlJumpTable[UA_DATATYPEKINDS] = {
    (decodeXmlSignature)Boolean_decodeXml,          
    (decodeXmlSignature)SByte_decodeXml,            
    (decodeXmlSignature)Byte_decodeXml,             
    (decodeXmlSignature)Int16_decodeXml,            
    (decodeXmlSignature)UInt16_decodeXml,           
    (decodeXmlSignature)Int32_decodeXml,            
    (decodeXmlSignature)UInt32_decodeXml,           
    (decodeXmlSignature)Int64_decodeXml,            
    (decodeXmlSignature)UInt64_decodeXml,           
    (decodeXmlSignature)Float_decodeXml,            
    (decodeXmlSignature)Double_decodeXml,           
    (decodeXmlSignature)String_decodeXml,           
    (decodeXmlSignature)DateTime_decodeXml,         
    (decodeXmlSignature)Guid_decodeXml,             
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)NodeId_decodeXml,           
    (decodeXmlSignature)ExpandedNodeId_decodeXml,   
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented,    
    (decodeXmlSignature)decodeXmlNotImplemented     
};

UA_StatusCode
UA_decodeXml(const UA_ByteString *src, void *dst, const UA_DataType *type,
              const UA_DecodeXmlOptions *options) {
    if(!dst || !src || !type)
        return UA_STATUSCODE_BADARGUMENTSMISSING;

    
    ParseCtxXml ctx;
    memset(&ctx, 0, sizeof(ParseCtxXml));
    ctx.data = (const char*)src->data;
    ctx.length = src->length;
    ctx.depth = 0;
    if(options) {
        ctx.customTypes = options->customTypes;
    }

    
    memset(dst, 0, type->memSize); 
    status ret = decodeXmlJumpTable[type->typeKind](&ctx, dst, type);

    if(ret != UA_STATUSCODE_GOOD) {
        UA_clear(dst, type);
        memset(dst, 0, type->memSize);
    }
    return ret;
}
