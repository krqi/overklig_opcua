
#include <opcua/types.h>
#include <opcua/types_generated.h>

#include "util/ua_util_internal.h"
#include "../deps/itoa.h"
#include "../deps/base64.h"
#include "libc_time.h"

#define UA_MAX_ARRAY_DIMS 100 


const UA_String UA_STRING_NULL = {0, NULL};
const UA_ByteString UA_BYTESTRING_NULL = {0, NULL};
const UA_Guid UA_GUID_NULL = {0, 0, 0, {0,0,0,0,0,0,0,0}};
const UA_NodeId UA_NODEID_NULL = {0, UA_NODEIDTYPE_NUMERIC, {0}};
const UA_ExpandedNodeId UA_EXPANDEDNODEID_NULL = {{0, UA_NODEIDTYPE_NUMERIC, {0}}, {0, NULL}, 0};

typedef UA_StatusCode
(*UA_copySignature)(const void *src, void *dst, const UA_DataType *type);
extern const UA_copySignature copyJumpTable[UA_DATATYPEKINDS];

typedef void (*UA_clearSignature)(void *p, const UA_DataType *type);
extern const UA_clearSignature clearJumpTable[UA_DATATYPEKINDS];

typedef UA_Order
(*UA_orderSignature)(const void *p1, const void *p2, const UA_DataType *type);
extern const UA_orderSignature orderJumpTable[UA_DATATYPEKINDS];

static UA_Order
nodeIdOrder(const UA_NodeId *p1, const UA_NodeId *p2, const UA_DataType *_);
static UA_Order
expandedNodeIdOrder(const UA_ExpandedNodeId *p1, const UA_ExpandedNodeId *p2,
                    const UA_DataType *_);
static UA_Order
guidOrder(const UA_Guid *p1, const UA_Guid *p2, const UA_DataType *_);

const UA_DataType *
UA_findDataTypeWithCustom(const UA_NodeId *typeId,
                          const UA_DataTypeArray *customTypes) {
    for(size_t i = 0; i < UA_TYPES_COUNT; ++i) {
        if(nodeIdOrder(&UA_TYPES[i].typeId, typeId, NULL) == UA_ORDER_EQ)
            return &UA_TYPES[i];
    }

    
    while(customTypes) {
        for(size_t i = 0; i < customTypes->typesSize; ++i) {
            if(nodeIdOrder(&customTypes->types[i].typeId, typeId, NULL) == UA_ORDER_EQ)
                return &customTypes->types[i];
        }
        customTypes = customTypes->next;
    }

    return NULL;
}

const UA_DataType *
UA_findDataType(const UA_NodeId *typeId) {
    return UA_findDataTypeWithCustom(typeId, NULL);
}

void
UA_cleanupDataTypeWithCustom(const UA_DataTypeArray *customTypes) {
    while (customTypes) {
        const UA_DataTypeArray *next = customTypes->next;
        if (customTypes->cleanup) {
            for(size_t i = 0; i < customTypes->typesSize; ++i) {
                const UA_DataType *type = &customTypes->types[i];
#ifdef UA_ENABLE_TYPEDESCRIPTION
                UA_free((void*)(uintptr_t)type->typeName);
                for(size_t j = 0; j < type->membersSize; ++j) {
                    const UA_DataTypeMember *m = &type->members[j];
                    UA_free((void*)(uintptr_t)m->memberName);
                }
#endif
                UA_free((void*)type->members);
            }
            UA_free((void*)(uintptr_t)customTypes->types);
            UA_free((void*)(uintptr_t)customTypes);
        }
        customTypes = next;
    }
}





UA_String
UA_String_fromChars(const char *src) {
    UA_String s; s.length = 0; s.data = NULL;
    if(!src)
        return s;
    s.length = strlen(src);
    if(s.length > 0) {
        s.data = (u8*)UA_malloc(s.length);
        if(UA_UNLIKELY(!s.data)) {
            s.length = 0;
            return s;
        }
        memcpy(s.data, src, s.length);
    } else {
        s.data = (u8*)UA_EMPTY_ARRAY_SENTINEL;
    }
    return s;
}

UA_Boolean
UA_String_isEmpty(const UA_String *s) {
    return (s->length == 0 || s->data == NULL);
}

static UA_Byte
lowercase(UA_Byte c) {
	if(((int)c) - 'A' < 26) return c | 32;
	return c;
}

static int
casecmp(const UA_Byte *l, const UA_Byte *r, size_t n) {
	if(!n--) return 0;
	for(; *l && *r && n && (*l == *r || lowercase(*l) == lowercase(*r)); l++, r++, n--);
	return lowercase(*l) - lowercase(*r);
}

UA_Boolean
UA_String_equal_ignorecase(const UA_String *s1, const UA_String *s2) {
    if(s1->length != s2->length)
        return false;
    if(s1->length == 0)
        return true;
    if(s2->data == NULL)
        return false;

    return casecmp(s1->data, s2->data, s1->length) == 0;
}

static UA_StatusCode
String_copy(UA_String const *src, UA_String *dst, const UA_DataType *_) {
    UA_StatusCode res =
        UA_Array_copy(src->data, src->length, (void**)&dst->data,
                      &UA_TYPES[UA_TYPES_BYTE]);
    if(res == UA_STATUSCODE_GOOD)
        dst->length = src->length;
    return res;
}

static void
String_clear(UA_String *s, const UA_DataType *_) {
    UA_Array_delete(s->data, s->length, &UA_TYPES[UA_TYPES_BYTE]);
}


static UA_StatusCode
QualifiedName_copy(const UA_QualifiedName *src, UA_QualifiedName *dst,
                   const UA_DataType *_) {
    dst->namespaceIndex = src->namespaceIndex;
    return String_copy(&src->name, &dst->name, NULL);
}

static void
QualifiedName_clear(UA_QualifiedName *p, const UA_DataType *_) {
    String_clear(&p->name, NULL);
}

u32
UA_QualifiedName_hash(const UA_QualifiedName *q) {
    return UA_ByteString_hash(q->namespaceIndex,
                              q->name.data, q->name.length);
}


UA_DateTimeStruct
UA_DateTime_toStruct(UA_DateTime t) {
    long long secSinceUnixEpoch = (long long)(t / UA_DATETIME_SEC)
        - (long long)(UA_DATETIME_UNIX_EPOCH / UA_DATETIME_SEC);

    UA_DateTime frac = t % UA_DATETIME_SEC;
    if(frac < 0) {
        secSinceUnixEpoch--;
        frac += UA_DATETIME_SEC;
    }

    struct mytm ts;
    memset(&ts, 0, sizeof(struct mytm));
    __secs_to_tm(secSinceUnixEpoch, &ts);

    UA_DateTimeStruct dateTimeStruct;
    dateTimeStruct.year   = (i16)(ts.tm_year + 1900);
    dateTimeStruct.month  = (u16)(ts.tm_mon + 1);
    dateTimeStruct.day    = (u16)ts.tm_mday;
    dateTimeStruct.hour   = (u16)ts.tm_hour;
    dateTimeStruct.min    = (u16)ts.tm_min;
    dateTimeStruct.sec    = (u16)ts.tm_sec;
    dateTimeStruct.milliSec = (u16)((frac % 10000000) / 10000);
    dateTimeStruct.microSec = (u16)((frac % 10000) / 10);
    dateTimeStruct.nanoSec  = (u16)((frac % 10) * 100);
    return dateTimeStruct;
}

UA_DateTime
UA_DateTime_fromStruct(UA_DateTimeStruct ts) {
    
    struct mytm tm;
    memset(&tm, 0, sizeof(struct mytm));
    tm.tm_year = ts.year - 1900;
    tm.tm_mon = ts.month - 1;
    tm.tm_mday = ts.day;
    tm.tm_hour = ts.hour;
    tm.tm_min = ts.min;
    tm.tm_sec = ts.sec;
    long long sec_epoch = __tm_to_secs(&tm);

    UA_DateTime t = UA_DATETIME_UNIX_EPOCH;
    t += sec_epoch * UA_DATETIME_SEC;
    t += ts.milliSec * UA_DATETIME_MSEC;
    t += ts.microSec * UA_DATETIME_USEC;
    t += ts.nanoSec / 100;
    return t;
}


static const u8 hexmapLower[16] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static const u8 hexmapUpper[16] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void
UA_Guid_to_hex(const UA_Guid *guid, u8* out, UA_Boolean lower) {
    const u8 *hexmap = (lower) ? hexmapLower : hexmapUpper;
    size_t i = 0, j = 28;
    for(; i<8;i++,j-=4)         
        out[i] = hexmap[(guid->data1 >> j) & 0x0Fu];
    out[i++] = '-';             
    for(j=12; i<13;i++,j-=4)    
        out[i] = hexmap[(uint16_t)(guid->data2 >> j) & 0x0Fu];
    out[i++] = '-';             
    for(j=12; i<18;i++,j-=4)    
        out[i] = hexmap[(uint16_t)(guid->data3 >> j) & 0x0Fu];
    out[i++] = '-';              
    for(j=0;i<23;i+=2,j++) {     
        out[i] = hexmap[(guid->data4[j] & 0xF0u) >> 4u];
        out[i+1] = hexmap[guid->data4[j] & 0x0Fu];
    }
    out[i++] = '-';              
    for(j=2; i<36;i+=2,j++) {    
        out[i] = hexmap[(guid->data4[j] & 0xF0u) >> 4u];
        out[i+1] = hexmap[guid->data4[j] & 0x0Fu];
    }
}

UA_StatusCode
UA_Guid_print(const UA_Guid *guid, UA_String *output) {
    if(output->length == 0) {
        UA_StatusCode res =
            UA_ByteString_allocBuffer((UA_ByteString*)output, 36);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    } else {
        if(output->length < 36)
            return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        output->length = 36;
    }
    UA_Guid_to_hex(guid, output->data, true);
    return UA_STATUSCODE_GOOD;
}


UA_StatusCode
UA_ByteString_allocBuffer(UA_ByteString *bs, size_t length) {
    UA_ByteString_init(bs);
    if(length == 0)
        return UA_STATUSCODE_GOOD;
    bs->data = (u8*)UA_malloc(length);
    if(UA_UNLIKELY(!bs->data))
        return UA_STATUSCODE_BADOUTOFMEMORY;
    bs->length = length;
    return UA_STATUSCODE_GOOD;
}


static void
NodeId_clear(UA_NodeId *p, const UA_DataType *_) {
    switch(p->identifierType) {
    case UA_NODEIDTYPE_STRING:
    case UA_NODEIDTYPE_BYTESTRING:
        String_clear(&p->identifier.string, NULL);
        break;
    default: break;
    }
}

static UA_StatusCode
NodeId_copy(UA_NodeId const *src, UA_NodeId *dst, const UA_DataType *_) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    switch(src->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
        *dst = *src;
        return UA_STATUSCODE_GOOD;
    case UA_NODEIDTYPE_STRING:
    case UA_NODEIDTYPE_BYTESTRING:
        retval |= String_copy(&src->identifier.string,
                              &dst->identifier.string, NULL);
        break;
    case UA_NODEIDTYPE_GUID:
        dst->identifier.guid = src->identifier.guid;
        break;
    default:
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    dst->namespaceIndex = src->namespaceIndex;
    dst->identifierType = src->identifierType;
    return retval;
}

UA_Boolean
UA_NodeId_isNull(const UA_NodeId *p) {
    if(p->namespaceIndex != 0)
        return false;
    switch (p->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
        return (p->identifier.numeric == 0);
    case UA_NODEIDTYPE_STRING:
    case UA_NODEIDTYPE_BYTESTRING:
        return (p->identifier.string.length == 0); 
    case UA_NODEIDTYPE_GUID:
        return (guidOrder(&p->identifier.guid, &UA_GUID_NULL, NULL) == UA_ORDER_EQ);
    }
    return false;
}

UA_Order
UA_NodeId_order(const UA_NodeId *n1, const UA_NodeId *n2) {
    return nodeIdOrder(n1, n2, NULL);
}


u32
UA_ByteString_hash(u32 initialHashValue,
                   const u8 *data, size_t size) {
    u32 h = initialHashValue;
    for(size_t i = 0; i < size; i++)
        h = data[i] + (h << 6) + (h << 16) - h;
    return h;
}

u32
UA_NodeId_hash(const UA_NodeId *n) {
    switch(n->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
    default:
        return UA_ByteString_hash(n->namespaceIndex, (const u8*)&n->identifier.numeric,
                                  sizeof(UA_UInt32));
    case UA_NODEIDTYPE_STRING:
    case UA_NODEIDTYPE_BYTESTRING:
        return UA_ByteString_hash(n->namespaceIndex, n->identifier.string.data,
                                  n->identifier.string.length);
    case UA_NODEIDTYPE_GUID:
        return UA_ByteString_hash(n->namespaceIndex, (const u8*)&n->identifier.guid,
                                  sizeof(UA_Guid));
    }
}


static size_t
nodeIdSize(const UA_NodeId *id,
           char *nsStr, size_t *nsStrSize,
           char *numIdStr, size_t *numIdStrSize) {
    
    size_t len = 0;
    if(id->namespaceIndex != 0) {
        len += 4; 
        *nsStrSize = itoaUnsigned(id->namespaceIndex, nsStr, 10);
        len += *nsStrSize;
    }

    switch (id->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
        *numIdStrSize = itoaUnsigned(id->identifier.numeric, numIdStr, 10);
        len += 2 + *numIdStrSize;
        break;
    case UA_NODEIDTYPE_STRING:
        len += 2 + id->identifier.string.length;
        break;
    case UA_NODEIDTYPE_GUID:
        len += 2 + 36;
        break;
    case UA_NODEIDTYPE_BYTESTRING:
        len += 2 + (4*((id->identifier.byteString.length + 2) / 3));
        break;
    default:
        len = 0;
    }
    return len;
}

#define PRINT_NODEID                                           \
                                     \
    if(id->namespaceIndex != 0) {                              \
        memcpy(pos, "ns=", 3);                                 \
        pos += 3;                                              \
        memcpy(pos, nsStr, nsStrSize);                         \
        pos += nsStrSize;                                      \
        *pos++ = ';';                                          \
    }                                                          \
                                                               \
                                    \
    switch(id->identifierType) {                               \
    case UA_NODEIDTYPE_NUMERIC:                                \
        memcpy(pos, "i=", 2);                                  \
        pos += 2;                                              \
        memcpy(pos, numIdStr, numIdStrSize);                   \
        pos += numIdStrSize;                                   \
        break;                                                 \
    case UA_NODEIDTYPE_STRING:                                 \
        memcpy(pos, "s=", 2);                                  \
        pos += 2;                                              \
        memcpy(pos, id->identifier.string.data,                \
               id->identifier.string.length);                  \
        pos += id->identifier.string.length;                   \
        break;                                                 \
    case UA_NODEIDTYPE_GUID:                                   \
        memcpy(pos, "g=", 2);                                  \
        pos += 2;                                              \
        UA_Guid_to_hex(&id->identifier.guid,                   \
                       (unsigned char*)pos, true);             \
        pos += 36;                                             \
        break;                                                 \
    case UA_NODEIDTYPE_BYTESTRING:                             \
        memcpy(pos, "b=", 2);                                  \
        pos += 2;                                              \
        pos += UA_base64_buf(id->identifier.byteString.data,   \
                             id->identifier.byteString.length, \
                             (unsigned char*)pos);             \
        break;                                                 \
    }                                                          \
    do { } while(false)

UA_StatusCode
UA_NodeId_print(const UA_NodeId *id, UA_String *output) {
    
    char nsStr[6];
    size_t nsStrSize = 0;
    char numIdStr[11];
    size_t numIdStrSize = 0;
    size_t idLen = nodeIdSize(id, nsStr, &nsStrSize, numIdStr, &numIdStrSize);
    if(idLen == 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    if(output->length == 0) {
        UA_StatusCode res = UA_ByteString_allocBuffer((UA_ByteString*)output, idLen);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    } else {
        if(output->length < idLen)
            return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        output->length = idLen;
    }

    
    char *pos = (char*)output->data;
    PRINT_NODEID;

    UA_assert(output->length == (size_t)((UA_Byte*)pos - output->data));
    return UA_STATUSCODE_GOOD;
}


static void
ExpandedNodeId_clear(UA_ExpandedNodeId *p, const UA_DataType *_) {
    NodeId_clear(&p->nodeId, _);
    String_clear(&p->namespaceUri, NULL);
}

static UA_StatusCode
ExpandedNodeId_copy(UA_ExpandedNodeId const *src, UA_ExpandedNodeId *dst,
                    const UA_DataType *_) {
    UA_StatusCode retval = NodeId_copy(&src->nodeId, &dst->nodeId, NULL);
    retval |= String_copy(&src->namespaceUri, &dst->namespaceUri, NULL);
    dst->serverIndex = src->serverIndex;
    return retval;
}

UA_Boolean
UA_ExpandedNodeId_isLocal(const UA_ExpandedNodeId *n) {
    return (n->namespaceUri.length == 0 && n->serverIndex == 0);
}

UA_Order
UA_ExpandedNodeId_order(const UA_ExpandedNodeId *n1,
                        const UA_ExpandedNodeId *n2) {
    return expandedNodeIdOrder(n1, n2, NULL);
}

u32
UA_ExpandedNodeId_hash(const UA_ExpandedNodeId *n) {
    u32 h = UA_NodeId_hash(&n->nodeId);
    if(n->serverIndex != 0)
        h = UA_ByteString_hash(h, (const UA_Byte*)&n->serverIndex, 4);
    if(n->namespaceUri.length != 0)
        h = UA_ByteString_hash(h, n->namespaceUri.data, n->namespaceUri.length);
    return h;
}

UA_StatusCode
UA_ExpandedNodeId_print(const UA_ExpandedNodeId *eid, UA_String *output) {
    
    UA_NodeId stackid = eid->nodeId;
    UA_NodeId *id = &stackid; 
    if(eid->namespaceUri.data != NULL)
        id->namespaceIndex = 0;

    
    char nsStr[6];
    size_t nsStrSize = 0;
    char numIdStr[11];
    size_t numIdStrSize = 0;
    size_t idLen = nodeIdSize(id, nsStr, &nsStrSize, numIdStr, &numIdStrSize);
    if(idLen == 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    char srvIdxStr[11];
    size_t srvIdxSize = 0;
    if(eid->serverIndex != 0) {
        idLen += 5; 
        srvIdxSize = itoaUnsigned(eid->serverIndex, srvIdxStr, 10);
        idLen += srvIdxSize;
    }

    if(eid->namespaceUri.data != NULL) {
        idLen += 5; 
        idLen += eid->namespaceUri.length;
    }

    
    if(output->length == 0) {
        UA_StatusCode res = UA_ByteString_allocBuffer((UA_ByteString*)output, idLen);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    } else {
        if(output->length < idLen)
            return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        output->length = idLen;
    }

    
    char *pos = (char*)output->data;
    if(eid->serverIndex != 0) {
        memcpy(pos, "svr=", 4);
        pos += 4;
        memcpy(pos, srvIdxStr, srvIdxSize);
        pos += srvIdxSize;
        *pos++ = ';';
    }

    
    if(eid->namespaceUri.data != NULL) {
        memcpy(pos, "nsu=", 4);
        pos += 4;
        memcpy(pos, eid->namespaceUri.data, eid->namespaceUri.length);
        pos += eid->namespaceUri.length;
        *pos++ = ';';
    }

    
    PRINT_NODEID;

    UA_assert(output->length == (size_t)((UA_Byte*)pos - output->data));
    return UA_STATUSCODE_GOOD;
}


static void
ExtensionObject_clear(UA_ExtensionObject *p, const UA_DataType *_) {
    switch(p->encoding) {
    case UA_EXTENSIONOBJECT_ENCODED_NOBODY:
    case UA_EXTENSIONOBJECT_ENCODED_BYTESTRING:
    case UA_EXTENSIONOBJECT_ENCODED_XML:
        NodeId_clear(&p->content.encoded.typeId, NULL);
        String_clear(&p->content.encoded.body, NULL);
        break;
    case UA_EXTENSIONOBJECT_DECODED:
        if(p->content.decoded.data)
            UA_delete(p->content.decoded.data, p->content.decoded.type);
        break;
    default:
        break;
    }
}

static UA_StatusCode
ExtensionObject_copy(UA_ExtensionObject const *src, UA_ExtensionObject *dst,
                     const UA_DataType *_) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    switch(src->encoding) {
    case UA_EXTENSIONOBJECT_ENCODED_NOBODY:
    case UA_EXTENSIONOBJECT_ENCODED_BYTESTRING:
    case UA_EXTENSIONOBJECT_ENCODED_XML:
        dst->encoding = src->encoding;
        retval = NodeId_copy(&src->content.encoded.typeId,
                             &dst->content.encoded.typeId, NULL);
        
        retval |= String_copy(&src->content.encoded.body,
                              &dst->content.encoded.body, NULL);
        break;
    case UA_EXTENSIONOBJECT_DECODED:
    case UA_EXTENSIONOBJECT_DECODED_NODELETE:
        if(!src->content.decoded.type || !src->content.decoded.data)
            return UA_STATUSCODE_BADINTERNALERROR;
        dst->encoding = UA_EXTENSIONOBJECT_DECODED;
        dst->content.decoded.type = src->content.decoded.type;
        retval = UA_Array_copy(src->content.decoded.data, 1,
            &dst->content.decoded.data, src->content.decoded.type);
        break;
    default:
        break;
    }
    return retval;
}

void
UA_ExtensionObject_setValue(UA_ExtensionObject *eo,
                            void * UA_RESTRICT p,
                            const UA_DataType *type) {
    UA_ExtensionObject_init(eo);
    eo->content.decoded.data = p;
    eo->content.decoded.type = type;
    eo->encoding = UA_EXTENSIONOBJECT_DECODED;
}

void
UA_ExtensionObject_setValueNoDelete(UA_ExtensionObject *eo,
                                    void * UA_RESTRICT p,
                                    const UA_DataType *type) {
    UA_ExtensionObject_init(eo);
    eo->content.decoded.data = p;
    eo->content.decoded.type = type;
    eo->encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
}

UA_StatusCode
UA_ExtensionObject_setValueCopy(UA_ExtensionObject *eo,
                                void * UA_RESTRICT p,
                                const UA_DataType *type) {
    UA_ExtensionObject_init(eo);

    
    void *val = UA_malloc(type->memSize);
    if(UA_UNLIKELY(!val))
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_copy(p, val, type);
    if(UA_UNLIKELY(res != UA_STATUSCODE_GOOD)) {
        UA_free(val);
        return res;
    }

    
    eo->content.decoded.data = val;
    eo->content.decoded.type = type;
    eo->encoding = UA_EXTENSIONOBJECT_DECODED;
    return UA_STATUSCODE_GOOD;
}


static void
Variant_clear(UA_Variant *p, const UA_DataType *_) {
    
    if(p->storageType == UA_VARIANT_DATA_NODELETE)
        return;

    
    if(p->type && p->data > UA_EMPTY_ARRAY_SENTINEL) {
        if(p->arrayLength == 0)
            p->arrayLength = 1;
        UA_Array_delete(p->data, p->arrayLength, p->type);
        p->data = NULL;
    }

    
    if((void*)p->arrayDimensions > UA_EMPTY_ARRAY_SENTINEL)
        UA_free(p->arrayDimensions);
}

static UA_StatusCode
Variant_copy(UA_Variant const *src, UA_Variant *dst, const UA_DataType *_) {
    size_t length = src->arrayLength;
    if(UA_Variant_isScalar(src))
        length = 1;
    UA_StatusCode retval = UA_Array_copy(src->data, length,
                                         &dst->data, src->type);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    dst->arrayLength = src->arrayLength;
    dst->type = src->type;
    if(src->arrayDimensions) {
        retval = UA_Array_copy(src->arrayDimensions, src->arrayDimensionsSize,
            (void**)&dst->arrayDimensions, &UA_TYPES[UA_TYPES_INT32]);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        dst->arrayDimensionsSize = src->arrayDimensionsSize;
    }
    return UA_STATUSCODE_GOOD;
}

void
UA_Variant_setScalar(UA_Variant *v, void * UA_RESTRICT p,
                     const UA_DataType *type) {
    UA_Variant_init(v);
    v->type = type;
    v->arrayLength = 0;
    v->data = p;
}

UA_StatusCode
UA_Variant_setScalarCopy(UA_Variant *v, const void * UA_RESTRICT p,
                         const UA_DataType *type) {
    void *n = UA_malloc(type->memSize);
    if(UA_UNLIKELY(!n))
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode retval = UA_copy(p, n, type);
    if(UA_UNLIKELY(retval != UA_STATUSCODE_GOOD)) {
        UA_free(n);
        //cppcheck-suppress memleak
        return retval;
    }
    UA_Variant_setScalar(v, n, type);
    //cppcheck-suppress memleak
    return UA_STATUSCODE_GOOD;
}

void UA_Variant_setArray(UA_Variant *v, void * UA_RESTRICT array,
                         size_t arraySize, const UA_DataType *type) {
    UA_Variant_init(v);
    v->data = array;
    v->arrayLength = arraySize;
    v->type = type;
}

UA_StatusCode
UA_Variant_setArrayCopy(UA_Variant *v, const void * UA_RESTRICT array,
                        size_t arraySize, const UA_DataType *type) {
    UA_Variant_init(v);
    UA_StatusCode retval = UA_Array_copy(array, arraySize, &v->data, type);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    v->arrayLength = arraySize;
    v->type = type;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
checkAdjustRange(const UA_Variant *v, UA_NumericRange *range) {
    
#if (SIZE_MAX > 0xffffffff)
    if(v->arrayLength > UA_UINT32_MAX)
        return UA_STATUSCODE_BADINTERNALERROR;
#endif
    u32 arrayLength = (u32)v->arrayLength;

    
    const u32 *dims = v->arrayDimensions;
    size_t dims_count = v->arrayDimensionsSize;
    if(v->arrayDimensionsSize == 0) {
        dims_count = 1;
        dims = &arrayLength;
    }

    
    if(range->dimensionsSize != dims_count)
        return UA_STATUSCODE_BADINDEXRANGENODATA;

    size_t elements = 1;
    for(size_t i = 0; i < dims_count; ++i)
        elements *= dims[i];
    if(elements != v->arrayLength)
        return UA_STATUSCODE_BADINTERNALERROR;

    for(size_t i = 0; i < dims_count; ++i) {
        if(range->dimensions[i].min > range->dimensions[i].max)
            return UA_STATUSCODE_BADINDEXRANGEINVALID;
        if(range->dimensions[i].min >= dims[i])
            return UA_STATUSCODE_BADINDEXRANGENODATA;

        
        if(range->dimensions[i].max >= dims[i])
            range->dimensions[i].max = dims[i] - 1;
    }

    return UA_STATUSCODE_GOOD;
}

static void
computeStrides(const UA_Variant *v, const UA_NumericRange range,
               size_t *total, size_t *block, size_t *stride, size_t *first) {
    
    size_t count = 1;
    for(size_t i = 0; i < range.dimensionsSize; ++i)
        count *= (range.dimensions[i].max - range.dimensions[i].min) + 1;
    *total = count;

    
    u32 arrayLength = (u32)v->arrayLength;
    const u32 *dims = v->arrayDimensions;
    size_t dims_count = v->arrayDimensionsSize;
    if(v->arrayDimensionsSize == 0) {
        dims_count = 1;
        dims = &arrayLength;
    }

    
    *block = count;           
    *stride = v->arrayLength; 
    *first = 0;
    size_t running_dimssize = 1;
    UA_Boolean found_contiguous = false;
    for(size_t k = dims_count; k > 0;) {
        --k;
        size_t dimrange = 1 + range.dimensions[k].max - range.dimensions[k].min;
        if(!found_contiguous && dimrange != dims[k]) {
            
            found_contiguous = true;
            *block = running_dimssize * dimrange;
            *stride = running_dimssize * dims[k];
        }
        *first += running_dimssize * range.dimensions[k].min;
        running_dimssize *= dims[k];
    }
}


static UA_Boolean
isStringLike(const UA_DataType *type) {
    if(type == &UA_TYPES[UA_TYPES_STRING] ||
       type == &UA_TYPES[UA_TYPES_BYTESTRING] ||
       type == &UA_TYPES[UA_TYPES_XMLELEMENT])
        return true;
    return false;
}


static UA_StatusCode
copySubString(const UA_String *src, UA_String *dst,
              const UA_NumericRangeDimension *dim) {
    if(dim->min > dim->max)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    if(dim->min >= src->length)
        return UA_STATUSCODE_BADINDEXRANGENODATA;

    size_t length;
    if(dim->max < src->length)
       length = dim->max - dim->min + 1;
    else
        length = src->length - dim->min;

    UA_StatusCode retval = UA_ByteString_allocBuffer(dst, length);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    memcpy(dst->data, &src->data[dim->min], length);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Variant_copyRange(const UA_Variant *src, UA_Variant * UA_RESTRICT dst,
                     const UA_NumericRange range) {
    if(!src->type)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_Boolean isScalar = UA_Variant_isScalar(src);
    UA_Boolean stringLike = isStringLike(src->type);

    
    if(range.dimensionsSize > UA_MAX_ARRAY_DIMS)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    UA_NumericRangeDimension thisrangedims[UA_MAX_ARRAY_DIMS];
    memcpy(thisrangedims, range.dimensions, sizeof(UA_NumericRangeDimension) * range.dimensionsSize);
    UA_NumericRange thisrange = {range.dimensionsSize, thisrangedims};

    UA_NumericRangeDimension scalarThisDimension = {0,0}; 
    UA_NumericRange nextrange = {0, NULL};

    UA_Variant arraySrc;
    if(isScalar) {
        
        arraySrc = *src;
        arraySrc.arrayLength = 1;
        src = &arraySrc;
        
        thisrange.dimensions = &scalarThisDimension;
        thisrange.dimensionsSize = 1;
        nextrange = range;
    } else {
        
        size_t dims = src->arrayDimensionsSize;
        if(dims == 0)
            dims = 1;
        if(dims > range.dimensionsSize)
            return UA_STATUSCODE_BADINDEXRANGEINVALID;
       thisrange.dimensionsSize = dims;
       nextrange.dimensions = &range.dimensions[dims];
       nextrange.dimensionsSize = range.dimensionsSize - dims;
    }

    UA_StatusCode retval = checkAdjustRange(src, &thisrange);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    size_t count, block, stride, first;
    computeStrides(src, thisrange, &count, &block, &stride, &first);
    UA_assert(block > 0);

    
    UA_Variant_init(dst);
    dst->data = UA_Array_new(count, src->type);
    if(!dst->data)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    
    size_t block_count = count / block;
    size_t elem_size = src->type->memSize;
    uintptr_t nextdst = (uintptr_t)dst->data;
    uintptr_t nextsrc = (uintptr_t)src->data + (elem_size * first);
    if(nextrange.dimensionsSize == 0) {
        
        if(src->type->pointerFree) {
            for(size_t i = 0; i < block_count; ++i) {
                memcpy((void*)nextdst, (void*)nextsrc, elem_size * block);
                nextdst += block * elem_size;
                nextsrc += stride * elem_size;
            }
        } else {
            for(size_t i = 0; i < block_count; ++i) {
                for(size_t j = 0; j < block; ++j) {
                    retval = UA_copy((const void*)nextsrc,
                                     (void*)nextdst, src->type);
                    nextdst += elem_size;
                    nextsrc += elem_size;
                }
                nextsrc += (stride - block) * elem_size;
            }
        }
    } else {
        if(src->type != &UA_TYPES[UA_TYPES_VARIANT]) {
            if(!stringLike)
                retval = UA_STATUSCODE_BADINDEXRANGENODATA;
            if(nextrange.dimensionsSize != 1)
                retval = UA_STATUSCODE_BADINDEXRANGENODATA;
        }

        
        for(size_t i = 0; i < block_count; ++i) {
            for(size_t j = 0; j < block && retval == UA_STATUSCODE_GOOD; ++j) {
                if(stringLike)
                    retval = copySubString((const UA_String*)nextsrc,
                                           (UA_String*)nextdst,
                                           nextrange.dimensions);
                else
                    retval = UA_Variant_copyRange((const UA_Variant*)nextsrc,
                                                  (UA_Variant*)nextdst,
                                                  nextrange);
                nextdst += elem_size;
                nextsrc += elem_size;
            }
            nextsrc += (stride - block) * elem_size;
        }
    }

    
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Array_delete(dst->data, count, src->type);
        dst->data = NULL;
        return retval;
    }

    
    dst->type = src->type;
    if(isScalar)
        return retval;

    
    dst->arrayLength = count;
    if(src->arrayDimensionsSize > 0) {
        dst->arrayDimensions =
            (u32*)UA_Array_new(thisrange.dimensionsSize, &UA_TYPES[UA_TYPES_UINT32]);
        if(!dst->arrayDimensions) {
            Variant_clear(dst, NULL);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        dst->arrayDimensionsSize = thisrange.dimensionsSize;
        for(size_t k = 0; k < thisrange.dimensionsSize; ++k)
            dst->arrayDimensions[k] =
                thisrange.dimensions[k].max - thisrange.dimensions[k].min + 1;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
Variant_setRange(UA_Variant *v, void *array, size_t arraySize,
                 const UA_NumericRange range, UA_Boolean copy) {
    if(!v->type)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    
    if(range.dimensionsSize > UA_MAX_ARRAY_DIMS)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    UA_NumericRangeDimension thisrangedims[UA_MAX_ARRAY_DIMS];
    memcpy(thisrangedims, range.dimensions, sizeof(UA_NumericRangeDimension) * range.dimensionsSize);
    UA_NumericRange thisrange = {range.dimensionsSize, thisrangedims};

    UA_StatusCode retval = checkAdjustRange(v, &thisrange);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    size_t count, block, stride, first;
    computeStrides(v, range, &count, &block, &stride, &first);
    if(count != arraySize)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;

    
    size_t block_count = count / block;
    size_t elem_size = v->type->memSize;
    uintptr_t nextdst = (uintptr_t)v->data + (first * elem_size);
    uintptr_t nextsrc = (uintptr_t)array;
    if(v->type->pointerFree || !copy) {
        for(size_t i = 0; i < block_count; ++i) {
            memcpy((void*)nextdst, (void*)nextsrc, elem_size * block);
            nextsrc += block * elem_size;
            nextdst += stride * elem_size;
        }
    } else {
        for(size_t i = 0; i < block_count; ++i) {
            for(size_t j = 0; j < block; ++j) {
                clearJumpTable[v->type->typeKind]((void*)nextdst, v->type);
                retval |= UA_copy((void*)nextsrc, (void*)nextdst, v->type);
                nextdst += elem_size;
                nextsrc += elem_size;
            }
            nextdst += (stride - block) * elem_size;
        }
    }

    
    if(!copy && !v->type->pointerFree)
        memset(array, 0, sizeof(elem_size)*arraySize);

    return retval;
}

UA_StatusCode
UA_Variant_setRange(UA_Variant *v, void * UA_RESTRICT array,
                    size_t arraySize, const UA_NumericRange range) {
    return Variant_setRange(v, array, arraySize, range, false);
}

UA_StatusCode
UA_Variant_setRangeCopy(UA_Variant *v, const void * UA_RESTRICT array,
                        size_t arraySize, const UA_NumericRange range) {
    return Variant_setRange(v, (void*)(uintptr_t)array,
                            arraySize, range, true);
}


static void
LocalizedText_clear(UA_LocalizedText *p, const UA_DataType *_) {
    String_clear(&p->locale, NULL);
    String_clear(&p->text, NULL);
}

static UA_StatusCode
LocalizedText_copy(UA_LocalizedText const *src, UA_LocalizedText *dst,
                   const UA_DataType *_) {
    UA_StatusCode retval = String_copy(&src->locale, &dst->locale, NULL);
    retval |= String_copy(&src->text, &dst->text, NULL);
    return retval;
}


static void
DataValue_clear(UA_DataValue *p, const UA_DataType *_) {
    Variant_clear(&p->value, NULL);
}

static UA_StatusCode
DataValue_copy(UA_DataValue const *src, UA_DataValue *dst,
               const UA_DataType *_) {
    memcpy(dst, src, sizeof(UA_DataValue));
    UA_Variant_init(&dst->value);
    UA_StatusCode retval = Variant_copy(&src->value, &dst->value, NULL);
    if(retval != UA_STATUSCODE_GOOD)
        DataValue_clear(dst, NULL);
    return retval;
}

UA_StatusCode
UA_DataValue_copyVariantRange(const UA_DataValue *src, UA_DataValue * UA_RESTRICT dst,
                              const UA_NumericRange range) {
    memcpy(dst, src, sizeof(UA_DataValue));
    UA_Variant_init(&dst->value);
    UA_StatusCode retval = UA_Variant_copyRange(&src->value, &dst->value, range);
    if(retval != UA_STATUSCODE_GOOD)
        DataValue_clear(dst, NULL);
    return retval;
}


static void
DiagnosticInfo_clear(UA_DiagnosticInfo *p, const UA_DataType *_) {
    String_clear(&p->additionalInfo, NULL);
    if(p->hasInnerDiagnosticInfo && p->innerDiagnosticInfo) {
        DiagnosticInfo_clear(p->innerDiagnosticInfo, NULL);
        UA_free(p->innerDiagnosticInfo);
    }
}

static UA_StatusCode
DiagnosticInfo_copy(UA_DiagnosticInfo const *src, UA_DiagnosticInfo *dst,
                    const UA_DataType *_) {
    memcpy(dst, src, sizeof(UA_DiagnosticInfo));
    UA_String_init(&dst->additionalInfo);
    dst->innerDiagnosticInfo = NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(src->hasAdditionalInfo)
        retval = String_copy(&src->additionalInfo, &dst->additionalInfo, NULL);
    if(src->hasInnerDiagnosticInfo && src->innerDiagnosticInfo) {
        dst->innerDiagnosticInfo = (UA_DiagnosticInfo*)
            UA_malloc(sizeof(UA_DiagnosticInfo));
        if(UA_LIKELY(dst->innerDiagnosticInfo != NULL)) {
            retval |= DiagnosticInfo_copy(src->innerDiagnosticInfo,
                                          dst->innerDiagnosticInfo, NULL);
            dst->hasInnerDiagnosticInfo = true;
        } else {
            dst->hasInnerDiagnosticInfo = false;
            retval |= UA_STATUSCODE_BADOUTOFMEMORY;
        }
    }
    return retval;
}





void *
UA_new(const UA_DataType *type) {
    void *p = UA_calloc(1, type->memSize);
    return p;
}

static UA_StatusCode
copyByte(const u8 *src, u8 *dst, const UA_DataType *_) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
copy2Byte(const u16 *src, u16 *dst, const UA_DataType *_) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
copy4Byte(const u32 *src, u32 *dst, const UA_DataType *_) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
copy8Byte(const u64 *src, u64 *dst, const UA_DataType *_) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
copyGuid(const UA_Guid *src, UA_Guid *dst, const UA_DataType *_) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
copyStructure(const void *src, void *dst, const UA_DataType *type) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    uintptr_t ptrs = (uintptr_t)src;
    uintptr_t ptrd = (uintptr_t)dst;
    for(size_t i = 0; i < type->membersSize; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        ptrs += m->padding;
        ptrd += m->padding;
        if(!m->isOptional) {
            if(!m->isArray) {
                retval |= copyJumpTable[mt->typeKind]((const void *)ptrs, (void *)ptrd, mt);
                ptrs += mt->memSize;
                ptrd += mt->memSize;
            } else {
                size_t *dst_size = (size_t*)ptrd;
                const size_t size = *((const size_t*)ptrs);
                ptrs += sizeof(size_t);
                ptrd += sizeof(size_t);
                retval |= UA_Array_copy(*(void* const*)ptrs, size, (void**)ptrd, mt);
                if(retval == UA_STATUSCODE_GOOD)
                    *dst_size = size;
                else
                    *dst_size = 0;
                ptrs += sizeof(void*);
                ptrd += sizeof(void*);
            }
        } else {
            if(!m->isArray) {
                if(*(void* const*)ptrs != NULL)
                    retval |= UA_Array_copy(*(void* const*)ptrs, 1, (void**)ptrd, mt);
            } else {
                if(*(void* const*)(ptrs+sizeof(size_t)) != NULL) {
                    size_t *dst_size = (size_t*)ptrd;
                    const size_t size = *((const size_t*)ptrs);
                    ptrs += sizeof(size_t);
                    ptrd += sizeof(size_t);
                    retval |= UA_Array_copy(*(void* const*)ptrs, size, (void**)ptrd, mt);
                    if(retval == UA_STATUSCODE_GOOD)
                        *dst_size = size;
                    else
                        *dst_size = 0;
                } else {
                    ptrs += sizeof(size_t);
                    ptrd += sizeof(size_t);
                }
            }
            ptrs += sizeof(void*);
            ptrd += sizeof(void*);
        }
    }
    return retval;
}

static UA_StatusCode
copyUnion(const void *src, void *dst, const UA_DataType *type) {
    uintptr_t ptrs = (uintptr_t) src;
    uintptr_t ptrd = (uintptr_t) dst;
    UA_UInt32 selection = *(UA_UInt32 *)ptrs;
    UA_copy((const UA_UInt32 *) ptrs, (UA_UInt32 *) ptrd, &UA_TYPES[UA_TYPES_UINT32]);
    if(selection == 0)
        return UA_STATUSCODE_GOOD;
    const UA_DataTypeMember *m = &type->members[selection-1];
    const UA_DataType *mt = m->memberType;
    ptrs += m->padding;
    ptrd += m->padding;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if (m->isArray) {
        size_t *dst_size = (size_t*)ptrd;
        const size_t size = *((const size_t*)ptrs);
        ptrs += sizeof(size_t);
        ptrd += sizeof(size_t);
        retval = UA_Array_copy(*(void* const*)ptrs, size, (void**)ptrd, mt);
        if(retval == UA_STATUSCODE_GOOD)
            *dst_size = size;
        else
            *dst_size = 0;
    } else {
        retval = copyJumpTable[mt->typeKind]((const void *)ptrs, (void *)ptrd, mt);
    }

    return retval;
}

static UA_StatusCode
copyNotImplemented(const void *src, void *dst, const UA_DataType *type) {
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

const UA_copySignature copyJumpTable[UA_DATATYPEKINDS] = {
    (UA_copySignature)copyByte, 
    (UA_copySignature)copyByte, 
    (UA_copySignature)copyByte, 
    (UA_copySignature)copy2Byte, 
    (UA_copySignature)copy2Byte, 
    (UA_copySignature)copy4Byte, 
    (UA_copySignature)copy4Byte, 
    (UA_copySignature)copy8Byte, 
    (UA_copySignature)copy8Byte, 
    (UA_copySignature)copy4Byte, 
    (UA_copySignature)copy8Byte, 
    (UA_copySignature)String_copy,
    (UA_copySignature)copy8Byte, 
    (UA_copySignature)copyGuid, 
    (UA_copySignature)String_copy, 
    (UA_copySignature)String_copy, 
    (UA_copySignature)NodeId_copy,
    (UA_copySignature)ExpandedNodeId_copy,
    (UA_copySignature)copy4Byte, 
    (UA_copySignature)QualifiedName_copy,
    (UA_copySignature)LocalizedText_copy,
    (UA_copySignature)ExtensionObject_copy,
    (UA_copySignature)DataValue_copy,
    (UA_copySignature)Variant_copy,
    (UA_copySignature)DiagnosticInfo_copy,
    (UA_copySignature)copyNotImplemented, 
    (UA_copySignature)copy4Byte, 
    (UA_copySignature)copyStructure,
    (UA_copySignature)copyStructure, 
    (UA_copySignature)copyUnion, 
    (UA_copySignature)copyNotImplemented 
};

UA_StatusCode
UA_copy(const void *src, void *dst, const UA_DataType *type) {
    memset(dst, 0, type->memSize); 
    UA_StatusCode retval = copyJumpTable[type->typeKind](src, dst, type);
    if(retval != UA_STATUSCODE_GOOD)
        UA_clear(dst, type);
    return retval;
}

static void
clearStructure(void *p, const UA_DataType *type) {
    uintptr_t ptr = (uintptr_t)p;
    for(size_t i = 0; i < type->membersSize; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        ptr += m->padding;
        if(!m->isOptional) {
            if(!m->isArray) {
                clearJumpTable[mt->typeKind]((void*)ptr, mt);
                ptr += mt->memSize;
            } else {
                size_t length = *(size_t*)ptr;
                ptr += sizeof(size_t);
                UA_Array_delete(*(void**)ptr, length, mt);
                ptr += sizeof(void*);
            }
        } else { 
            if(!m->isArray) {
                
                if((*(void *const *)ptr != NULL))
                    UA_Array_delete(*(void **)ptr, 1, mt);
                ptr += sizeof(void *);
            } else {
                
                if((*(void *const *)(ptr + sizeof(size_t)) != NULL)) {
                    size_t length = *(size_t *)ptr;
                    ptr += sizeof(size_t);
                    UA_Array_delete(*(void **)ptr, length, mt);
                    ptr += sizeof(void *);
                } else { 
                    ptr += sizeof(size_t);
                    ptr += sizeof(void *);
                }
            }
        }
    }
}

static void
clearUnion(void *p, const UA_DataType *type) {
    uintptr_t ptr = (uintptr_t) p;
    UA_UInt32 selection = *(UA_UInt32 *)ptr;
    if(selection == 0)
        return;
    const UA_DataTypeMember *m = &type->members[selection-1];
    const UA_DataType *mt = m->memberType;
    ptr += m->padding;
    if (m->isArray) {
        size_t length = *(size_t *)ptr;
        ptr += sizeof(size_t);
        UA_Array_delete(*(void **)ptr, length, mt);
    } else {
        UA_clear((void *) ptr, mt);
    }
}

static void nopClear(void *p, const UA_DataType *type) { }

const
UA_clearSignature clearJumpTable[UA_DATATYPEKINDS] = {
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)String_clear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)String_clear, 
    (UA_clearSignature)String_clear, 
    (UA_clearSignature)NodeId_clear,
    (UA_clearSignature)ExpandedNodeId_clear,
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)QualifiedName_clear,
    (UA_clearSignature)LocalizedText_clear,
    (UA_clearSignature)ExtensionObject_clear,
    (UA_clearSignature)DataValue_clear,
    (UA_clearSignature)Variant_clear,
    (UA_clearSignature)DiagnosticInfo_clear,
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)nopClear, 
    (UA_clearSignature)clearStructure,
    (UA_clearSignature)clearStructure, 
    (UA_clearSignature)clearUnion, 
    (UA_clearSignature)nopClear 
};

void
UA_clear(void *p, const UA_DataType *type) {
    clearJumpTable[type->typeKind](p, type);
    memset(p, 0, type->memSize); 
}

void
UA_delete(void *p, const UA_DataType *type) {
    clearJumpTable[type->typeKind](p, type);
    UA_free(p);
}





#define UA_NUMERICORDER(NAME, TYPE)                                 \
    static UA_Order                                                 \
    NAME(const TYPE *p1, const TYPE *p2, const UA_DataType *type) { \
        if(*p1 != *p2)                                              \
            return (*p1 < *p2) ? UA_ORDER_LESS : UA_ORDER_MORE;     \
        return UA_ORDER_EQ;                                         \
    }

UA_NUMERICORDER(booleanOrder, UA_Boolean)
UA_NUMERICORDER(sByteOrder, UA_SByte)
UA_NUMERICORDER(byteOrder, UA_Byte)
UA_NUMERICORDER(int16Order, UA_Int16)
UA_NUMERICORDER(uInt16Order, UA_UInt16)
UA_NUMERICORDER(int32Order, UA_Int32)
UA_NUMERICORDER(uInt32Order, UA_UInt32)
UA_NUMERICORDER(int64Order, UA_Int64)
UA_NUMERICORDER(uInt64Order, UA_UInt64)

#define UA_FLOATORDER(NAME, TYPE)                                   \
    static UA_Order                                                 \
    NAME(const TYPE *p1, const TYPE *p2, const UA_DataType *type) { \
        if(*p1 != *p2) {                                            \
                                                     \
            if(*p1 != *p1) {                                        \
                if(*p2 != *p2)                                      \
                    return UA_ORDER_EQ;                             \
                return UA_ORDER_LESS;                               \
            }                                                       \
                                                     \
            if(*p2 != *p2)                                          \
                return UA_ORDER_MORE;                               \
            return (*p1 < *p2) ? UA_ORDER_LESS : UA_ORDER_MORE;     \
        }                                                           \
        return UA_ORDER_EQ;                                         \
    }

UA_FLOATORDER(floatOrder, UA_Float)
UA_FLOATORDER(doubleOrder, UA_Double)

static UA_Order
guidOrder(const UA_Guid *p1, const UA_Guid *p2, const UA_DataType *type) {
    if(p1->data1 != p2->data1)
        return (p1->data1 < p2->data1) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->data2 != p2->data2)
        return (p1->data2 < p2->data2) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->data3 != p2->data3)
        return (p1->data3 < p2->data3) ? UA_ORDER_LESS : UA_ORDER_MORE;
    int cmp = memcmp(p1->data4, p2->data4, 8);
    if(cmp != 0)
        return (cmp < 0) ? UA_ORDER_LESS : UA_ORDER_MORE;
    return UA_ORDER_EQ;
}

static UA_Order
stringOrder(const UA_String *p1, const UA_String *p2, const UA_DataType *type) {
    if(p1->length != p2->length)
        return (p1->length < p2->length) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->data == p2->data) return UA_ORDER_EQ;
    if(p1->data == NULL) return UA_ORDER_LESS;
    if(p2->data == NULL) return UA_ORDER_MORE;
    int cmp = memcmp((const char*)p1->data, (const char*)p2->data, p1->length);
    if(cmp != 0)
        return (cmp < 0) ? UA_ORDER_LESS : UA_ORDER_MORE;
    return UA_ORDER_EQ;
}

static UA_Order
nodeIdOrder(const UA_NodeId *p1, const UA_NodeId *p2, const UA_DataType *_) {
    
    if(p1->namespaceIndex != p2->namespaceIndex)
        return (p1->namespaceIndex < p2->namespaceIndex) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->identifierType != p2->identifierType)
        return (p1->identifierType < p2->identifierType) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    switch(p1->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
    default:
        if(p1->identifier.numeric != p2->identifier.numeric)
            return (p1->identifier.numeric < p2->identifier.numeric) ?
                UA_ORDER_LESS : UA_ORDER_MORE;
        return UA_ORDER_EQ;
    case UA_NODEIDTYPE_GUID:
        return guidOrder(&p1->identifier.guid, &p2->identifier.guid, NULL);
    case UA_NODEIDTYPE_STRING:
    case UA_NODEIDTYPE_BYTESTRING:
        return stringOrder(&p1->identifier.string, &p2->identifier.string, NULL);
    }
}

static UA_Order
expandedNodeIdOrder(const UA_ExpandedNodeId *p1, const UA_ExpandedNodeId *p2,
                    const UA_DataType *_) {
    if(p1->serverIndex != p2->serverIndex)
        return (p1->serverIndex < p2->serverIndex) ? UA_ORDER_LESS : UA_ORDER_MORE;
    UA_Order o = stringOrder(&p1->namespaceUri, &p2->namespaceUri, NULL);
    if(o != UA_ORDER_EQ)
        return o;
    return nodeIdOrder(&p1->nodeId, &p2->nodeId, NULL);
}

static UA_Order
qualifiedNameOrder(const UA_QualifiedName *p1, const UA_QualifiedName *p2,
                   const UA_DataType *_) {
    if(p1->namespaceIndex != p2->namespaceIndex)
        return (p1->namespaceIndex < p2->namespaceIndex) ? UA_ORDER_LESS : UA_ORDER_MORE;
    return stringOrder(&p1->name, &p2->name, NULL);
}

static UA_Order
localizedTextOrder(const UA_LocalizedText *p1, const UA_LocalizedText *p2,
                   const UA_DataType *_) {
    UA_Order o = stringOrder(&p1->locale, &p2->locale, NULL);
    if(o != UA_ORDER_EQ)
        return o;
    return stringOrder(&p1->text, &p2->text, NULL);
}

static UA_Order
extensionObjectOrder(const UA_ExtensionObject *p1, const UA_ExtensionObject *p2,
                     const UA_DataType *_) {
    UA_ExtensionObjectEncoding enc1 = p1->encoding;
    UA_ExtensionObjectEncoding enc2 = p2->encoding;
    if(enc1 > UA_EXTENSIONOBJECT_DECODED)
        enc1 = UA_EXTENSIONOBJECT_DECODED;
    if(enc2 > UA_EXTENSIONOBJECT_DECODED)
        enc2 = UA_EXTENSIONOBJECT_DECODED;
    if(enc1 != enc2)
        return (enc1 < enc2) ? UA_ORDER_LESS : UA_ORDER_MORE;

    switch(enc1) {
    case UA_EXTENSIONOBJECT_ENCODED_NOBODY:
        return UA_ORDER_EQ;

    case UA_EXTENSIONOBJECT_ENCODED_BYTESTRING:
    case UA_EXTENSIONOBJECT_ENCODED_XML: {
            UA_Order o = nodeIdOrder(&p1->content.encoded.typeId,
                                     &p2->content.encoded.typeId, NULL);
            if(o != UA_ORDER_EQ)
                return o;
            return stringOrder((const UA_String*)&p1->content.encoded.body,
                               (const UA_String*)&p2->content.encoded.body, NULL);
        }

    case UA_EXTENSIONOBJECT_DECODED:
    default: {
            const UA_DataType *type1 = p1->content.decoded.type;
            const UA_DataType *type2 = p1->content.decoded.type;
            if(type1 != type2)
                return ((uintptr_t)type1 < (uintptr_t)type2) ? UA_ORDER_LESS : UA_ORDER_MORE;
            if(!type1)
                return UA_ORDER_EQ;
            return orderJumpTable[type1->typeKind]
                (p1->content.decoded.data, p2->content.decoded.data, type1);
        }
    }
}

static UA_Order
arrayOrder(const void *p1, size_t p1Length,
           const void *p2, size_t p2Length,
           const UA_DataType *type) {
    if(p1Length != p2Length)
        return (p1Length < p2Length) ? UA_ORDER_LESS : UA_ORDER_MORE;
    uintptr_t u1 = (uintptr_t)p1;
    uintptr_t u2 = (uintptr_t)p2;
    for(size_t i = 0; i < p1Length; i++) {
        UA_Order o = orderJumpTable[type->typeKind]((const void*)u1, (const void*)u2, type);
        if(o != UA_ORDER_EQ)
            return o;
        u1 += type->memSize;
        u2 += type->memSize;
    }
    return UA_ORDER_EQ;
}

static UA_Order
variantOrder(const UA_Variant *p1, const UA_Variant *p2, const UA_DataType *_) {
    if(p1->type != p2->type)
        return ((uintptr_t)p1->type < (uintptr_t)p2->type) ? UA_ORDER_LESS : UA_ORDER_MORE;

    UA_Order o;
    if(p1->type != NULL) {
        
        UA_Boolean s1 = UA_Variant_isScalar(p1);
        UA_Boolean s2 = UA_Variant_isScalar(p2);
        if(s1 != s2)
            return s1 ? UA_ORDER_LESS : UA_ORDER_MORE;
        if(s1) {
            o = orderJumpTable[p1->type->typeKind](p1->data, p2->data, p1->type);
        } else {
            
            if(p1->arrayLength != p2->arrayLength)
                return (p1->arrayLength < p2->arrayLength) ? UA_ORDER_LESS : UA_ORDER_MORE;
            o = arrayOrder(p1->data, p1->arrayLength, p2->data, p2->arrayLength, p1->type);
        }
        if(o != UA_ORDER_EQ)
            return o;
    }

    if(p1->arrayDimensionsSize != p2->arrayDimensionsSize)
        return (p1->arrayDimensionsSize < p2->arrayDimensionsSize) ?
            UA_ORDER_LESS : UA_ORDER_MORE;
    o = UA_ORDER_EQ;
    if(p1->arrayDimensionsSize > 0)
        o = arrayOrder(p1->arrayDimensions, p1->arrayDimensionsSize,
                       p2->arrayDimensions, p2->arrayDimensionsSize,
                       &UA_TYPES[UA_TYPES_UINT32]);
    return o;
}

static UA_Order
dataValueOrder(const UA_DataValue *p1, const UA_DataValue *p2, const UA_DataType *_) {
    
    if(p1->hasValue != p2->hasValue)
        return (!p1->hasValue) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasValue) {
        UA_Order o = variantOrder(&p1->value, &p2->value, NULL);
        if(o != UA_ORDER_EQ)
            return o;
    }

    
    if(p1->hasStatus != p2->hasStatus)
        return (!p1->hasStatus) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasStatus && p1->status != p2->status)
        return (p1->status < p2->status) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasSourceTimestamp != p2->hasSourceTimestamp)
        return (!p1->hasSourceTimestamp) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasSourceTimestamp && p1->sourceTimestamp != p2->sourceTimestamp)
        return (p1->sourceTimestamp < p2->sourceTimestamp) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasServerTimestamp != p2->hasServerTimestamp)
        return (!p1->hasServerTimestamp) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasServerTimestamp && p1->serverTimestamp != p2->serverTimestamp)
        return (p1->serverTimestamp < p2->serverTimestamp) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasSourcePicoseconds != p2->hasSourcePicoseconds)
        return (!p1->hasSourcePicoseconds) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasSourcePicoseconds && p1->sourcePicoseconds != p2->sourcePicoseconds)
        return (p1->sourcePicoseconds < p2->sourcePicoseconds) ?
            UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasServerPicoseconds != p2->hasServerPicoseconds)
        return (!p1->hasServerPicoseconds) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasServerPicoseconds && p1->serverPicoseconds != p2->serverPicoseconds)
        return (p1->serverPicoseconds < p2->serverPicoseconds) ?
            UA_ORDER_LESS : UA_ORDER_MORE;

    return UA_ORDER_EQ;
}

static UA_Order
diagnosticInfoOrder(const UA_DiagnosticInfo *p1, const UA_DiagnosticInfo *p2,
                    const UA_DataType *_) {
    
    if(p1->hasSymbolicId != p2->hasSymbolicId)
        return (!p1->hasSymbolicId) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasSymbolicId && p1->symbolicId != p2->symbolicId)
        return (p1->symbolicId < p2->symbolicId) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasNamespaceUri != p2->hasNamespaceUri)
        return (!p1->hasNamespaceUri) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasNamespaceUri && p1->namespaceUri != p2->namespaceUri)
        return (p1->namespaceUri < p2->namespaceUri) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasLocalizedText != p2->hasLocalizedText)
        return (!p1->hasLocalizedText) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasLocalizedText && p1->localizedText != p2->localizedText)
        return (p1->localizedText < p2->localizedText) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasLocale != p2->hasLocale)
        return (!p1->hasLocale) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasLocale && p1->locale != p2->locale)
        return (p1->locale < p2->locale) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasAdditionalInfo != p2->hasAdditionalInfo)
        return (!p1->hasAdditionalInfo) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasAdditionalInfo) {
        UA_Order o = stringOrder(&p1->additionalInfo, &p2->additionalInfo, NULL);
        if(o != UA_ORDER_EQ)
            return o;
    }

    
    if(p1->hasInnerStatusCode != p2->hasInnerStatusCode)
        return (!p1->hasInnerStatusCode) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->hasInnerStatusCode && p1->innerStatusCode != p2->innerStatusCode)
        return (p1->innerStatusCode < p2->innerStatusCode) ? UA_ORDER_LESS : UA_ORDER_MORE;

    
    if(p1->hasInnerDiagnosticInfo != p2->hasInnerDiagnosticInfo)
        return (!p1->hasInnerDiagnosticInfo) ? UA_ORDER_LESS : UA_ORDER_MORE;
    if(p1->innerDiagnosticInfo == p2->innerDiagnosticInfo)
        return UA_ORDER_EQ;
    if(!p1->innerDiagnosticInfo || !p2->innerDiagnosticInfo)
        return (!p1->innerDiagnosticInfo) ? UA_ORDER_LESS : UA_ORDER_MORE;
    return diagnosticInfoOrder(p1->innerDiagnosticInfo, p2->innerDiagnosticInfo, NULL);
}

static UA_Order
structureOrder(const void *p1, const void *p2, const UA_DataType *type) {
    uintptr_t u1 = (uintptr_t)p1;
    uintptr_t u2 = (uintptr_t)p2;
    UA_Order o = UA_ORDER_EQ;
    for(size_t i = 0; i < type->membersSize; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        u1 += m->padding;
        u2 += m->padding;
        if(!m->isOptional) {
            if(!m->isArray) {
                o = orderJumpTable[mt->typeKind]((const void *)u1, (const void *)u2, mt);
                u1 += mt->memSize;
                u2 += mt->memSize;
            } else {
                size_t size1 = *(size_t*)u1;
                size_t size2 = *(size_t*)u2;
                u1 += sizeof(size_t);
                u2 += sizeof(size_t);
                o = arrayOrder(*(void* const*)u1, size1, *(void* const*)u2, size2, mt);
                u1 += sizeof(void*);
                u2 += sizeof(void*);
            }
        } else {
            if(!m->isArray) {
                const void *pp1 = *(void* const*)u1;
                const void *pp2 = *(void* const*)u2;
                if(pp1 == pp2) {
                    o = UA_ORDER_EQ;
                } else if(pp1 == NULL) {
                    o = UA_ORDER_LESS;
                } else if(pp2 == NULL) {
                    o = UA_ORDER_MORE;
                } else {
                    o = orderJumpTable[mt->typeKind](pp1, pp2, mt);
                }
            } else {
                size_t sa1 = *(size_t*)u1;
                size_t sa2 = *(size_t*)u2;
                u1 += sizeof(size_t);
                u2 += sizeof(size_t);
                o = arrayOrder(*(void* const*)u1, sa1, *(void* const*)u2, sa2, mt);
            }
            u1 += sizeof(void*);
            u2 += sizeof(void*);
        }

        if(o != UA_ORDER_EQ)
            break;
    }
    return o;
}

static UA_Order
unionOrder(const void *p1, const void *p2, const UA_DataType *type) {
    UA_UInt32 sel1 = *(const UA_UInt32 *)p1;
    UA_UInt32 sel2 = *(const UA_UInt32 *)p2;
    if(sel1 != sel2)
        return (sel1 < sel2) ? UA_ORDER_LESS : UA_ORDER_MORE;

    if(sel1 == 0) {
        return UA_ORDER_EQ;
    }

    const UA_DataTypeMember *m = &type->members[sel1-1];
    const UA_DataType *mt = m->memberType;

    uintptr_t u1 = ((uintptr_t)p1) + m->padding; 
    uintptr_t u2 = ((uintptr_t)p2) + m->padding;
    if(m->isArray) {
        size_t sa1 = *(size_t*)u1;
        size_t sa2 = *(size_t*)u2;
        u1 += sizeof(size_t);
        u2 += sizeof(size_t);
        return arrayOrder(*(void* const*)u1, sa1, *(void* const*)u2, sa2, mt);
    }
    return orderJumpTable[mt->typeKind]((const void*)u1, (const void*)u2, mt);
}

static UA_Order
notImplementedOrder(const void *p1, const void *p2, const UA_DataType *type) {
    return UA_ORDER_EQ;
}

const
UA_orderSignature orderJumpTable[UA_DATATYPEKINDS] = {
    (UA_orderSignature)booleanOrder,
    (UA_orderSignature)sByteOrder,
    (UA_orderSignature)byteOrder,
    (UA_orderSignature)int16Order,
    (UA_orderSignature)uInt16Order,
    (UA_orderSignature)int32Order,
    (UA_orderSignature)uInt32Order,
    (UA_orderSignature)int64Order,
    (UA_orderSignature)uInt64Order,
    (UA_orderSignature)floatOrder,
    (UA_orderSignature)doubleOrder,
    (UA_orderSignature)stringOrder,
    (UA_orderSignature)int64Order,  
    (UA_orderSignature)guidOrder,
    (UA_orderSignature)stringOrder, 
    (UA_orderSignature)stringOrder, 
    (UA_orderSignature)nodeIdOrder,
    (UA_orderSignature)expandedNodeIdOrder,
    (UA_orderSignature)uInt32Order, 
    (UA_orderSignature)qualifiedNameOrder,
    (UA_orderSignature)localizedTextOrder,
    (UA_orderSignature)extensionObjectOrder,
    (UA_orderSignature)dataValueOrder,
    (UA_orderSignature)variantOrder,
    (UA_orderSignature)diagnosticInfoOrder,
    notImplementedOrder, 
    (UA_orderSignature)uInt32Order, 
    (UA_orderSignature)structureOrder,
    (UA_orderSignature)structureOrder, 
    (UA_orderSignature)unionOrder, 
    notImplementedOrder 
};

UA_Order UA_order(const void *p1, const void *p2, const UA_DataType *type) {
    return orderJumpTable[type->typeKind](p1, p2, type);
}





void *
UA_Array_new(size_t size, const UA_DataType *type) {
    if(size > UA_INT32_MAX)
        return NULL;
    if(size == 0)
        return UA_EMPTY_ARRAY_SENTINEL;
    return UA_calloc(size, type->memSize);
}

UA_StatusCode
UA_Array_copy(const void *src, size_t size,
              void **dst, const UA_DataType *type) {
    if(size == 0) {
        if(src == NULL)
            *dst = NULL;
        else
            *dst= UA_EMPTY_ARRAY_SENTINEL;
        return UA_STATUSCODE_GOOD;
    }

    if(UA_UNLIKELY(!type || !src))
        return UA_STATUSCODE_BADINTERNALERROR;

    
    *dst = UA_calloc(size, type->memSize);
    if(!*dst)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    if(type->pointerFree) {
        memcpy(*dst, src, type->memSize * size);
        return UA_STATUSCODE_GOOD;
    }

    uintptr_t ptrs = (uintptr_t)src;
    uintptr_t ptrd = (uintptr_t)*dst;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < size; ++i) {
        retval |= UA_copy((void*)ptrs, (void*)ptrd, type);
        ptrs += type->memSize;
        ptrd += type->memSize;
    }
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Array_delete(*dst, size, type);
        *dst = NULL;
    }
    return retval;
}

UA_StatusCode
UA_Array_resize(void **p, size_t *size, size_t newSize,
                const UA_DataType *type) {
    if(*size == newSize)
        return UA_STATUSCODE_GOOD;

    
    if(newSize == 0) {
        UA_Array_delete(*p, *size, type);
        *p = UA_EMPTY_ARRAY_SENTINEL;
        *size = 0;
        return UA_STATUSCODE_GOOD;
    }

    void *deleteMembers = NULL;
    if(newSize < *size && !type->pointerFree) {
        size_t deleteSize = *size - newSize;
        deleteMembers = UA_malloc(deleteSize * type->memSize);
        if(!deleteMembers)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        memcpy(deleteMembers, (void*)((uintptr_t)*p + (newSize * type->memSize)),
               deleteSize * type->memSize); 
    }

    void *oldP = *p;
    if(oldP == UA_EMPTY_ARRAY_SENTINEL)
        oldP = NULL;

    
    void *newP = UA_realloc(oldP, newSize * type->memSize);
    if(!newP) {
        if(deleteMembers)
            UA_free(deleteMembers);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    if(newSize > *size) {
        memset((void*)((uintptr_t)newP + (*size * type->memSize)), 0,
               (newSize - *size) * type->memSize);
    } else if(deleteMembers) {
        UA_Array_delete(deleteMembers, *size - newSize, type);
    }

    
    *p = newP;
    *size = newSize;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Array_append(void **p, size_t *size, void *newElem,
                const UA_DataType *type) {
    
    size_t oldSize = *size;
    UA_StatusCode res = UA_Array_resize(p, size, oldSize+1, type);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    
    memcpy((void*)((uintptr_t)*p + (oldSize * type->memSize)),
           newElem, type->memSize);
    UA_init(newElem, type);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode UA_EXPORT
UA_Array_appendCopy(void **p, size_t *size, const void *newElem,
                    const UA_DataType *type) {
    char scratch[512];
    if(type->memSize > 512)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    UA_StatusCode res = UA_copy(newElem, (void*)scratch, type);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    
    res = UA_Array_append(p, size, (void*)scratch, type);
    if(res != UA_STATUSCODE_GOOD)
        UA_clear((void*)scratch, type);
    return res;
}

void
UA_Array_delete(void *p, size_t size, const UA_DataType *type) {
    if(!type->pointerFree) {
        uintptr_t ptr = (uintptr_t)p;
        for(size_t i = 0; i < size; ++i) {
            UA_clear((void*)ptr, type);
            ptr += type->memSize;
        }
    }
    UA_free((void*)((uintptr_t)p & ~(uintptr_t)UA_EMPTY_ARRAY_SENTINEL));
}

#ifdef UA_ENABLE_TYPEDESCRIPTION
UA_Boolean
UA_DataType_getStructMember(const UA_DataType *type, const char *memberName,
                            size_t *outOffset, const UA_DataType **outMemberType,
                            UA_Boolean *outIsArray) {
    if(type->typeKind != UA_DATATYPEKIND_STRUCTURE &&
       type->typeKind != UA_DATATYPEKIND_OPTSTRUCT)
        return false;

    size_t offset = 0;
    for(size_t i = 0; i < type->membersSize; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = m->memberType;
        offset += m->padding;

        if(strcmp(memberName, m->memberName) == 0) {
            *outOffset = offset;
            *outMemberType = mt;
            *outIsArray = m->isArray;
            return true;
        }

        if(!m->isOptional) {
            if(!m->isArray) {
                offset += mt->memSize;
            } else {
                offset += sizeof(size_t);
                offset += sizeof(void*);
            }
        } else { 
            if(!m->isArray) {
                offset += sizeof(void *);
            } else {
                offset += sizeof(size_t);
                offset += sizeof(void *);
            }
        }
    }

    return false;
}
#endif

UA_Boolean
UA_DataType_isNumeric(const UA_DataType *type) {
    switch(type->typeKind) {
    case UA_DATATYPEKIND_SBYTE:
    case UA_DATATYPEKIND_BYTE:
    case UA_DATATYPEKIND_INT16:
    case UA_DATATYPEKIND_UINT16:
    case UA_DATATYPEKIND_INT32:
    case UA_DATATYPEKIND_UINT32:
    case UA_DATATYPEKIND_INT64:
    case UA_DATATYPEKIND_UINT64:
    case UA_DATATYPEKIND_FLOAT:
    case UA_DATATYPEKIND_DOUBLE:
    
        return true;
    default:
        return false;
    }
}





static size_t
readDimension(UA_Byte *buf, size_t buflen, UA_NumericRangeDimension *dim) {
    size_t progress = UA_readNumber(buf, buflen, &dim->min);
    if(progress == 0)
        return 0;
    if(buflen <= progress + 1 || buf[progress] != ':') {
        dim->max = dim->min;
        return progress;
    }

    ++progress;
    size_t progress2 = UA_readNumber(&buf[progress], buflen - progress, &dim->max);
    if(progress2 == 0)
        return 0;

    
    if(dim->min >= dim->max)
        return 0;

    return progress + progress2;
}

UA_StatusCode
UA_NumericRange_parse(UA_NumericRange *range, const UA_String str) {
    size_t idx = 0;
    size_t dimensionsMax = 0;
    UA_NumericRangeDimension *dimensions = NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    size_t offset = 0;
    while(true) {
        
        if(idx >= dimensionsMax) {
            UA_NumericRangeDimension *newds;
            size_t newdssize = sizeof(UA_NumericRangeDimension) * (dimensionsMax + 2);
            newds = (UA_NumericRangeDimension*)UA_realloc(dimensions, newdssize);
            if(!newds) {
                retval = UA_STATUSCODE_BADOUTOFMEMORY;
                break;
            }
            dimensions = newds;
            dimensionsMax = dimensionsMax + 2;
        }

        
        size_t progress = readDimension(&str.data[offset], str.length - offset,
                                        &dimensions[idx]);
        if(progress == 0) {
            retval = UA_STATUSCODE_BADINDEXRANGEINVALID;
            break;
        }
        offset += progress;
        ++idx;

        
        if(offset >= str.length)
            break;

        if(str.data[offset] != ',') {
            retval = UA_STATUSCODE_BADINDEXRANGEINVALID;
            break;
        }
        ++offset;
    }

    if(retval == UA_STATUSCODE_GOOD && idx > 0) {
        range->dimensions = dimensions;
        range->dimensionsSize = idx;
    } else {
        UA_free(dimensions);
    }

    return retval;
}
