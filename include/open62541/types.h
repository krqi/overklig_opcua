
#ifndef UA_TYPES_H_
#define UA_TYPES_H_

#include <opcua/config.h>
#include <opcua/common.h>
#include <opcua/statuscodes.h>

_UA_BEGIN_DECLS

typedef bool UA_Boolean;
#define UA_TRUE true UA_INTERNAL_DEPRECATED
#define UA_FALSE false UA_INTERNAL_DEPRECATED

typedef int8_t UA_SByte;
#define UA_SBYTE_MIN (-128)
#define UA_SBYTE_MAX 127

typedef uint8_t UA_Byte;
#define UA_BYTE_MIN 0
#define UA_BYTE_MAX 255

typedef int16_t UA_Int16;
#define UA_INT16_MIN (-32768)
#define UA_INT16_MAX 32767

typedef uint16_t UA_UInt16;
#define UA_UINT16_MIN 0
#define UA_UINT16_MAX 65535

typedef int32_t UA_Int32;
#define UA_INT32_MIN ((int32_t)-2147483648LL)
#define UA_INT32_MAX 2147483647L

typedef uint32_t UA_UInt32;
#define UA_UINT32_MIN 0
#define UA_UINT32_MAX 4294967295UL

typedef int64_t UA_Int64;
#define UA_INT64_MAX (int64_t)9223372036854775807LL
#define UA_INT64_MIN ((int64_t)-UA_INT64_MAX-1LL)

typedef uint64_t UA_UInt64;
#define UA_UINT64_MIN 0
#define UA_UINT64_MAX (uint64_t)18446744073709551615ULL

typedef float UA_Float;
#define UA_FLOAT_MIN FLT_MIN
#define UA_FLOAT_MAX FLT_MAX

typedef double UA_Double;
#define UA_DOUBLE_MIN DBL_MIN
#define UA_DOUBLE_MAX DBL_MAX

typedef uint32_t UA_StatusCode;

UA_EXPORT const char *
UA_StatusCode_name(UA_StatusCode code);

UA_INLINABLE(UA_Boolean
             UA_StatusCode_isBad(UA_StatusCode code), {
    return ((code >> 30) >= 0x02);
})

UA_INLINABLE(UA_Boolean
             UA_StatusCode_isUncertain(UA_StatusCode code), {
    return ((code >> 30) == 0x01);
})

UA_INLINABLE(UA_Boolean
             UA_StatusCode_isGood(UA_StatusCode code), {
    return ((code >> 30) == 0x00);
})

UA_INLINABLE(UA_Boolean
             UA_StatusCode_isEqualTop(UA_StatusCode s1, UA_StatusCode s2), {
    return ((s1 & 0xFFFF0000) == (s2 & 0xFFFF0000));
})

typedef struct {
    size_t length; 
    UA_Byte *data; 
} UA_String;


UA_String UA_EXPORT
UA_String_fromChars(const char *src) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

UA_Boolean UA_EXPORT
UA_String_isEmpty(const UA_String *s);

UA_EXPORT extern const UA_String UA_STRING_NULL;

UA_INLINABLE(UA_String
             UA_STRING(char *chars), {
    UA_String s;
    memset(&s, 0, sizeof(s));
    if(!chars)
        return s;
    s.length = strlen(chars); s.data = (UA_Byte*)chars;
    return s;
})

#define UA_STRING_ALLOC(CHARS) UA_String_fromChars(CHARS)


#define UA_STRING_STATIC(CHARS) {sizeof(CHARS)-1, (UA_Byte*)CHARS}


typedef int64_t UA_DateTime;


#define UA_DATETIME_USEC 10LL
#define UA_DATETIME_MSEC (UA_DATETIME_USEC * 1000LL)
#define UA_DATETIME_SEC (UA_DATETIME_MSEC * 1000LL)


UA_DateTime UA_EXPORT UA_DateTime_now(void);


UA_Int64 UA_EXPORT UA_DateTime_localTimeUtcOffset(void);

UA_DateTime UA_EXPORT UA_DateTime_nowMonotonic(void);


typedef struct UA_DateTimeStruct {
    UA_UInt16 nanoSec;
    UA_UInt16 microSec;
    UA_UInt16 milliSec;
    UA_UInt16 sec;
    UA_UInt16 min;
    UA_UInt16 hour;
    UA_UInt16 day;   
    UA_UInt16 month; 
    UA_Int16 year;   
} UA_DateTimeStruct;

UA_DateTimeStruct UA_EXPORT UA_DateTime_toStruct(UA_DateTime t);
UA_DateTime UA_EXPORT UA_DateTime_fromStruct(UA_DateTimeStruct ts);



#define UA_DATETIME_UNIX_EPOCH (11644473600LL * UA_DATETIME_SEC)

UA_INLINABLE(UA_Int64
             UA_DateTime_toUnixTime(UA_DateTime date), {
    return (date - UA_DATETIME_UNIX_EPOCH) / UA_DATETIME_SEC;
})

UA_INLINABLE(UA_DateTime
             UA_DateTime_fromUnixTime(UA_Int64 unixDate), {
    return (unixDate * UA_DATETIME_SEC) + UA_DATETIME_UNIX_EPOCH;
})

typedef struct {
    UA_UInt32 data1;
    UA_UInt16 data2;
    UA_UInt16 data3;
    UA_Byte   data4[8];
} UA_Guid;

UA_EXPORT extern const UA_Guid UA_GUID_NULL;

UA_StatusCode UA_EXPORT
UA_Guid_print(const UA_Guid *guid, UA_String *output);


#ifdef UA_ENABLE_PARSING
UA_StatusCode UA_EXPORT
UA_Guid_parse(UA_Guid *guid, const UA_String str);

UA_INLINABLE(UA_Guid
             UA_GUID(const char *chars), {
    UA_Guid guid;
    UA_Guid_parse(&guid, UA_STRING((char*)(uintptr_t)chars));
    return guid;
})
#endif

typedef UA_String UA_ByteString;

UA_EXPORT extern const UA_ByteString UA_BYTESTRING_NULL;

UA_StatusCode UA_EXPORT
UA_ByteString_allocBuffer(UA_ByteString *bs, size_t length);

UA_StatusCode UA_EXPORT
UA_ByteString_toBase64(const UA_ByteString *bs, UA_String *output);


UA_StatusCode UA_EXPORT
UA_ByteString_fromBase64(UA_ByteString *bs,
                         const UA_String *input);

#define UA_BYTESTRING(chars) UA_STRING(chars)
#define UA_BYTESTRING_ALLOC(chars) UA_STRING_ALLOC(chars)


UA_UInt32 UA_EXPORT
UA_ByteString_hash(UA_UInt32 initialHashValue,
                   const UA_Byte *data, size_t size);

typedef UA_String UA_XmlElement;

enum UA_NodeIdType {
    UA_NODEIDTYPE_STRING     = 3,
    UA_NODEIDTYPE_GUID       = 4,
    UA_NODEIDTYPE_BYTESTRING = 5
};

typedef struct {
    UA_UInt16 namespaceIndex;
    enum UA_NodeIdType identifierType;
    union {
        UA_UInt32     numeric;
        UA_String     string;
        UA_Guid       guid;
        UA_ByteString byteString;
    } identifier;
} UA_NodeId;

UA_EXPORT extern const UA_NodeId UA_NODEID_NULL;

UA_Boolean UA_EXPORT UA_NodeId_isNull(const UA_NodeId *p);

UA_StatusCode UA_EXPORT
UA_NodeId_print(const UA_NodeId *id, UA_String *output);

#ifdef UA_ENABLE_PARSING
UA_StatusCode UA_EXPORT
UA_NodeId_parse(UA_NodeId *id, const UA_String str);

UA_INLINABLE(UA_NodeId
             UA_NODEID(const char *chars), {
    UA_NodeId id;
    UA_NodeId_parse(&id, UA_STRING((char*)(uintptr_t)chars));
    return id;
})
#endif


UA_INLINABLE(UA_NodeId
             UA_NODEID_NUMERIC(UA_UInt16 nsIndex,
                               UA_UInt32 identifier), {
    UA_NodeId id;
    memset(&id, 0, sizeof(UA_NodeId));
    id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_NUMERIC;
    id.identifier.numeric = identifier;
    return id;
})

#define UA_NS0ID(ID) UA_NODEID_NUMERIC(0, UA_NS0ID_##ID)

UA_INLINABLE(UA_NodeId
             UA_NODEID_STRING(UA_UInt16 nsIndex, char *chars), {
    UA_NodeId id;
    memset(&id, 0, sizeof(UA_NodeId));
    id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_STRING;
    id.identifier.string = UA_STRING(chars);
    return id;
})

UA_INLINABLE(UA_NodeId
             UA_NODEID_STRING_ALLOC(UA_UInt16 nsIndex,
                                    const char *chars), {
    UA_NodeId id;
    memset(&id, 0, sizeof(UA_NodeId));
    id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_STRING;
    id.identifier.string = UA_STRING_ALLOC(chars);
    return id;
})

UA_INLINABLE(UA_NodeId
             UA_NODEID_GUID(UA_UInt16 nsIndex, UA_Guid guid), {
    UA_NodeId id;
    memset(&id, 0, sizeof(UA_NodeId));
    id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_GUID;
    id.identifier.guid = guid;
    return id;
})

UA_INLINABLE(UA_NodeId
             UA_NODEID_BYTESTRING(UA_UInt16 nsIndex, char *chars), {
    UA_NodeId id;
    memset(&id, 0, sizeof(UA_NodeId));
    id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_BYTESTRING;
    id.identifier.byteString = UA_BYTESTRING(chars);
    return id;
})

UA_INLINABLE(UA_NodeId
             UA_NODEID_BYTESTRING_ALLOC(UA_UInt16 nsIndex,
                                        const char *chars), {
    UA_NodeId id;
    memset(&id, 0, sizeof(UA_NodeId));
    id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_BYTESTRING;
    id.identifier.byteString = UA_BYTESTRING_ALLOC(chars);
    return id;
})


UA_Order UA_EXPORT
UA_NodeId_order(const UA_NodeId *n1, const UA_NodeId *n2);


UA_UInt32 UA_EXPORT UA_NodeId_hash(const UA_NodeId *n);

typedef struct {
    UA_NodeId nodeId;
    UA_String namespaceUri;
    UA_UInt32 serverIndex;
} UA_ExpandedNodeId;

UA_EXPORT extern const UA_ExpandedNodeId UA_EXPANDEDNODEID_NULL;

UA_StatusCode UA_EXPORT
UA_ExpandedNodeId_print(const UA_ExpandedNodeId *id, UA_String *output);

#ifdef UA_ENABLE_PARSING
UA_StatusCode UA_EXPORT
UA_ExpandedNodeId_parse(UA_ExpandedNodeId *id, const UA_String str);

UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID(const char *chars), {
    UA_ExpandedNodeId id;
    UA_ExpandedNodeId_parse(&id, UA_STRING((char*)(uintptr_t)chars));
    return id;
})
#endif



UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID_NUMERIC(UA_UInt16 nsIndex, UA_UInt32 identifier), {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_NUMERIC(nsIndex, identifier);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
})

#define UA_NS0EXID(ID) UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_##ID)

UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID_STRING(UA_UInt16 nsIndex, char *chars), {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_STRING(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
})

UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID_STRING_ALLOC(UA_UInt16 nsIndex, const char *chars), {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_STRING_ALLOC(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
})

UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID_STRING_GUID(UA_UInt16 nsIndex, UA_Guid guid), {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_GUID(nsIndex, guid);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
})

UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID_BYTESTRING(UA_UInt16 nsIndex, char *chars), {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_BYTESTRING(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
})

UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID_BYTESTRING_ALLOC(UA_UInt16 nsIndex, const char *chars), {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_BYTESTRING_ALLOC(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
})

UA_INLINABLE(UA_ExpandedNodeId
             UA_EXPANDEDNODEID_NODEID(UA_NodeId nodeId), {
    UA_ExpandedNodeId id; memset(&id, 0, sizeof(UA_ExpandedNodeId));
    id.nodeId = nodeId; return id;
})

UA_Boolean UA_EXPORT
UA_ExpandedNodeId_isLocal(const UA_ExpandedNodeId *n);


UA_Order UA_EXPORT
UA_ExpandedNodeId_order(const UA_ExpandedNodeId *n1,
                        const UA_ExpandedNodeId *n2);

UA_UInt32 UA_EXPORT
UA_ExpandedNodeId_hash(const UA_ExpandedNodeId *n);

typedef struct {
    UA_UInt16 namespaceIndex;
    UA_String name;
} UA_QualifiedName;

UA_INLINABLE(UA_Boolean
             UA_QualifiedName_isNull(const UA_QualifiedName *q), {
    return (q->namespaceIndex == 0 && q->name.length == 0);
})


UA_UInt32 UA_EXPORT
UA_QualifiedName_hash(const UA_QualifiedName *q);

UA_INLINABLE(UA_QualifiedName
             UA_QUALIFIEDNAME(UA_UInt16 nsIndex, char *chars), {
    UA_QualifiedName qn;
    qn.namespaceIndex = nsIndex;
    qn.name = UA_STRING(chars);
    return qn;
})

UA_INLINABLE(UA_QualifiedName
             UA_QUALIFIEDNAME_ALLOC(UA_UInt16 nsIndex, const char *chars), {
    UA_QualifiedName qn;
    qn.namespaceIndex = nsIndex;
    qn.name = UA_STRING_ALLOC(chars);
    return qn;
})

typedef struct {
    UA_String locale;
    UA_String text;
} UA_LocalizedText;

UA_INLINABLE(UA_LocalizedText
             UA_LOCALIZEDTEXT(char *locale, char *text), {
    UA_LocalizedText lt;
    lt.locale = UA_STRING(locale);
    lt.text = UA_STRING(text);
    return lt;
})

UA_INLINABLE(UA_LocalizedText
             UA_LOCALIZEDTEXT_ALLOC(const char *locale, const char *text), {
    UA_LocalizedText lt;
    lt.locale = UA_STRING_ALLOC(locale);
    lt.text = UA_STRING_ALLOC(text);
    return lt;
})

typedef struct {
    UA_UInt32 min;
    UA_UInt32 max;
} UA_NumericRangeDimension;

typedef struct  {
    size_t dimensionsSize;
    UA_NumericRangeDimension *dimensions;
} UA_NumericRange;

UA_StatusCode UA_EXPORT
UA_NumericRange_parse(UA_NumericRange *range, const UA_String str);

UA_INLINABLE(UA_NumericRange
             UA_NUMERICRANGE(const char *s), {
    UA_NumericRange nr;
    memset(&nr, 0, sizeof(nr)); 
    UA_NumericRange_parse(&nr, UA_STRING((char*)(uintptr_t)s));
    return nr;
})


struct UA_DataType;
typedef struct UA_DataType UA_DataType;

#define UA_EMPTY_ARRAY_SENTINEL ((void*)0x01)

typedef enum {
    UA_VARIANT_DATA,         
} UA_VariantStorageType;

typedef struct {
    const UA_DataType *type;      
    UA_VariantStorageType storageType;
    size_t arrayLength;           
    void *data;                   
    size_t arrayDimensionsSize;   
    UA_UInt32 *arrayDimensions;   
} UA_Variant;

UA_INLINABLE(UA_Boolean
             UA_Variant_isEmpty(const UA_Variant *v), {
    return v->type == NULL;
})

UA_INLINABLE(UA_Boolean
             UA_Variant_isScalar(const UA_Variant *v), {
    return (v->arrayLength == 0 && v->data > UA_EMPTY_ARRAY_SENTINEL);
})

UA_INLINABLE(UA_Boolean
             UA_Variant_hasScalarType(const UA_Variant *v,
                                      const UA_DataType *type), {
    return UA_Variant_isScalar(v) && type == v->type;
})

UA_INLINABLE(UA_Boolean
             UA_Variant_hasArrayType(const UA_Variant *v,
                                     const UA_DataType *type), {
    return (!UA_Variant_isScalar(v)) && type == v->type;
})

void UA_EXPORT
UA_Variant_setScalar(UA_Variant *v, void * UA_RESTRICT p,
                     const UA_DataType *type);

UA_StatusCode UA_EXPORT
UA_Variant_setScalarCopy(UA_Variant *v, const void * UA_RESTRICT p,
                         const UA_DataType *type);

void UA_EXPORT
UA_Variant_setArray(UA_Variant *v, void * UA_RESTRICT array,
                    size_t arraySize, const UA_DataType *type);

UA_StatusCode UA_EXPORT
UA_Variant_setArrayCopy(UA_Variant *v, const void * UA_RESTRICT array,
                        size_t arraySize, const UA_DataType *type);

UA_StatusCode UA_EXPORT
UA_Variant_copyRange(const UA_Variant *src, UA_Variant * UA_RESTRICT dst,
                     const UA_NumericRange range);

UA_StatusCode UA_EXPORT
UA_Variant_setRange(UA_Variant *v, void * UA_RESTRICT array,
                    size_t arraySize, const UA_NumericRange range);

UA_StatusCode UA_EXPORT
UA_Variant_setRangeCopy(UA_Variant *v, const void * UA_RESTRICT array,
                        size_t arraySize, const UA_NumericRange range);

typedef enum {
    UA_EXTENSIONOBJECT_ENCODED_NOBODY     = 0,
    UA_EXTENSIONOBJECT_ENCODED_BYTESTRING = 1,
    UA_EXTENSIONOBJECT_ENCODED_XML        = 2,
    UA_EXTENSIONOBJECT_DECODED            = 3,
} UA_ExtensionObjectEncoding;

typedef struct {
    UA_ExtensionObjectEncoding encoding;
    union {
        struct {
            UA_NodeId typeId;   
            UA_ByteString body; 
        } encoded;
        struct {
            const UA_DataType *type;
            void *data;
        } decoded;
    } content;
} UA_ExtensionObject;

void UA_EXPORT
UA_ExtensionObject_setValue(UA_ExtensionObject *eo,
                            void * UA_RESTRICT p,
                            const UA_DataType *type);

void UA_EXPORT
UA_ExtensionObject_setValueNoDelete(UA_ExtensionObject *eo,
                                    void * UA_RESTRICT p,
                                    const UA_DataType *type);

UA_StatusCode UA_EXPORT
UA_ExtensionObject_setValueCopy(UA_ExtensionObject *eo,
                                void * UA_RESTRICT p,
                                const UA_DataType *type);

typedef struct {
    UA_Variant    value;
    UA_DateTime   sourceTimestamp;
    UA_DateTime   serverTimestamp;
    UA_UInt16     sourcePicoseconds;
    UA_UInt16     serverPicoseconds;
    UA_StatusCode status;
    UA_Boolean    hasValue             : 1;
    UA_Boolean    hasStatus            : 1;
    UA_Boolean    hasSourceTimestamp   : 1;
    UA_Boolean    hasServerTimestamp   : 1;
    UA_Boolean    hasSourcePicoseconds : 1;
    UA_Boolean    hasServerPicoseconds : 1;
} UA_DataValue;

UA_StatusCode UA_EXPORT
UA_DataValue_copyVariantRange(const UA_DataValue *src, UA_DataValue * UA_RESTRICT dst,
                              const UA_NumericRange range);

typedef struct UA_DiagnosticInfo {
    UA_Boolean    hasSymbolicId          : 1;
    UA_Boolean    hasNamespaceUri        : 1;
    UA_Boolean    hasLocalizedText       : 1;
    UA_Boolean    hasLocale              : 1;
    UA_Boolean    hasAdditionalInfo      : 1;
    UA_Boolean    hasInnerStatusCode     : 1;
    UA_Boolean    hasInnerDiagnosticInfo : 1;
    UA_Int32      symbolicId;
    UA_Int32      namespaceUri;
    UA_Int32      localizedText;
    UA_Int32      locale;
    UA_String     additionalInfo;
    UA_StatusCode innerStatusCode;
    struct UA_DiagnosticInfo *innerDiagnosticInfo;
} UA_DiagnosticInfo;


typedef struct {
#ifdef UA_ENABLE_TYPEDESCRIPTION
    const char *memberName;       
#endif
    const UA_DataType *memberType;
    UA_Byte isArray    : 1;       
    UA_Byte isOptional : 1;       
} UA_DataTypeMember;

#define UA_DATATYPEKINDS 31
typedef enum {
    UA_DATATYPEKIND_BOOLEAN = 0,
    UA_DATATYPEKIND_SBYTE = 1,
    UA_DATATYPEKIND_BYTE = 2,
    UA_DATATYPEKIND_INT16 = 3,
    UA_DATATYPEKIND_UINT16 = 4,
    UA_DATATYPEKIND_INT32 = 5,
    UA_DATATYPEKIND_UINT32 = 6,
    UA_DATATYPEKIND_INT64 = 7,
    UA_DATATYPEKIND_UINT64 = 8,
    UA_DATATYPEKIND_FLOAT = 9,
    UA_DATATYPEKIND_DOUBLE = 10,
    UA_DATATYPEKIND_STRING = 11,
    UA_DATATYPEKIND_DATETIME = 12,
    UA_DATATYPEKIND_GUID = 13,
    UA_DATATYPEKIND_BYTESTRING = 14,
    UA_DATATYPEKIND_XMLELEMENT = 15,
    UA_DATATYPEKIND_NODEID = 16,
    UA_DATATYPEKIND_EXPANDEDNODEID = 17,
    UA_DATATYPEKIND_STATUSCODE = 18,
    UA_DATATYPEKIND_QUALIFIEDNAME = 19,
    UA_DATATYPEKIND_LOCALIZEDTEXT = 20,
    UA_DATATYPEKIND_EXTENSIONOBJECT = 21,
    UA_DATATYPEKIND_DATAVALUE = 22,
    UA_DATATYPEKIND_VARIANT = 23,
    UA_DATATYPEKIND_DIAGNOSTICINFO = 24,
    UA_DATATYPEKIND_DECIMAL = 25,
    UA_DATATYPEKIND_ENUM = 26,
    UA_DATATYPEKIND_STRUCTURE = 27,
    UA_DATATYPEKIND_OPTSTRUCT = 28, 
    UA_DATATYPEKIND_UNION = 29,
    UA_DATATYPEKIND_BITFIELDCLUSTER = 30 
} UA_DataTypeKind;

struct UA_DataType {
#ifdef UA_ENABLE_TYPEDESCRIPTION
    const char *typeName;
#endif
    UA_NodeId typeId;           
    UA_NodeId binaryEncodingId; 
    //UA_NodeId xmlEncodingId;  
    UA_UInt32 memSize     : 16; 
    UA_UInt32 typeKind    : 6;  
    UA_UInt32 membersSize : 8;  
    UA_DataTypeMember *members;
};

typedef struct UA_DataTypeArray {
    const struct UA_DataTypeArray *next;
    const size_t typesSize;
    const UA_DataType *types;
} UA_DataTypeArray;

#ifdef UA_ENABLE_TYPEDESCRIPTION
UA_Boolean
UA_DataType_getStructMember(const UA_DataType *type,
                            const char *memberName,
                            size_t *outOffset,
                            const UA_DataType **outMemberType,
                            UA_Boolean *outIsArray);
#endif

UA_Boolean
UA_DataType_isNumeric(const UA_DataType *type);


const UA_DataType UA_EXPORT *
UA_findDataType(const UA_NodeId *typeId);


const UA_DataType UA_EXPORT *
UA_findDataTypeWithCustom(const UA_NodeId *typeId,
                          const UA_DataTypeArray *customTypes);



void UA_EXPORT * UA_new(const UA_DataType *type) UA_FUNC_ATTR_MALLOC;

UA_INLINABLE(void
             UA_init(void *p, const UA_DataType *type), {
    memset(p, 0, type->memSize);
})

UA_StatusCode UA_EXPORT
UA_copy(const void *src, void *dst, const UA_DataType *type);

void UA_EXPORT UA_clear(void *p, const UA_DataType *type);

void UA_EXPORT UA_delete(void *p, const UA_DataType *type);

#ifdef UA_ENABLE_JSON_ENCODING
UA_StatusCode UA_EXPORT
UA_print(const void *p, const UA_DataType *type, UA_String *output);
#endif

UA_Order UA_EXPORT
UA_order(const void *p1, const void *p2, const UA_DataType *type);


UA_INLINABLE(UA_Boolean
             UA_equal(const void *p1, const void *p2, const UA_DataType *type), {
    return (UA_order(p1, p2, type) == UA_ORDER_EQ);
})


UA_EXPORT size_t
UA_calcSizeBinary(const void *p, const UA_DataType *type);

UA_EXPORT UA_StatusCode
UA_encodeBinary(const void *p, const UA_DataType *type,
                UA_ByteString *outBuf);

typedef struct {
    
    const UA_DataTypeArray *customTypes;

    void *callocContext;
    void * (*calloc)(void *callocContext, size_t nelem, size_t elsize);
} UA_DecodeBinaryOptions;

UA_EXPORT UA_StatusCode
UA_decodeBinary(const UA_ByteString *inBuf,
                void *p, const UA_DataType *type,
                const UA_DecodeBinaryOptions *options);


#ifdef UA_ENABLE_JSON_ENCODING

typedef struct {
    const UA_String *namespaces;
    size_t namespacesSize;
    const UA_String *serverUris;
    size_t serverUrisSize;
    UA_Boolean useReversible;

    UA_Boolean prettyPrint;   


    UA_Boolean unquotedKeys;  
    UA_Boolean stringNodeIds; 
} UA_EncodeJsonOptions;

UA_EXPORT size_t
UA_calcSizeJson(const void *src, const UA_DataType *type,
                const UA_EncodeJsonOptions *options);

UA_StatusCode UA_EXPORT
UA_encodeJson(const void *src, const UA_DataType *type, UA_ByteString *outBuf,
              const UA_EncodeJsonOptions *options);

typedef struct {
    const UA_String *namespaces;
    size_t namespacesSize;
    const UA_String *serverUris;
    size_t serverUrisSize;
} UA_DecodeJsonOptions;

UA_StatusCode UA_EXPORT
UA_decodeJson(const UA_ByteString *src, void *dst, const UA_DataType *type,
              const UA_DecodeJsonOptions *options);

#endif 


#ifdef UA_ENABLE_XML_ENCODING

typedef struct {
    UA_Boolean prettyPrint;   
} UA_EncodeXmlOptions;

UA_EXPORT size_t
UA_calcSizeXml(const void *src, const UA_DataType *type,
               const UA_EncodeXmlOptions *options);

UA_StatusCode UA_EXPORT
UA_encodeXml(const void *src, const UA_DataType *type, UA_ByteString *outBuf,
             const UA_EncodeXmlOptions *options);

typedef struct {
} UA_DecodeXmlOptions;

UA_StatusCode UA_EXPORT
UA_decodeXml(const UA_ByteString *src, void *dst, const UA_DataType *type,
             const UA_DecodeXmlOptions *options);

#endif 


void UA_EXPORT *
UA_Array_new(size_t size, const UA_DataType *type) UA_FUNC_ATTR_MALLOC;

UA_StatusCode UA_EXPORT
UA_Array_copy(const void *src, size_t size, void **dst,
              const UA_DataType *type) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

UA_StatusCode UA_EXPORT
UA_Array_resize(void **p, size_t *size, size_t newSize,
                const UA_DataType *type) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

UA_StatusCode UA_EXPORT
UA_Array_append(void **p, size_t *size, void *newElem,
                const UA_DataType *type) UA_FUNC_ATTR_WARN_UNUSED_RESULT;


UA_StatusCode UA_EXPORT
UA_Array_appendCopy(void **p, size_t *size, const void *newElem,
                    const UA_DataType *type) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

void UA_EXPORT
UA_Array_delete(void *p, size_t size, const UA_DataType *type);




#ifdef UA_ENABLE_TYPEDESCRIPTION
# define UA_TYPENAME(name) name,
#else
# define UA_TYPENAME(name)
#endif

#include <opcua/types_generated.h>

_UA_END_DECLS

#endif 
