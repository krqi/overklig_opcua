
#ifndef UA_HELPER_H_
#define UA_HELPER_H_

#include <opcua/types.h>
#include <opcua/plugin/log.h>

_UA_BEGIN_DECLS


typedef struct {
    UA_UInt32 min;
    UA_UInt32 max;
} UA_UInt32Range;

typedef struct {
    UA_Duration min;
    UA_Duration max;
} UA_DurationRange;

typedef struct {
    const UA_Logger *logger;
} UA_EventFilterParserOptions;

#ifdef UA_ENABLE_PARSING
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
UA_EXPORT UA_StatusCode
UA_EventFilter_parse(UA_EventFilter *filter, UA_ByteString content,
                     UA_EventFilterParserOptions *options);
#endif
#endif



void UA_EXPORT
UA_random_seed(UA_UInt64 seed);

UA_UInt32 UA_EXPORT
UA_UInt32_random(void); 

UA_Guid UA_EXPORT
UA_Guid_random(void);   


typedef struct {
    size_t mapSize;
    UA_KeyValuePair *map;
} UA_KeyValueMap;

UA_EXPORT extern const UA_KeyValueMap UA_KEYVALUEMAP_NULL;

UA_EXPORT UA_KeyValueMap *
UA_KeyValueMap_new(void);

UA_EXPORT void
UA_KeyValueMap_clear(UA_KeyValueMap *map);

UA_EXPORT void
UA_KeyValueMap_delete(UA_KeyValueMap *map);


UA_EXPORT UA_Boolean
UA_KeyValueMap_isEmpty(const UA_KeyValueMap *map);


UA_EXPORT UA_Boolean
UA_KeyValueMap_contains(const UA_KeyValueMap *map, const UA_QualifiedName key);

UA_EXPORT UA_StatusCode
UA_KeyValueMap_set(UA_KeyValueMap *map,
                   const UA_QualifiedName key,
                   const UA_Variant *value);

UA_EXPORT UA_StatusCode
UA_KeyValueMap_setScalar(UA_KeyValueMap *map,
                         const UA_QualifiedName key,
                         void * UA_RESTRICT p,
                         const UA_DataType *type);


UA_EXPORT const UA_Variant *
UA_KeyValueMap_get(const UA_KeyValueMap *map,
                   const UA_QualifiedName key);

UA_EXPORT const void *
UA_KeyValueMap_getScalar(const UA_KeyValueMap *map,
                         const UA_QualifiedName key,
                         const UA_DataType *type);


UA_EXPORT UA_StatusCode
UA_KeyValueMap_remove(UA_KeyValueMap *map,
                      const UA_QualifiedName key);


UA_EXPORT UA_StatusCode
UA_KeyValueMap_copy(const UA_KeyValueMap *src, UA_KeyValueMap *dst);

UA_EXPORT UA_StatusCode
UA_KeyValueMap_merge(UA_KeyValueMap *lhs, const UA_KeyValueMap *rhs);


typedef struct {
    UA_UInt32 protocolVersion;
    UA_UInt32 recvBufferSize;
    UA_UInt32 sendBufferSize;
    UA_UInt32 localMaxMessageSize;  
    UA_UInt32 remoteMaxMessageSize; 
    UA_UInt32 localMaxChunkCount;   
    UA_UInt32 remoteMaxChunkCount;  
} UA_ConnectionConfig;


UA_EXPORT extern const UA_VariableAttributes UA_VariableAttributes_default;
UA_EXPORT extern const UA_VariableTypeAttributes UA_VariableTypeAttributes_default;


UA_EXPORT extern const UA_MethodAttributes UA_MethodAttributes_default;


UA_EXPORT extern const UA_ObjectAttributes UA_ObjectAttributes_default;
UA_EXPORT extern const UA_ObjectTypeAttributes UA_ObjectTypeAttributes_default;
UA_EXPORT extern const UA_ReferenceTypeAttributes UA_ReferenceTypeAttributes_default;
UA_EXPORT extern const UA_DataTypeAttributes UA_DataTypeAttributes_default;
UA_EXPORT extern const UA_ViewAttributes UA_ViewAttributes_default;


UA_StatusCode UA_EXPORT
UA_parseEndpointUrl(const UA_String *endpointUrl, UA_String *outHostname,
                    UA_UInt16 *outPort, UA_String *outPath);

UA_StatusCode UA_EXPORT
UA_parseEndpointUrlEthernet(const UA_String *endpointUrl, UA_String *target,
                            UA_UInt16 *vid, UA_Byte *pcp);

size_t UA_EXPORT
UA_readNumber(const UA_Byte *buf, size_t buflen, UA_UInt32 *number);


size_t UA_EXPORT
UA_readNumberWithBase(const UA_Byte *buf, size_t buflen,
                      UA_UInt32 *number, UA_Byte base);

#ifndef UA_MIN
#define UA_MIN(A, B) ((A) > (B) ? (B) : (A))
#endif

#ifndef UA_MAX
#define UA_MAX(A, B) ((A) > (B) ? (A) : (B))
#endif


#ifdef UA_ENABLE_PARSING
UA_EXPORT UA_StatusCode
UA_RelativePath_parse(UA_RelativePath *rp, const UA_String str);

UA_EXPORT UA_StatusCode
UA_RelativePath_parseWithServer(UA_Server *server, UA_RelativePath *rp,
                                const UA_String str);

UA_EXPORT UA_StatusCode
UA_RelativePath_print(const UA_RelativePath *rp, UA_String *out);
#endif


#ifdef UA_ENABLE_PARSING
UA_EXPORT UA_StatusCode
UA_SimpleAttributeOperand_parse(UA_SimpleAttributeOperand *sao,
                                const UA_String str);

UA_EXPORT UA_StatusCode
UA_SimpleAttributeOperand_print(const UA_SimpleAttributeOperand *sao,
                                UA_String *out);
#endif

#define UA_PRINTF_GUID_FORMAT "%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 \
    "-%02" PRIx8 "%02" PRIx8 "-%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8
#define UA_PRINTF_GUID_DATA(GUID) (GUID).data1, (GUID).data2, (GUID).data3, \
        (GUID).data4[0], (GUID).data4[1], (GUID).data4[2], (GUID).data4[3], \
        (GUID).data4[4], (GUID).data4[5], (GUID).data4[6], (GUID).data4[7]

#define UA_PRINTF_STRING_FORMAT "\"%.*s\""
#define UA_PRINTF_STRING_DATA(STRING) (int)(STRING).length, (STRING).data


UA_EXPORT UA_Boolean
UA_constantTimeEqual(const void *ptr1, const void *ptr2, size_t length);

UA_EXPORT void
UA_ByteString_memZero(UA_ByteString *bs);



UA_EXPORT UA_StatusCode
UA_TrustListDataType_add(const UA_TrustListDataType *src, UA_TrustListDataType *dst);

UA_EXPORT UA_StatusCode
UA_TrustListDataType_remove(const UA_TrustListDataType *src, UA_TrustListDataType *dst);

UA_EXPORT UA_Boolean
UA_TrustListDataType_contains(const UA_TrustListDataType *trustList,
                              const UA_ByteString *certificate,
                              UA_TrustListMasks mask);


UA_EXPORT UA_UInt32
UA_TrustListDataType_getSize(const UA_TrustListDataType *trustList);

_UA_END_DECLS

#endif 
