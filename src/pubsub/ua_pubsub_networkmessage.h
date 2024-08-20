
#ifndef UA_PUBSUB_NETWORKMESSAGE_H_
#define UA_PUBSUB_NETWORKMESSAGE_H_

#include <opcua/types.h>
#include <opcua/types_generated.h>
#include <opcua/plugin/securitypolicy.h>
#include <opcua/pubsub.h>
#include <opcua/server_pubsub.h>

#include "../ua_types_encoding_binary.h"

#ifdef UA_ENABLE_PUBSUB

_UA_BEGIN_DECLS






typedef enum {
    UA_PUBSUB_OFFSETTYPE_DATASETMESSAGE_SEQUENCENUMBER,
    UA_PUBSUB_OFFSETTYPE_NETWORKMESSAGE_SEQUENCENUMBER,
    UA_PUBSUB_OFFSETTYPE_NETWORKMESSAGE_FIELDENCDODING,
    UA_PUBSUB_OFFSETTYPE_TIMESTAMP_PICOSECONDS,
    UA_PUBSUB_OFFSETTYPE_TIMESTAMP,     
    UA_PUBSUB_OFFSETTYPE_TIMESTAMP_NOW, 
    UA_PUBSUB_OFFSETTYPE_PAYLOAD_DATAVALUE,
    UA_PUBSUB_OFFSETTYPE_PAYLOAD_DATAVALUE_EXTERNAL,
    UA_PUBSUB_OFFSETTYPE_PAYLOAD_VARIANT,
    UA_PUBSUB_OFFSETTYPE_PAYLOAD_VARIANT_EXTERNAL,
    UA_PUBSUB_OFFSETTYPE_PAYLOAD_RAW,
    UA_PUBSUB_OFFSETTYPE_PAYLOAD_RAW_EXTERNAL,
    
    UA_PUBSUB_OFFSETTYPE_PUBLISHERID,
    UA_PUBSUB_OFFSETTYPE_WRITERGROUPID,
    UA_PUBSUB_OFFSETTYPE_DATASETWRITERID
    
} UA_NetworkMessageOffsetType;

typedef struct {
    UA_NetworkMessageOffsetType contentType;
    union {
        UA_UInt16 sequenceNumber;
        UA_DataValue **externalValue;
        UA_DataValue value;
    } content;
    size_t offset;
} UA_NetworkMessageOffset;

typedef struct {
    UA_ByteString buffer; 
    UA_NetworkMessageOffset *offsets; 
    size_t offsetsSize;
    UA_NetworkMessage *nm; 
    size_t rawMessageLength;
    UA_Byte *payloadPosition; 
} UA_NetworkMessageOffsetBuffer;

void
UA_NetworkMessageOffsetBuffer_clear(UA_NetworkMessageOffsetBuffer *nmob);

UA_StatusCode
UA_NetworkMessage_updateBufferedMessage(UA_NetworkMessageOffsetBuffer *buffer);

UA_StatusCode
UA_NetworkMessage_updateBufferedNwMessage(Ctx *ctx, UA_NetworkMessageOffsetBuffer *buffer);

size_t
UA_NetworkMessage_calcSizeBinaryWithOffsetBuffer(
    const UA_NetworkMessage *p, UA_NetworkMessageOffsetBuffer *offsetBuffer);


UA_StatusCode
UA_DataSetMessageHeader_encodeBinary(const UA_DataSetMessageHeader *src,
                                     UA_Byte **bufPos, const UA_Byte *bufEnd);

UA_StatusCode
UA_DataSetMessageHeader_decodeBinary(Ctx *ctx, UA_DataSetMessageHeader *dst);

UA_StatusCode
UA_DataSetMessage_encodeBinary(const UA_DataSetMessage *src, UA_Byte **bufPos,
                               const UA_Byte *bufEnd);

UA_StatusCode
UA_DataSetMessage_decodeBinary(Ctx *ctx, UA_DataSetMessage *dst, UA_UInt16 dsmSize);

size_t
UA_DataSetMessage_calcSizeBinary(UA_DataSetMessage *p,
                                 UA_NetworkMessageOffsetBuffer *offsetBuffer,
                                 size_t currentOffset);

void UA_DataSetMessage_clear(UA_DataSetMessage *p);


UA_StatusCode
UA_NetworkMessage_encodeHeaders(const UA_NetworkMessage *src,
                               UA_Byte **bufPos, const UA_Byte *bufEnd);

UA_StatusCode
UA_NetworkMessage_encodePayload(const UA_NetworkMessage *src,
                               UA_Byte **bufPos, const UA_Byte *bufEnd);

UA_StatusCode
UA_NetworkMessage_encodeFooters(const UA_NetworkMessage *src,
                               UA_Byte **bufPos, const UA_Byte *bufEnd);


UA_StatusCode
UA_NetworkMessage_decodeHeaders(Ctx *ctx, UA_NetworkMessage *dst);

UA_StatusCode
UA_NetworkMessage_decodePayload(Ctx *ctx, UA_NetworkMessage *dst);

UA_StatusCode
UA_NetworkMessage_decodeFooters(Ctx *ctx, UA_NetworkMessage *dst);
                          
UA_StatusCode
UA_NetworkMessage_encodeJsonInternal(const UA_NetworkMessage *src,
                                     UA_Byte **bufPos, const UA_Byte **bufEnd,
                                     UA_String *namespaces, size_t namespaceSize,
                                     UA_String *serverUris, size_t serverUriSize,
                                     UA_Boolean useReversible);

size_t
UA_NetworkMessage_calcSizeJsonInternal(const UA_NetworkMessage *src,
                                       UA_String *namespaces, size_t namespaceSize,
                                       UA_String *serverUris, size_t serverUriSize,
                                       UA_Boolean useReversible);

UA_StatusCode
UA_NetworkMessage_encodeBinaryWithEncryptStart(const UA_NetworkMessage* src,
                                               UA_Byte **bufPos, const UA_Byte *bufEnd,
                                               UA_Byte **dataToEncryptStart);

UA_StatusCode
UA_NetworkMessage_signEncrypt(UA_NetworkMessage *nm, UA_MessageSecurityMode securityMode,
                              UA_PubSubSecurityPolicy *policy, void *policyContext,
                              UA_Byte *messageStart, UA_Byte *encryptStart,
                              UA_Byte *sigStart);

_UA_END_DECLS

#endif 

#endif 
