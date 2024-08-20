
#ifndef UA_SECURECHANNEL_H_
#define UA_SECURECHANNEL_H_

#include <opcua/util.h>
#include <opcua/types.h>
#include <opcua/plugin/log.h>
#include <opcua/plugin/securitypolicy.h>
#include <opcua/plugin/eventloop.h>
#include <opcua/transport_generated.h>

#include "opcua_queue.h"
#include "util/ua_util_internal.h"

_UA_BEGIN_DECLS

struct UA_SecureChannel;
typedef struct UA_SecureChannel UA_SecureChannel;

struct UA_Session;
typedef struct UA_Session UA_Session;


#define UA_SECURECHANNEL_MESSAGEHEADER_LENGTH 8
#define UA_SECURECHANNEL_CHANNELHEADER_LENGTH 12
#define UA_SECURECHANNEL_SYMMETRIC_SECURITYHEADER_LENGTH 4
#define UA_SECURECHANNEL_SEQUENCEHEADER_LENGTH 8
#define UA_SECURECHANNEL_SYMMETRIC_HEADER_UNENCRYPTEDLENGTH \
    (UA_SECURECHANNEL_CHANNELHEADER_LENGTH +                \
     UA_SECURECHANNEL_SYMMETRIC_SECURITYHEADER_LENGTH)
#define UA_SECURECHANNEL_SYMMETRIC_HEADER_TOTALLENGTH   \
    (UA_SECURECHANNEL_CHANNELHEADER_LENGTH +            \
    UA_SECURECHANNEL_SYMMETRIC_SECURITYHEADER_LENGTH +  \
     UA_SECURECHANNEL_SEQUENCEHEADER_LENGTH)


#define UA_SECURECHANNEL_MESSAGE_MIN_LENGTH 16


typedef struct UA_Chunk {
    SIMPLEQ_ENTRY(UA_Chunk) pointers;
    UA_ByteString bytes;
    UA_MessageType messageType;
    UA_ChunkType chunkType;
    UA_UInt32 requestId;
} UA_Chunk;

typedef SIMPLEQ_HEAD(UA_ChunkQueue, UA_Chunk) UA_ChunkQueue;

typedef enum {
    UA_SECURECHANNELRENEWSTATE_NORMAL,

    
    UA_SECURECHANNELRENEWSTATE_SENT,

    UA_SECURECHANNELRENEWSTATE_NEWTOKEN_SERVER,

    UA_SECURECHANNELRENEWSTATE_NEWTOKEN_CLIENT
} UA_SecureChannelRenewState;

struct UA_SecureChannel {
    UA_SecureChannelState state;
    UA_SecureChannelRenewState renewState;
    UA_MessageSecurityMode securityMode;
    UA_ShutdownReason shutdownReason;
    UA_ConnectionConfig config;

    UA_String endpointUrl;

    
    UA_ConnectionManager *connectionManager;
    uintptr_t connectionId;

    
    TAILQ_ENTRY(UA_SecureChannel) serverEntry;
    TAILQ_ENTRY(UA_SecureChannel) componentEntry;

    UA_ChannelSecurityToken securityToken;    

    
    const UA_SecurityPolicy *securityPolicy;
    void *channelContext; 

    
    UA_ByteString remoteCertificate;
    UA_Byte remoteCertificateThumbprint[20]; 

    UA_ByteString remoteNonce;
    UA_ByteString localNonce;

    UA_UInt32 receiveSequenceNumber;
    UA_UInt32 sendSequenceNumber;

    UA_Session *sessions;

    size_t decryptedChunksCount;
    size_t decryptedChunksLength;

    UA_CertificateGroup *certificateVerification;
    UA_StatusCode (*processOPNHeader)(void *application, UA_SecureChannel *channel,
                                      const UA_AsymmetricAlgorithmSecurityHeader *asymHeader);
};

void UA_SecureChannel_init(UA_SecureChannel *channel);


void UA_SecureChannel_shutdown(UA_SecureChannel *channel,
                               UA_ShutdownReason shutdownReason);

void UA_SecureChannel_clear(UA_SecureChannel *channel);

UA_StatusCode
UA_SecureChannel_processHELACK(UA_SecureChannel *channel,
                               const UA_TcpAcknowledgeMessage *remoteConfig);

UA_StatusCode
UA_SecureChannel_setSecurityPolicy(UA_SecureChannel *channel,
                                   const UA_SecurityPolicy *securityPolicy,
                                   const UA_ByteString *remoteCertificate);

UA_Boolean
UA_SecureChannel_isConnected(UA_SecureChannel *channel);

UA_Boolean
UA_SecureChannel_checkTimeout(UA_SecureChannel *channel,
                              UA_DateTime nowMonotonic);

void
UA_SecureChannel_sendError(UA_SecureChannel *channel, UA_TcpErrorMessage *error);


void
UA_SecureChannel_deleteBuffered(UA_SecureChannel *channel);

UA_StatusCode
UA_SecureChannel_generateLocalNonce(UA_SecureChannel *channel);

UA_StatusCode
UA_SecureChannel_generateLocalKeys(const UA_SecureChannel *channel);

UA_StatusCode
generateRemoteKeys(const UA_SecureChannel *channel);


UA_StatusCode
UA_SecureChannel_sendAsymmetricOPNMessage(UA_SecureChannel *channel, UA_UInt32 requestId,
                                          const void *content, const UA_DataType *contentType);

UA_StatusCode
UA_SecureChannel_sendSymmetricMessage(UA_SecureChannel *channel, UA_UInt32 requestId,
                                      UA_MessageType messageType, void *payload,
                                      const UA_DataType *payloadType);

typedef struct {
    UA_SecureChannel *channel;
    UA_UInt32 requestId;
    UA_UInt32 messageType;

    UA_UInt16 chunksSoFar;
    size_t messageSizeSoFar;

    UA_ByteString messageBuffer;
    UA_Byte *buf_pos;
    const UA_Byte *buf_end;

    UA_Boolean final;
} UA_MessageContext;


UA_StatusCode
UA_MessageContext_begin(UA_MessageContext *mc, UA_SecureChannel *channel,
                        UA_UInt32 requestId, UA_MessageType messageType);

UA_StatusCode
UA_MessageContext_encode(UA_MessageContext *mc, const void *content,
                         const UA_DataType *contentType);

UA_StatusCode
UA_MessageContext_finish(UA_MessageContext *mc);

void
UA_MessageContext_abort(UA_MessageContext *mc);


typedef UA_StatusCode
(UA_ProcessMessageCallback)(void *application, UA_SecureChannel *channel,
                            UA_MessageType messageType, UA_UInt32 requestId,
                            UA_ByteString *message);

UA_StatusCode
UA_SecureChannel_processBuffer(UA_SecureChannel *channel, void *application,
                               UA_ProcessMessageCallback callback,
                               const UA_ByteString *buffer,
                               UA_DateTime nowMonotonic);



void
hideBytesAsym(const UA_SecureChannel *channel, UA_Byte **buf_start,
              const UA_Byte **buf_end);

UA_StatusCode
decryptAndVerifyChunk(const UA_SecureChannel *channel,
                      const UA_SecurityPolicyCryptoModule *cryptoModule,
                      UA_MessageType messageType, UA_ByteString *chunk,
                      size_t offset);

size_t
calculateAsymAlgSecurityHeaderLength(const UA_SecureChannel *channel);

UA_StatusCode
prependHeadersAsym(UA_SecureChannel *const channel, UA_Byte *header_pos,
                   const UA_Byte *buf_end, size_t totalLength,
                   size_t securityHeaderLength, UA_UInt32 requestId,
                   size_t *const finalLength);

void
setBufPos(UA_MessageContext *mc);

UA_StatusCode
checkSymHeader(UA_SecureChannel *channel, const UA_UInt32 tokenId,
               UA_DateTime nowMonotonic);

UA_StatusCode
checkAsymHeader(UA_SecureChannel *channel,
                const UA_AsymmetricAlgorithmSecurityHeader *asymHeader);

void
padChunk(UA_SecureChannel *channel, const UA_SecurityPolicyCryptoModule *cm,
         const UA_Byte *start, UA_Byte **pos);

UA_StatusCode
signAndEncryptAsym(UA_SecureChannel *channel, size_t preSignLength,
                   UA_ByteString *buf, size_t securityHeaderLength,
                   size_t totalLength);

UA_StatusCode
signAndEncryptSym(UA_MessageContext *messageContext,
                  size_t preSigLength, size_t totalLength);


#define UA_LOG_CHANNEL_INTERNAL(LOGGER, LEVEL, CHANNEL, MSG, ...)       \
    if(UA_LOGLEVEL <= UA_LOGLEVEL_##LEVEL) {                            \
        UA_LOG_##LEVEL(LOGGER, UA_LOGCATEGORY_SECURECHANNEL,            \
                       "TCP %lu\t| SC %" PRIu32 "\t| " MSG "%.0s", \
                       (long unsigned)(CHANNEL)->connectionId,          \
                       (CHANNEL)->securityToken.channelId, __VA_ARGS__); \
    }

#define UA_LOG_TRACE_CHANNEL(LOGGER, CHANNEL, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_CHANNEL_INTERNAL(LOGGER, TRACE, CHANNEL, __VA_ARGS__, ""))
#define UA_LOG_DEBUG_CHANNEL(LOGGER, CHANNEL, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_CHANNEL_INTERNAL(LOGGER, DEBUG, CHANNEL, __VA_ARGS__, ""))
#define UA_LOG_INFO_CHANNEL(LOGGER, CHANNEL, ...)                       \
    UA_MACRO_EXPAND(UA_LOG_CHANNEL_INTERNAL(LOGGER, INFO, CHANNEL, __VA_ARGS__, ""))
#define UA_LOG_WARNING_CHANNEL(LOGGER, CHANNEL, ...)                    \
    UA_MACRO_EXPAND(UA_LOG_CHANNEL_INTERNAL(LOGGER, WARNING, CHANNEL, __VA_ARGS__, ""))
#define UA_LOG_ERROR_CHANNEL(LOGGER, CHANNEL, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_CHANNEL_INTERNAL(LOGGER, ERROR, CHANNEL, __VA_ARGS__, ""))
#define UA_LOG_FATAL_CHANNEL(LOGGER, CHANNEL, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_CHANNEL_INTERNAL(LOGGER, FATAL, CHANNEL, __VA_ARGS__, ""))

_UA_END_DECLS

#endif 
