
#ifndef UA_SESSION_H_
#define UA_SESSION_H_

#include <opcua/util.h>

#include "ua_securechannel.h"

_UA_BEGIN_DECLS

#define UA_MAXCONTINUATIONPOINTS 5

struct ContinuationPoint;
typedef struct ContinuationPoint ContinuationPoint;


ContinuationPoint *
ContinuationPoint_clear(ContinuationPoint *cp);

struct UA_Subscription;
typedef struct UA_Subscription UA_Subscription;

#ifdef UA_ENABLE_SUBSCRIPTIONS
typedef struct UA_PublishResponseEntry {
    SIMPLEQ_ENTRY(UA_PublishResponseEntry) listEntry;
    UA_UInt32 requestId;
    UA_DateTime maxTime; 
    UA_PublishResponse response;
} UA_PublishResponseEntry;
#endif

struct UA_Session {
    UA_Session *next; 
    UA_SecureChannel *channel; 

    UA_NodeId sessionId;
    UA_NodeId authenticationToken;
    UA_String sessionName;
    UA_Boolean activated;


    UA_ByteString serverNonce;

    UA_ApplicationDescription clientDescription;
    UA_String clientUserIdOfSession;
    UA_Double timeout; 
    UA_DateTime validTill;

    UA_KeyValueMap *attributes;

    
    UA_UInt32 maxRequestMessageSize;
    UA_UInt32 maxResponseMessageSize;

    UA_UInt16         availableContinuationPoints;
    ContinuationPoint *continuationPoints;

    
    size_t localeIdsSize;
    UA_String *localeIds;

#ifdef UA_ENABLE_SUBSCRIPTIONS
    size_t subscriptionsSize;
    TAILQ_HEAD(, UA_Subscription) subscriptions;

    size_t responseQueueSize;
    SIMPLEQ_HEAD(, UA_PublishResponseEntry) responseQueue;

    size_t totalRetransmissionQueueSize; 
#endif

#ifdef UA_ENABLE_DIAGNOSTICS
    UA_SessionSecurityDiagnosticsDataType securityDiagnostics;
    UA_SessionDiagnosticsDataType diagnostics;
#endif
};


void UA_Session_init(UA_Session *session);
void UA_Session_clear(UA_Session *session, UA_Server *server);
void UA_Session_attachToSecureChannel(UA_Session *session, UA_SecureChannel *channel);
void UA_Session_detachFromSecureChannel(UA_Session *session);
UA_StatusCode UA_Session_generateNonce(UA_Session *session);


void UA_Session_updateLifetime(UA_Session *session, UA_DateTime now,
                               UA_DateTime nowMonotonic);


#ifdef UA_ENABLE_SUBSCRIPTIONS

void
UA_Session_attachSubscription(UA_Session *session, UA_Subscription *sub);

void
UA_Session_detachSubscription(UA_Server *server, UA_Session *session,
                              UA_Subscription *sub, UA_Boolean releasePublishResponses);

UA_Subscription *
UA_Session_getSubscriptionById(UA_Session *session,
                               UA_UInt32 subscriptionId);


void
UA_Session_queuePublishReq(UA_Session *session,
                           UA_PublishResponseEntry* entry,
                           UA_Boolean head);

UA_PublishResponseEntry *
UA_Session_dequeuePublishReq(UA_Session *session);

#endif


#define UA_LOG_SESSION_INTERNAL(LOGGER, LEVEL, SESSION, MSG, ...)       \
    if(UA_LOGLEVEL <= UA_LOGLEVEL_##LEVEL) {                            \
        UA_String sessionName = (SESSION) ? (SESSION)->sessionName: UA_STRING_NULL; \
        unsigned long sockId = ((SESSION) && (SESSION)->channel) ?      \
            (unsigned long)(SESSION)->channel->connectionId : 0;        \
        UA_UInt32 chanId = ((SESSION) && (SESSION)->channel) ?          \
            (SESSION)->channel->securityToken.channelId : 0;            \
        UA_LOG_##LEVEL(LOGGER, UA_LOGCATEGORY_SESSION,                  \
                       "TCP %lu\t| SC %" PRIu32 "\t| Session \"%S\"\t| " MSG "%.0s", \
                       sockId, chanId, sessionName, __VA_ARGS__);   \
    }

#define UA_LOG_TRACE_SESSION(LOGGER, SESSION, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_SESSION_INTERNAL(LOGGER, TRACE, SESSION, __VA_ARGS__, ""))
#define UA_LOG_DEBUG_SESSION(LOGGER, SESSION, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_SESSION_INTERNAL(LOGGER, DEBUG, SESSION, __VA_ARGS__, ""))
#define UA_LOG_INFO_SESSION(LOGGER, SESSION, ...)                       \
    UA_MACRO_EXPAND(UA_LOG_SESSION_INTERNAL(LOGGER, INFO, SESSION, __VA_ARGS__, ""))
#define UA_LOG_WARNING_SESSION(LOGGER, SESSION, ...)                    \
    UA_MACRO_EXPAND(UA_LOG_SESSION_INTERNAL(LOGGER, WARNING, SESSION, __VA_ARGS__, ""))
#define UA_LOG_ERROR_SESSION(LOGGER, SESSION, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_SESSION_INTERNAL(LOGGER, ERROR, SESSION, __VA_ARGS__, ""))
#define UA_LOG_FATAL_SESSION(LOGGER, SESSION, ...)                      \
    UA_MACRO_EXPAND(UA_LOG_SESSION_INTERNAL(LOGGER, FATAL, SESSION, __VA_ARGS__, ""))

_UA_END_DECLS

#endif 
