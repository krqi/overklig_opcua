
#ifndef UA_SUBSCRIPTION_H_
#define UA_SUBSCRIPTION_H_

#include <opcua/types.h>
#include <opcua/types_generated.h>
#include <opcua/plugin/nodestore.h>

#include "ua_session.h"
#include "util/ua_util_internal.h"

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_SUBSCRIPTIONS







#define UA_SUBSCRIPTION_QUEUE_SENTINEL ((UA_Notification*)0x01)

typedef struct UA_Notification {
    TAILQ_ENTRY(UA_Notification) subEntry; 
    TAILQ_ENTRY(UA_Notification) monEntry; 
    UA_MonitoredItem *mon; 

    
    union {
        UA_MonitoredItemNotification dataChange;
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
        UA_EventFieldList event;
#endif
    } data;

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    UA_Boolean isOverflowEvent; 
#endif
} UA_Notification;

UA_Notification * UA_Notification_new(void);

void UA_Notification_enqueueAndTrigger(UA_Server *server,
                                       UA_Notification *n);

typedef struct UA_NotificationMessageEntry {
    TAILQ_ENTRY(UA_NotificationMessageEntry) listEntry;
    UA_NotificationMessage message;
} UA_NotificationMessageEntry;


typedef TAILQ_HEAD(NotificationQueue, UA_Notification) NotificationQueue;
typedef TAILQ_HEAD(NotificationMessageQueue, UA_NotificationMessageEntry)
    NotificationMessageQueue;





typedef enum {
    UA_MONITOREDITEMSAMPLINGTYPE_NONE = 0,
    UA_MONITOREDITEMSAMPLINGTYPE_CYCLIC, 
    UA_MONITOREDITEMSAMPLINGTYPE_PUBLISH 
} UA_MonitoredItemSamplingType;

struct UA_MonitoredItem {
    UA_DelayedCallback delayedFreePointers;
    LIST_ENTRY(UA_MonitoredItem) listEntry; 
    UA_Subscription *subscription;          
    UA_UInt32 monitoredItemId;

    
    UA_ReadValueId itemToMonitor;
    UA_MonitoringMode monitoringMode;
    UA_TimestampsToReturn timestampsToReturn;
    UA_Boolean registered;       

    UA_MonitoringParameters parameters;

    
    UA_MonitoredItemSamplingType samplingType;
    union {
        UA_UInt64 callbackId;
        UA_MonitoredItem *nodeListNext; 
    } sampling;
    UA_DataValue lastValue;

    
    size_t triggeringLinksSize;
    UA_UInt32 *triggeringLinks;

    
    NotificationQueue queue;
};

void UA_MonitoredItem_init(UA_MonitoredItem *mon);
void UA_MonitoredItem_delete(UA_Server *server, UA_MonitoredItem *mon);
void UA_MonitoredItem_removeOverflowInfoBits(UA_MonitoredItem *mon);
void UA_Server_registerMonitoredItem(UA_Server *server, UA_MonitoredItem *mon);

UA_StatusCode
UA_MonitoredItem_registerSampling(UA_Server *server, UA_MonitoredItem *mon);

void
UA_MonitoredItem_unregisterSampling(UA_Server *server, UA_MonitoredItem *mon);

UA_StatusCode
UA_MonitoredItem_setMonitoringMode(UA_Server *server, UA_MonitoredItem *mon,
                                   UA_MonitoringMode monitoringMode);

void
UA_MonitoredItem_sample(UA_Server *server, UA_MonitoredItem *mon);


void
UA_MonitoredItem_processSampledValue(UA_Server *server, UA_MonitoredItem *mon,
                                     UA_DataValue *value);

UA_StatusCode
UA_MonitoredItem_removeLink(UA_Subscription *sub, UA_MonitoredItem *mon,
                            UA_UInt32 linkId);

UA_StatusCode
UA_MonitoredItem_addLink(UA_Subscription *sub, UA_MonitoredItem *mon,
                         UA_UInt32 linkId);

UA_StatusCode
UA_MonitoredItem_createDataChangeNotification(UA_Server *server, UA_MonitoredItem *mon,
                                              const UA_DataValue *value);

void UA_MonitoredItem_ensureQueueSpace(UA_Server *server, UA_MonitoredItem *mon);






typedef enum {
    UA_SUBSCRIPTIONSTATE_STOPPED = 0,
    UA_SUBSCRIPTIONSTATE_REMOVING,
    UA_SUBSCRIPTIONSTATE_ENABLED_NOPUBLISH, 
    UA_SUBSCRIPTIONSTATE_ENABLED
} UA_SubscriptionState;

struct UA_Subscription {
    UA_DelayedCallback delayedFreePointers;
    LIST_ENTRY(UA_Subscription) serverListEntry;
    TAILQ_ENTRY(UA_Subscription) sessionListEntry;
    UA_Session *session; 
    UA_UInt32 subscriptionId;

    
    UA_UInt32 lifeTimeCount;
    UA_UInt32 maxKeepAliveCount;
    UA_Double publishingInterval; 
    UA_UInt32 notificationsPerPublish;
    UA_Byte priority;

    
    UA_SubscriptionState state;
    UA_Boolean late;
    UA_UInt32 nextSequenceNumber;
    UA_UInt32 currentKeepAliveCount;
    UA_UInt32 currentLifetimeCount;

    
    UA_UInt64 publishCallbackId;

    
    UA_Boolean delayedCallbackRegistered;
    UA_DelayedCallback delayedMoreNotifications;

    
    UA_UInt32 lastMonitoredItemId; 
    LIST_HEAD(, UA_MonitoredItem) monitoredItems;
    UA_UInt32 monitoredItemsSize;

    LIST_HEAD(, UA_MonitoredItem) samplingMonitoredItems;

    
    TAILQ_HEAD(, UA_Notification) notificationQueue;
    UA_UInt32 notificationQueueSize; 
    UA_UInt32 dataChangeNotifications;
    UA_UInt32 eventNotifications;

    
    NotificationMessageQueue retransmissionQueue;
    size_t retransmissionQueueSize;

#ifdef UA_ENABLE_DIAGNOSTICS
    UA_NodeId ns0Id; 

    UA_UInt32 modifyCount;
    UA_UInt32 enableCount;
    UA_UInt32 disableCount;
    UA_UInt32 republishRequestCount;
    UA_UInt32 republishMessageCount;
    UA_UInt32 transferRequestCount;
    UA_UInt32 transferredToAltClientCount;
    UA_UInt32 transferredToSameClientCount;
    UA_UInt32 publishRequestCount;
    UA_UInt32 dataChangeNotificationsCount;
    UA_UInt32 eventNotificationsCount;
    UA_UInt32 notificationsCount;
    UA_UInt32 latePublishRequestCount;
    UA_UInt32 discardedMessageCount;
    UA_UInt32 monitoringQueueOverflowCount;
    UA_UInt32 eventQueueOverFlowCount;
#endif
};

UA_Subscription * UA_Subscription_new(void);

void
UA_Subscription_delete(UA_Server *server, UA_Subscription *sub);

UA_StatusCode
Subscription_setState(UA_Server *server, UA_Subscription *sub,
                      UA_SubscriptionState state);

void
Subscription_resetLifetime(UA_Subscription *sub);

UA_MonitoredItem *
UA_Subscription_getMonitoredItem(UA_Subscription *sub,
                                 UA_UInt32 monitoredItemId);

void
UA_Subscription_publish(UA_Server *server, UA_Subscription *sub);

void
UA_Subscription_localPublish(UA_Server *server, UA_Subscription *sub);

void
UA_Subscription_resendData(UA_Server *server, UA_Subscription *sub);

UA_StatusCode
UA_Subscription_removeRetransmissionMessage(UA_Subscription *sub,
                                            UA_UInt32 sequenceNumber);

void
UA_Session_ensurePublishQueueSpace(UA_Server *server, UA_Session *session);


struct UA_ConditionSource;
typedef struct UA_ConditionSource UA_ConditionSource;


#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS

#define UA_EVENTFILTER_MAXELEMENTS 64 
#define UA_EVENTFILTER_MAXOPERANDS 64 
#define UA_EVENTFILTER_MAXSELECT   64 

UA_StatusCode
UA_MonitoredItem_addEvent(UA_Server *server, UA_MonitoredItem *mon,
                          const UA_NodeId *event);

UA_StatusCode
generateEventId(UA_ByteString *generatedId);


UA_StatusCode
UA_SimpleAttributeOperandValidation(UA_Server *server,
                                    const UA_SimpleAttributeOperand *sao);


UA_ContentFilterElementResult
UA_ContentFilterElementValidation(UA_Server *server, size_t operatorIndex,
                                  size_t operatorsCount,
                                  const UA_ContentFilterElement *ef);


UA_StatusCode
evaluateWhereClause(UA_Server *server, UA_Session *session, const UA_NodeId *eventNode,
                    const UA_ContentFilter *contentFilter,
                    UA_ContentFilterResult *contentFilterResult);

#endif






#define UA_BOUNDEDVALUE_SETWBOUNDS(BOUNDS, SRC, DST) { \
        if(SRC > BOUNDS.max) DST = BOUNDS.max;         \
        else if(SRC < BOUNDS.min) DST = BOUNDS.min;    \
        else DST = SRC;                                \
    }

#define UA_LOG_SUBSCRIPTION_INTERNAL(LOGGER, LEVEL, SUB, MSG, ...)      \
    do {                                                                \
        if((SUB) && (SUB)->session) {                                   \
            UA_LOG_##LEVEL##_SESSION(LOGGER, (SUB)->session,            \
                                     "Subscription %" PRIu32 " | " MSG "%.0s", \
                                     (SUB)->subscriptionId, __VA_ARGS__); \
        } else {                                                        \
            UA_LOG_##LEVEL(LOGGER, UA_LOGCATEGORY_SERVER,               \
                           "Subscription %" PRIu32 " | " MSG "%.0s",    \
                           (SUB) ? (SUB)->subscriptionId : 0, __VA_ARGS__); \
        }                                                               \
    } while(0)

#if UA_LOGLEVEL <= 100
# define UA_LOG_TRACE_SUBSCRIPTION(LOGGER, SUB, ...)                     \
    UA_MACRO_EXPAND(UA_LOG_SUBSCRIPTION_INTERNAL(LOGGER, TRACE, SUB, __VA_ARGS__, ""))
#else
# define UA_LOG_TRACE_SUBSCRIPTION(LOGGER, SUB, ...) do {} while(0)
#endif

#if UA_LOGLEVEL <= 200
# define UA_LOG_DEBUG_SUBSCRIPTION(LOGGER, SUB, ...)                     \
    UA_MACRO_EXPAND(UA_LOG_SUBSCRIPTION_INTERNAL(LOGGER, DEBUG, SUB, __VA_ARGS__, ""))
#else
# define UA_LOG_DEBUG_SUBSCRIPTION(LOGGER, SUB, ...) do {} while(0)
#endif

#if UA_LOGLEVEL <= 300
# define UA_LOG_INFO_SUBSCRIPTION(LOGGER, SUB, ...)                     \
    UA_MACRO_EXPAND(UA_LOG_SUBSCRIPTION_INTERNAL(LOGGER, INFO, SUB, __VA_ARGS__, ""))
#else
# define UA_LOG_INFO_SUBSCRIPTION(LOGGER, SUB, ...) do {} while(0)
#endif

#if UA_LOGLEVEL <= 400
# define UA_LOG_WARNING_SUBSCRIPTION(LOGGER, SUB, ...)                     \
    UA_MACRO_EXPAND(UA_LOG_SUBSCRIPTION_INTERNAL(LOGGER, WARNING, SUB, __VA_ARGS__, ""))
#else
# define UA_LOG_WARNING_SUBSCRIPTION(LOGGER, SUB, ...) do {} while(0)
#endif

#if UA_LOGLEVEL <= 500
# define UA_LOG_ERROR_SUBSCRIPTION(LOGGER, SUB, ...)                     \
    UA_MACRO_EXPAND(UA_LOG_SUBSCRIPTION_INTERNAL(LOGGER, ERROR, SUB, __VA_ARGS__, ""))
#else
# define UA_LOG_ERROR_SUBSCRIPTION(LOGGER, SUB, ...) do {} while(0)
#endif

#if UA_LOGLEVEL <= 600
# define UA_LOG_FATAL_SUBSCRIPTION(LOGGER, SUB, ...)                     \
    UA_MACRO_EXPAND(UA_LOG_SUBSCRIPTION_INTERNAL(LOGGER, FATAL, SUB, __VA_ARGS__, ""))
#else
# define UA_LOG_FATAL_SUBSCRIPTION(LOGGER, SUB, ...) do {} while(0)
#endif

#endif 

_UA_END_DECLS

#endif 
