
#ifndef UA_CLIENT_INTERNAL_H_
#define UA_CLIENT_INTERNAL_H_

#define UA_INTERNAL
#include <opcua/client.h>
#include <opcua/client_highlevel.h>
#include <opcua/client_subscriptions.h>

#include "opcua_queue.h"
#include "ua_securechannel.h"
#include "util/ua_util_internal.h"
#include "ziptree.h"

_UA_BEGIN_DECLS





typedef struct UA_Client_NotificationsAckNumber {
    LIST_ENTRY(UA_Client_NotificationsAckNumber) listEntry;
    UA_SubscriptionAcknowledgement subAck;
} UA_Client_NotificationsAckNumber;

typedef struct UA_Client_MonitoredItem {
    ZIP_ENTRY(UA_Client_MonitoredItem) zipfields;
    UA_UInt32 monitoredItemId;
    UA_UInt32 clientHandle;
    void *context;
    UA_Client_DeleteMonitoredItemCallback deleteCallback;
    union {
        UA_Client_DataChangeNotificationCallback dataChangeCallback;
        UA_Client_EventNotificationCallback eventCallback;
    } handler;
    UA_Boolean isEventMonitoredItem; 
} UA_Client_MonitoredItem;

ZIP_HEAD(MonitorItemsTree, UA_Client_MonitoredItem);
typedef struct MonitorItemsTree MonitorItemsTree;

typedef struct UA_Client_Subscription {
    LIST_ENTRY(UA_Client_Subscription) listEntry;
    UA_UInt32 subscriptionId;
    void *context;
    UA_Double publishingInterval;
    UA_UInt32 maxKeepAliveCount;
    UA_Client_StatusChangeNotificationCallback statusChangeCallback;
    UA_Client_DeleteSubscriptionCallback deleteCallback;
    UA_UInt32 sequenceNumber;
    UA_DateTime lastActivity;
    MonitorItemsTree monitoredItems;
} UA_Client_Subscription;

void
__Client_Subscriptions_clear(UA_Client *client);


UA_StatusCode
__Client_preparePublishRequest(UA_Client *client, UA_PublishRequest *request);

void
__Client_Subscriptions_backgroundPublish(UA_Client *client);

void
__Client_Subscriptions_backgroundPublishInactivityCheck(UA_Client *client);





typedef struct AsyncServiceCall {
    LIST_ENTRY(AsyncServiceCall) pointers;
    UA_UInt32 requestId;     
    UA_ClientAsyncServiceCallback callback;
    const UA_DataType *responseType;
    void *userdata;
    UA_DateTime start;
    UA_UInt32 timeout;
} AsyncServiceCall;

typedef LIST_HEAD(UA_AsyncServiceList, AsyncServiceCall) UA_AsyncServiceList;

void
__Client_AsyncService_removeAll(UA_Client *client, UA_StatusCode statusCode);

typedef struct CustomCallback {
    UA_UInt32 callbackId;

    UA_ClientAsyncServiceCallback userCallback;
    void *userData;

    void *clientData;
} CustomCallback;

struct UA_Client {
    UA_ClientConfig config;

    
    UA_UInt64 houseKeepingCallbackId;

    
    UA_StatusCode connectStatus;

    
    UA_SecureChannelState oldChannelState;
    UA_SessionState oldSessionState;
    UA_StatusCode oldConnectStatus;

    UA_Boolean findServersHandshake;   
    UA_Boolean endpointsHandshake;     

    UA_String discoveryUrl;

    UA_ApplicationDescription serverDescription;

    UA_RuleHandling allowAllCertificateUris;

    
    UA_SecureChannel channel;
    UA_UInt32 requestId; 
    UA_DateTime nextChannelRenewal;

    
    UA_SessionState sessionState;
    UA_NodeId authenticationToken;
    UA_ByteString serverSessionNonce;
    UA_ByteString clientSessionNonce;

    
    UA_DateTime lastConnectivityCheck;
    UA_Boolean pendingConnectivityCheck;

    
    UA_AsyncServiceList asyncServiceCalls;

    
    LIST_HEAD(, UA_Client_NotificationsAckNumber) pendingNotificationsAcks;
    LIST_HEAD(, UA_Client_Subscription) subscriptions;
    UA_UInt32 monitoredItemHandles;
    UA_UInt16 currentlyOutStandingPublishRequests;

#if UA_MULTITHREADING >= 100
    UA_Lock clientMutex;
#endif
};

UA_StatusCode
__Client_AsyncService(UA_Client *client, const void *request,
                      const UA_DataType *requestType,
                      UA_ClientAsyncServiceCallback callback,
                      const UA_DataType *responseType,
                      void *userdata, UA_UInt32 *requestId);

void
__Client_Service(UA_Client *client, const void *request,
                 const UA_DataType *requestType, void *response,
                 const UA_DataType *responseType);

UA_StatusCode
__UA_Client_startup(UA_Client *client);

UA_StatusCode
__Client_renewSecureChannel(UA_Client *client);

UA_StatusCode
processServiceResponse(void *application, UA_SecureChannel *channel,
                       UA_MessageType messageType, UA_UInt32 requestId,
                       UA_ByteString *message);

UA_StatusCode connectInternal(UA_Client *client, UA_Boolean async);
UA_StatusCode connectSecureChannel(UA_Client *client, const char *endpointUrl);
UA_Boolean isFullyConnected(UA_Client *client);
void connectSync(UA_Client *client);
void notifyClientState(UA_Client *client);
void processRHEMessage(UA_Client *client, const UA_ByteString *chunk);
void processERRResponse(UA_Client *client, const UA_ByteString *chunk);
void processACKResponse(UA_Client *client, const UA_ByteString *chunk);
void processOPNResponse(UA_Client *client, const UA_ByteString *message);
void closeSecureChannel(UA_Client *client);
void cleanupSession(UA_Client *client);

void
Client_warnEndpointsResult(UA_Client *client,
                           const UA_GetEndpointsResponse *response,
                           const UA_String *endpointUrl);

_UA_END_DECLS

#endif 
