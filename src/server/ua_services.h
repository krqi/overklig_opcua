
#ifndef UA_SERVICES_H_
#define UA_SERVICES_H_

#include <opcua/server.h>
#include "ua_session.h"

_UA_BEGIN_DECLS

typedef void (*UA_Service)(UA_Server*, UA_Session*,
                           const void *request, void *response);

typedef void (*UA_ChannelService)(UA_Server*, UA_SecureChannel*,
                                  const void *request, void *response);

typedef struct {
    UA_UInt32 requestTypeId;
#ifdef UA_ENABLE_DIAGNOSTICS
    UA_UInt16 counterOffset;
#endif
    UA_Boolean sessionRequired;
    UA_Service serviceCallback;
    const UA_DataType *requestType;
    const UA_DataType *responseType;
} UA_ServiceDescription;


UA_ServiceDescription * getServiceDescription(UA_UInt32 requestTypeId);


void Service_FindServers(UA_Server *server, UA_Session *session,
                         const UA_FindServersRequest *request,
                         UA_FindServersResponse *response);

void Service_GetEndpoints(UA_Server *server, UA_Session *session,
                          const UA_GetEndpointsRequest *request,
                          UA_GetEndpointsResponse *response);

#ifdef UA_ENABLE_DISCOVERY

void Service_RegisterServer(UA_Server *server, UA_Session *session,
                            const UA_RegisterServerRequest *request,
                            UA_RegisterServerResponse *response);

void Service_RegisterServer2(UA_Server *server, UA_Session *session,
                            const UA_RegisterServer2Request *request,
                            UA_RegisterServer2Response *response);

# ifdef UA_ENABLE_DISCOVERY_MULTICAST

void Service_FindServersOnNetwork(UA_Server *server, UA_Session *session,
                                  const UA_FindServersOnNetworkRequest *request,
                                  UA_FindServersOnNetworkResponse *response);

# endif 

#endif 


void Service_OpenSecureChannel(UA_Server *server, UA_SecureChannel* channel,
                               UA_OpenSecureChannelRequest *request,
                               UA_OpenSecureChannelResponse *response);

void Service_CloseSecureChannel(UA_Server *server, UA_SecureChannel *channel);


void Service_CreateSession(UA_Server *server, UA_SecureChannel *channel,
                           const UA_CreateSessionRequest *request,
                           UA_CreateSessionResponse *response);

void Service_ActivateSession(UA_Server *server, UA_SecureChannel *channel,
                             const UA_ActivateSessionRequest *request,
                             UA_ActivateSessionResponse *response);

void Service_CloseSession(UA_Server *server, UA_SecureChannel *channel,
                          const UA_CloseSessionRequest *request,
                          UA_CloseSessionResponse *response);

void Service_Cancel(UA_Server *server, UA_Session *session,
                    const UA_CancelRequest *request,
                    UA_CancelResponse *response);


void Service_AddNodes(UA_Server *server, UA_Session *session,
                      const UA_AddNodesRequest *request,
                      UA_AddNodesResponse *response);

void Service_AddReferences(UA_Server *server, UA_Session *session,
                           const UA_AddReferencesRequest *request,
                           UA_AddReferencesResponse *response);

void Service_DeleteNodes(UA_Server *server, UA_Session *session,
                         const UA_DeleteNodesRequest *request,
                         UA_DeleteNodesResponse *response);

void Service_DeleteReferences(UA_Server *server, UA_Session *session,
                              const UA_DeleteReferencesRequest *request,
                              UA_DeleteReferencesResponse *response);


void Service_Browse(UA_Server *server, UA_Session *session,
                    const UA_BrowseRequest *request,
                    UA_BrowseResponse *response);

void Service_BrowseNext(UA_Server *server, UA_Session *session,
                        const UA_BrowseNextRequest *request,
                        UA_BrowseNextResponse *response);

void Service_TranslateBrowsePathsToNodeIds(UA_Server *server, UA_Session *session,
             const UA_TranslateBrowsePathsToNodeIdsRequest *request,
             UA_TranslateBrowsePathsToNodeIdsResponse *response);

void Service_RegisterNodes(UA_Server *server, UA_Session *session,
                           const UA_RegisterNodesRequest *request,
                           UA_RegisterNodesResponse *response);

void Service_UnregisterNodes(UA_Server *server, UA_Session *session,
                             const UA_UnregisterNodesRequest *request,
                             UA_UnregisterNodesResponse *response);




void Service_Read(UA_Server *server, UA_Session *session,
                  const UA_ReadRequest *request,
                  UA_ReadResponse *response);

void Service_Write(UA_Server *server, UA_Session *session,
                   const UA_WriteRequest *request,
                   UA_WriteResponse *response);

#ifdef UA_ENABLE_HISTORIZING
void Service_HistoryRead(UA_Server *server, UA_Session *session,
                         const UA_HistoryReadRequest *request,
                         UA_HistoryReadResponse *response);

void Service_HistoryUpdate(UA_Server *server, UA_Session *session,
                           const UA_HistoryUpdateRequest *request,
                           UA_HistoryUpdateResponse *response);
#endif


#ifdef UA_ENABLE_METHODCALLS
void Service_Call(UA_Server *server, UA_Session *session,
                  const UA_CallRequest *request,
                  UA_CallResponse *response);

# if UA_MULTITHREADING >= 100
void Service_CallAsync(UA_Server *server, UA_Session *session, UA_UInt32 requestId,
                       const UA_CallRequest *request, UA_CallResponse *response,
                       UA_Boolean *finished);
#endif
#endif

#ifdef UA_ENABLE_SUBSCRIPTIONS


void Service_CreateMonitoredItems(UA_Server *server, UA_Session *session,
                                  const UA_CreateMonitoredItemsRequest *request,
                                  UA_CreateMonitoredItemsResponse *response);

void Service_DeleteMonitoredItems(UA_Server *server, UA_Session *session,
                                  const UA_DeleteMonitoredItemsRequest *request,
                                  UA_DeleteMonitoredItemsResponse *response);

void Service_ModifyMonitoredItems(UA_Server *server, UA_Session *session,
                                  const UA_ModifyMonitoredItemsRequest *request,
                                  UA_ModifyMonitoredItemsResponse *response);

void Service_SetMonitoringMode(UA_Server *server, UA_Session *session,
                               const UA_SetMonitoringModeRequest *request,
                               UA_SetMonitoringModeResponse *response);

void Service_SetTriggering(UA_Server *server, UA_Session *session,
                           const UA_SetTriggeringRequest *request,
                           UA_SetTriggeringResponse *response);


void Service_CreateSubscription(UA_Server *server, UA_Session *session,
                                const UA_CreateSubscriptionRequest *request,
                                UA_CreateSubscriptionResponse *response);

void Service_ModifySubscription(UA_Server *server, UA_Session *session,
                                const UA_ModifySubscriptionRequest *request,
                                UA_ModifySubscriptionResponse *response);

void Service_SetPublishingMode(UA_Server *server, UA_Session *session,
                               const UA_SetPublishingModeRequest *request,
                               UA_SetPublishingModeResponse *response);


UA_StatusCode
Service_Publish(UA_Server *server, UA_Session *session,
                const UA_PublishRequest *request, UA_UInt32 requestId);

void Service_Republish(UA_Server *server, UA_Session *session,
                       const UA_RepublishRequest *request,
                       UA_RepublishResponse *response);

void Service_DeleteSubscriptions(UA_Server *server, UA_Session *session,
                                 const UA_DeleteSubscriptionsRequest *request,
                                 UA_DeleteSubscriptionsResponse *response);

void Service_TransferSubscriptions(UA_Server *server, UA_Session *session,
                                   const UA_TransferSubscriptionsRequest *request,
                                   UA_TransferSubscriptionsResponse *response);

#endif 

_UA_END_DECLS

#endif 
