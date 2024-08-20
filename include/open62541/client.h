
#ifndef UA_CLIENT_H_
#define UA_CLIENT_H_

#include <opcua/types.h>
#include <opcua/common.h>
#include <opcua/util.h>

#include <opcua/plugin/log.h>
#include <opcua/plugin/eventloop.h>
#include <opcua/plugin/securitypolicy.h>


struct UA_ClientConfig;
typedef struct UA_ClientConfig UA_ClientConfig;

_UA_BEGIN_DECLS


struct UA_ClientConfig {
    void *clientContext; 
    UA_Logger *logging;  

    UA_UInt32 timeout;

    UA_ApplicationDescription clientDescription;

    UA_String endpointUrl;

    UA_ExtensionObject userIdentityToken; 

    UA_Boolean noSession;   

    UA_EndpointDescription endpoint;
    UA_UserTokenPolicy userTokenPolicy;

    UA_String applicationUri;

    UA_Boolean tcpReuseAddr;

    const UA_DataTypeArray *customDataTypes;


    UA_UInt32 requestedSessionTimeout; 
    UA_ConnectionConfig localConnectionConfig;

    
    UA_EventLoop *eventLoop;
    UA_Boolean externalEventLoop; 

    
    size_t securityPoliciesSize;
    UA_SecurityPolicy *securityPolicies;

    
    UA_CertificateGroup certificateVerification;

#ifdef UA_ENABLE_ENCRYPTION
    
    UA_UInt32 maxTrustListSize; 
    UA_UInt32 maxRejectedListSize; 
#endif

    size_t authSecurityPoliciesSize;
    UA_SecurityPolicy *authSecurityPolicies;
    
    UA_String authSecurityPolicyUri;

    void (*stateCallback)(UA_Client *client,
                          UA_SecureChannelState channelState,
                          UA_SessionState sessionState,
                          UA_StatusCode connectStatus);

    void (*inactivityCallback)(UA_Client *client);

    
    UA_UInt16 outStandingPublishRequests;

    void (*subscriptionInactivityCallback)(UA_Client *client,
                                           UA_UInt32 subscriptionId,
                                           void *subContext);

    
    UA_String sessionName;
    UA_LocaleId *sessionLocaleIds;
    size_t sessionLocaleIdsSize;

#ifdef UA_ENABLE_ENCRYPTION
    UA_StatusCode (*privateKeyPasswordCallback)(UA_ClientConfig *cc,
                                                UA_ByteString *password);
#endif
};

UA_EXPORT UA_StatusCode
UA_ClientConfig_copy(UA_ClientConfig const *src, UA_ClientConfig *dst);

UA_EXPORT void
UA_ClientConfig_delete(UA_ClientConfig *config);

UA_EXPORT void
UA_ClientConfig_clear(UA_ClientConfig *config);

UA_INLINABLE( UA_StatusCode
UA_ClientConfig_setAuthenticationUsername(UA_ClientConfig *config,
                                          const char *username,
                                          const char *password) ,{
    UA_UserNameIdentityToken* identityToken = UA_UserNameIdentityToken_new();
    if(!identityToken)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    identityToken->userName = UA_STRING_ALLOC(username);
    identityToken->password = UA_STRING_ALLOC(password);

    UA_ExtensionObject_clear(&config->userIdentityToken);
    UA_ExtensionObject_setValue(&config->userIdentityToken, identityToken,
                                &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
    return UA_STATUSCODE_GOOD;
})


UA_EXPORT UA_Client * UA_Client_new(void);

UA_Client UA_EXPORT *
UA_Client_newWithConfig(const UA_ClientConfig *config);


void UA_EXPORT UA_THREADSAFE
UA_Client_getState(UA_Client *client,
                   UA_SecureChannelState *channelState,
                   UA_SessionState *sessionState,
                   UA_StatusCode *connectStatus);


UA_EXPORT UA_ClientConfig *
UA_Client_getConfig(UA_Client *client);


UA_INLINABLE( void *
UA_Client_getContext(UA_Client *client) ,{
    return UA_Client_getConfig(client)->clientContext; 
})


void UA_EXPORT
UA_Client_delete(UA_Client *client);


UA_EXPORT UA_StatusCode
UA_Client_getConnectionAttribute(UA_Client *client, const UA_QualifiedName key,
                                 UA_Variant *outValue);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Client_getConnectionAttributeCopy(UA_Client *client, const UA_QualifiedName key,
                                     UA_Variant *outValue);

UA_EXPORT UA_StatusCode
UA_Client_getConnectionAttribute_scalar(UA_Client *client,
                                        const UA_QualifiedName key,
                                        const UA_DataType *type,
                                        void *outValue);


UA_StatusCode UA_EXPORT UA_THREADSAFE
__UA_Client_connect(UA_Client *client, UA_Boolean async);

UA_INLINABLE( UA_StatusCode
UA_Client_connect(UA_Client *client, const char *endpointUrl), {
    
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    cc->noSession = false; 
    UA_String_clear(&cc->endpointUrl);
    cc->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    
    return __UA_Client_connect(client, false);
})

UA_INLINABLE( UA_StatusCode
UA_Client_connectAsync(UA_Client *client, const char *endpointUrl) ,{
    
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    cc->noSession = false; 
    UA_String_clear(&cc->endpointUrl);
    cc->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    
    return __UA_Client_connect(client, true);
})

UA_INLINABLE( UA_StatusCode
UA_Client_connectSecureChannel(UA_Client *client, const char *endpointUrl) ,{
    
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    cc->noSession = true; 
    UA_String_clear(&cc->endpointUrl);
    cc->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    
    return __UA_Client_connect(client, false);
})


UA_INLINABLE( UA_StatusCode
UA_Client_connectSecureChannelAsync(UA_Client *client, const char *endpointUrl) ,{
    
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    cc->noSession = true; 
    UA_String_clear(&cc->endpointUrl);
    cc->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    
    return __UA_Client_connect(client, true);
})

UA_INLINABLE( UA_StatusCode
UA_Client_connectUsername(UA_Client *client, const char *endpointUrl,
                          const char *username, const char *password) ,{
    
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_StatusCode res =
        UA_ClientConfig_setAuthenticationUsername(cc, username, password);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    
    return UA_Client_connect(client, endpointUrl);
})

UA_StatusCode UA_EXPORT
UA_Client_startListeningForReverseConnect(
    UA_Client *client, const UA_String *listenHostnames,
    size_t listenHostnamesLength, UA_UInt16 port);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_disconnect(UA_Client *client);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_disconnectAsync(UA_Client *client);


UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_disconnectSecureChannel(UA_Client *client);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_disconnectSecureChannelAsync(UA_Client *client);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_getSessionAuthenticationToken(
    UA_Client *client, UA_NodeId *authenticationToken, UA_ByteString *serverNonce);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_activateCurrentSession(UA_Client *client);


UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_activateCurrentSessionAsync(UA_Client *client);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_activateSession(UA_Client *client,
                          const UA_NodeId authenticationToken,
                          const UA_ByteString serverNonce);


UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_activateSessionAsync(UA_Client *client,
                               const UA_NodeId authenticationToken,
                               const UA_ByteString serverNonce);


UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_getEndpoints(UA_Client *client, const char *serverUrl,
                       size_t* endpointDescriptionsSize,
                       UA_EndpointDescription** endpointDescriptions);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_findServers(UA_Client *client, const char *serverUrl,
                      size_t serverUrisSize, UA_String *serverUris,
                      size_t localeIdsSize, UA_String *localeIds,
                      size_t *registeredServersSize,
                      UA_ApplicationDescription **registeredServers);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_findServersOnNetwork(UA_Client *client, const char *serverUrl,
                               UA_UInt32 startingRecordId,
                               UA_UInt32 maxRecordsToReturn,
                               size_t serverCapabilityFilterSize,
                               UA_String *serverCapabilityFilter,
                               size_t *serverOnNetworkSize,
                               UA_ServerOnNetwork **serverOnNetwork);


void UA_EXPORT UA_THREADSAFE
__UA_Client_Service(UA_Client *client, const void *request,
                    const UA_DataType *requestType, void *response,
                    const UA_DataType *responseType);

UA_INLINABLE( UA_THREADSAFE UA_ReadResponse
UA_Client_Service_read(UA_Client *client, const UA_ReadRequest request) ,{
    UA_ReadResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_READREQUEST],
                        &response, &UA_TYPES[UA_TYPES_READRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_WriteResponse
UA_Client_Service_write(UA_Client *client, const UA_WriteRequest request) ,{
    UA_WriteResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_WRITEREQUEST],
                        &response, &UA_TYPES[UA_TYPES_WRITERESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_HistoryReadResponse
UA_Client_Service_historyRead(UA_Client *client,
                              const UA_HistoryReadRequest request) ,{
    UA_HistoryReadResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_HISTORYREADREQUEST],
        &response, &UA_TYPES[UA_TYPES_HISTORYREADRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_HistoryUpdateResponse
UA_Client_Service_historyUpdate(UA_Client *client,
                                const UA_HistoryUpdateRequest request) ,{
    UA_HistoryUpdateResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_HISTORYUPDATEREQUEST],
        &response, &UA_TYPES[UA_TYPES_HISTORYUPDATERESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_CallResponse
UA_Client_Service_call(UA_Client *client,
                       const UA_CallRequest request) ,{
    UA_CallResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_CALLREQUEST],
        &response, &UA_TYPES[UA_TYPES_CALLRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_AddNodesResponse
UA_Client_Service_addNodes(UA_Client *client,
                           const UA_AddNodesRequest request) ,{
    UA_AddNodesResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_ADDNODESREQUEST],
        &response, &UA_TYPES[UA_TYPES_ADDNODESRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_AddReferencesResponse
UA_Client_Service_addReferences(UA_Client *client,
                                const UA_AddReferencesRequest request) ,{
    UA_AddReferencesResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_ADDREFERENCESREQUEST],
        &response, &UA_TYPES[UA_TYPES_ADDREFERENCESRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_DeleteNodesResponse
UA_Client_Service_deleteNodes(UA_Client *client,
                              const UA_DeleteNodesRequest request) ,{
    UA_DeleteNodesResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_DELETENODESREQUEST],
        &response, &UA_TYPES[UA_TYPES_DELETENODESRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_DeleteReferencesResponse
UA_Client_Service_deleteReferences(
    UA_Client *client, const UA_DeleteReferencesRequest request) ,{
    UA_DeleteReferencesResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_DELETEREFERENCESREQUEST],
        &response, &UA_TYPES[UA_TYPES_DELETEREFERENCESRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_BrowseResponse
UA_Client_Service_browse(UA_Client *client,
                         const UA_BrowseRequest request) ,{
    UA_BrowseResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_BROWSEREQUEST],
        &response, &UA_TYPES[UA_TYPES_BROWSERESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_BrowseNextResponse
UA_Client_Service_browseNext(UA_Client *client,
                             const UA_BrowseNextRequest request) ,{
    UA_BrowseNextResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_BROWSENEXTREQUEST],
        &response, &UA_TYPES[UA_TYPES_BROWSENEXTRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_TranslateBrowsePathsToNodeIdsResponse
UA_Client_Service_translateBrowsePathsToNodeIds(
    UA_Client *client,
    const UA_TranslateBrowsePathsToNodeIdsRequest request) ,{
    UA_TranslateBrowsePathsToNodeIdsResponse response;
    __UA_Client_Service(
        client, &request,
        &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSREQUEST],
        &response,
        &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_RegisterNodesResponse
UA_Client_Service_registerNodes(
    UA_Client *client, const UA_RegisterNodesRequest request) ,{
    UA_RegisterNodesResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_REGISTERNODESREQUEST],
        &response, &UA_TYPES[UA_TYPES_REGISTERNODESRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_UnregisterNodesResponse
UA_Client_Service_unregisterNodes(
    UA_Client *client, const UA_UnregisterNodesRequest request) ,{
    UA_UnregisterNodesResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_UNREGISTERNODESREQUEST],
        &response, &UA_TYPES[UA_TYPES_UNREGISTERNODESRESPONSE]);
    return response;
})

#ifdef UA_ENABLE_QUERY

UA_INLINABLE( UA_THREADSAFE UA_QueryFirstResponse
UA_Client_Service_queryFirst(UA_Client *client,
                             const UA_QueryFirstRequest request) ,{
    UA_QueryFirstResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST],
        &response, &UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
    return response;
})

UA_INLINABLE( UA_THREADSAFE UA_QueryNextResponse
UA_Client_Service_queryNext(UA_Client *client,
                            const UA_QueryNextRequest request) ,{
    UA_QueryNextResponse response;
    __UA_Client_Service(
        client, &request, &UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST],
        &response, &UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
    return response;
})

#endif


typedef void
(*UA_ClientAsyncServiceCallback)(UA_Client *client, void *userdata,
                                 UA_UInt32 requestId, void *response);

UA_StatusCode UA_EXPORT UA_THREADSAFE
__UA_Client_AsyncService(UA_Client *client, const void *request,
                         const UA_DataType *requestType,
                         UA_ClientAsyncServiceCallback callback,
                         const UA_DataType *responseType,
                         void *userdata, UA_UInt32 *requestId);

UA_EXPORT UA_THREADSAFE UA_StatusCode
UA_Client_cancelByRequestHandle(UA_Client *client, UA_UInt32 requestHandle,
                                UA_UInt32 *cancelCount);

UA_EXPORT UA_THREADSAFE UA_StatusCode
UA_Client_cancelByRequestId(UA_Client *client, UA_UInt32 requestId,
                            UA_UInt32 *cancelCount);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_modifyAsyncCallback(UA_Client *client, UA_UInt32 requestId,
                              void *userdata, UA_ClientAsyncServiceCallback callback);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_run_iterate(UA_Client *client, UA_UInt32 timeout);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_renewSecureChannel(UA_Client *client);


typedef void (*UA_ClientCallback)(UA_Client *client, void *data);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_addTimedCallback(UA_Client *client, UA_ClientCallback callback,
                           void *data, UA_DateTime date, UA_UInt64 *callbackId);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_addRepeatedCallback(UA_Client *client, UA_ClientCallback callback,
                              void *data, UA_Double interval_ms,
                              UA_UInt64 *callbackId);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Client_changeRepeatedCallbackInterval(UA_Client *client,
                                         UA_UInt64 callbackId,
                                         UA_Double interval_ms);

void UA_EXPORT UA_THREADSAFE
UA_Client_removeCallback(UA_Client *client, UA_UInt64 callbackId);

#define UA_Client_removeRepeatedCallback(server, callbackId)    \
    UA_Client_removeCallback(server, callbackId);


UA_EXPORT const UA_DataType *
UA_Client_findDataType(UA_Client *client, const UA_NodeId *typeId);


_UA_END_DECLS

#endif 
