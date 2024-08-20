
#include <opcua/client.h>
#include "ua_discovery.h"
#include "ua_server_internal.h"

#ifdef UA_ENABLE_DISCOVERY

void
UA_DiscoveryManager_setState(UA_Server *server,
                             UA_DiscoveryManager *dm,
                             UA_LifecycleState state) {
    
    if(state == UA_LIFECYCLESTATE_STOPPING ||
       state == UA_LIFECYCLESTATE_STOPPED) {
        state = UA_LIFECYCLESTATE_STOPPED;
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
        if(dm->mdnsRecvConnectionsSize != 0 || dm->mdnsSendConnection != 0)
            state = UA_LIFECYCLESTATE_STOPPING;
#endif

        for(size_t i = 0; i < UA_MAXREGISTERREQUESTS; i++) {
            if(dm->registerRequests[i].client != NULL)
                state = UA_LIFECYCLESTATE_STOPPING;
        }
    }

    
    if(state == dm->sc.state)
        return;

    
    dm->sc.state = state;
    if(dm->sc.notifyState)
        dm->sc.notifyState(server, &dm->sc, state);
}

static UA_StatusCode
UA_DiscoveryManager_free(UA_Server *server,
                         struct UA_ServerComponent *sc) {
    UA_DiscoveryManager *dm = (UA_DiscoveryManager*)sc;

    if(sc->state != UA_LIFECYCLESTATE_STOPPED) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "Cannot delete the DiscoveryManager because "
                     "it is not stopped");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    registeredServer *rs, *rs_tmp;
    LIST_FOREACH_SAFE(rs, &dm->registeredServers, pointers, rs_tmp) {
        LIST_REMOVE(rs, pointers);
        UA_RegisteredServer_clear(&rs->registeredServer);
        UA_free(rs);
    }

# ifdef UA_ENABLE_DISCOVERY_MULTICAST
    serverOnNetwork *son, *son_tmp;
    LIST_FOREACH_SAFE(son, &dm->serverOnNetwork, pointers, son_tmp) {
        LIST_REMOVE(son, pointers);
        UA_ServerOnNetwork_clear(&son->serverOnNetwork);
        if(son->pathTmp)
            UA_free(son->pathTmp);
        UA_free(son);
    }

    UA_String_clear(&dm->selfFqdnMdnsRecord);

    for(size_t i = 0; i < SERVER_ON_NETWORK_HASH_SIZE; i++) {
        serverOnNetwork_hash_entry* currHash = dm->serverOnNetworkHash[i];
        while(currHash) {
            serverOnNetwork_hash_entry* nextHash = currHash->next;
            UA_free(currHash);
            currHash = nextHash;
        }
    }
# endif 

    UA_free(dm);
    return UA_STATUSCODE_GOOD;
}

static void
UA_DiscoveryManager_cleanupTimedOut(UA_Server *server, void *data) {
    UA_EventLoop *el = server->config.eventLoop;
    UA_DiscoveryManager *dm = (UA_DiscoveryManager*)data;

    UA_DateTime timedOut = el->dateTime_nowMonotonic(el);
    if(server->config.discoveryCleanupTimeout)
        timedOut -= server->config.discoveryCleanupTimeout * UA_DATETIME_SEC;

    registeredServer *current, *temp;
    LIST_FOREACH_SAFE(current, &dm->registeredServers, pointers, temp) {
        UA_Boolean semaphoreDeleted = false;

#ifdef UA_ENABLE_DISCOVERY_SEMAPHORE
        if(current->registeredServer.semaphoreFilePath.length) {
            size_t fpSize = current->registeredServer.semaphoreFilePath.length+1;
            char* filePath = (char *)UA_malloc(fpSize);
            if(filePath) {
                memcpy(filePath, current->registeredServer.semaphoreFilePath.data,
                       current->registeredServer.semaphoreFilePath.length );
                filePath[current->registeredServer.semaphoreFilePath.length] = '\0';
                semaphoreDeleted = UA_fileExists(filePath) == false;
                UA_free(filePath);
            } else {
                UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                             "Cannot check registration semaphore. Out of memory");
            }
        }
#endif

        if(semaphoreDeleted ||
           (server->config.discoveryCleanupTimeout &&
            current->lastSeen < timedOut)) {
            if(semaphoreDeleted) {
                UA_LOG_INFO(server->config.logging, UA_LOGCATEGORY_SERVER,
                            "Registration of server with URI %S is removed because "
                            "the semaphore file '%S' was deleted",
                            current->registeredServer.serverUri,
                            current->registeredServer.semaphoreFilePath);
            } else {
                // cppcheck-suppress unreadVariable
                UA_LOG_INFO(server->config.logging, UA_LOGCATEGORY_SERVER,
                            "Registration of server with URI %S has timed out "
                            "and is removed", current->registeredServer.serverUri);
            }
            LIST_REMOVE(current, pointers);
            UA_RegisteredServer_clear(&current->registeredServer);
            UA_free(current);
            dm->registeredServersSize--;
        }
    }

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    
    UA_DiscoveryManager_sendMulticastMessages(dm);
#endif
}

static UA_StatusCode
UA_DiscoveryManager_start(UA_Server *server,
                          struct UA_ServerComponent *sc) {
    if(sc->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_DiscoveryManager *dm = (UA_DiscoveryManager*)sc;
    dm->server = server; 

    UA_StatusCode res =
        addRepeatedCallback(server, UA_DiscoveryManager_cleanupTimedOut,
                            dm, 1000.0, &dm->discoveryCallbackId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    if(server->config.mdnsEnabled)
        UA_DiscoveryManager_startMulticast(dm);
#endif

    UA_DiscoveryManager_setState(server, dm, UA_LIFECYCLESTATE_STARTED);
    return UA_STATUSCODE_GOOD;
}

static void
UA_DiscoveryManager_stop(UA_Server *server,
                         struct UA_ServerComponent *sc) {
    if(sc->state != UA_LIFECYCLESTATE_STARTED)
        return;

    UA_DiscoveryManager *dm = (UA_DiscoveryManager*)sc;
    removeCallback(server, dm->discoveryCallbackId);

    
    for(size_t i = 0; i < UA_MAXREGISTERREQUESTS; i++) {
        if(dm->registerRequests[i].client == NULL)
            continue;
        UA_Client_disconnectSecureChannelAsync(dm->registerRequests[i].client);
    }

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    if(server->config.mdnsEnabled)
        UA_DiscoveryManager_stopMulticast(dm);
#endif

    UA_DiscoveryManager_setState(server, dm, UA_LIFECYCLESTATE_STOPPED);
}

UA_ServerComponent *
UA_DiscoveryManager_new(UA_Server *server) {
    UA_DiscoveryManager *dm = (UA_DiscoveryManager*)
        UA_calloc(1, sizeof(UA_DiscoveryManager));
    if(!dm)
        return NULL;

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    UA_EventLoop *el = server->config.eventLoop;
    dm->serverOnNetworkRecordIdLastReset = el->dateTime_now(el);
#endif 

    dm->sc.name = UA_STRING("discovery");
    dm->sc.start = UA_DiscoveryManager_start;
    dm->sc.stop = UA_DiscoveryManager_stop;
    dm->sc.free = UA_DiscoveryManager_free;
    return &dm->sc;
}





static void
asyncRegisterRequest_clear(void *app, void *context) {
    UA_Server *server = (UA_Server*)app;
    asyncRegisterRequest *ar = (asyncRegisterRequest*)context;
    UA_DiscoveryManager *dm = ar->dm;

    UA_String_clear(&ar->semaphoreFilePath);
    if(ar->client)
        UA_Client_delete(ar->client);
    memset(ar, 0, sizeof(asyncRegisterRequest));

    
    UA_DiscoveryManager_setState(server, dm, dm->sc.state);
}

static void
asyncRegisterRequest_clearAsync(asyncRegisterRequest *ar) {
    UA_Server *server = ar->server;
    UA_ServerConfig *sc = &server->config;
    UA_EventLoop *el = sc->eventLoop;

    ar->cleanupCallback.callback = asyncRegisterRequest_clear;
    ar->cleanupCallback.application = server;
    ar->cleanupCallback.context = ar;
    el->addDelayedCallback(el, &ar->cleanupCallback);
}

static void
setupRegisterRequest(asyncRegisterRequest *ar, UA_RequestHeader *rh,
                     UA_RegisteredServer *rs) {
    UA_ServerConfig *sc = &ar->dm->server->config;

    rh->timeoutHint = 10000;

    rs->isOnline = !ar->unregister;
    rs->serverUri = sc->applicationDescription.applicationUri;
    rs->productUri = sc->applicationDescription.productUri;
    rs->serverType = sc->applicationDescription.applicationType;
    rs->gatewayServerUri = sc->applicationDescription.gatewayServerUri;
    rs->semaphoreFilePath = ar->semaphoreFilePath;

    rs->serverNames = &sc->applicationDescription.applicationName;
    rs->serverNamesSize = 1;

    rs->discoveryUrls = sc->applicationDescription.discoveryUrls;
    rs->discoveryUrlsSize = sc->applicationDescription.discoveryUrlsSize;
}

static void
registerAsyncResponse(UA_Client *client, void *userdata,
                      UA_UInt32 requestId, void *resp) {
    asyncRegisterRequest *ar = (asyncRegisterRequest*)userdata;
    const UA_ServerConfig *sc = &ar->dm->server->config;
    UA_Response *response = (UA_Response*)resp;
    const char *regtype = (ar->register2) ? "RegisterServer2" : "RegisterServer";

    
    if(response->responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(sc->logging, UA_LOGCATEGORY_SERVER, "%s succeeded", regtype);
        goto done;
    }

    UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                   "%s failed with statuscode %s", regtype,
                   UA_StatusCode_name(response->responseHeader.serviceResult));

    
    ar->register2 = false;

    UA_SecureChannelState ss;
    UA_Client_getState(client, &ss, NULL, NULL);
    if(!ar->shutdown && ss == UA_SECURECHANNELSTATE_OPEN) {
        UA_RegisterServerRequest request;
        UA_RegisterServerRequest_init(&request);
        setupRegisterRequest(ar, &request.requestHeader, &request.server);
        UA_StatusCode res =
            __UA_Client_AsyncService(client, &request,
                                     &UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST],
                                     registerAsyncResponse,
                                     &UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE], ar, NULL);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR((const UA_Logger *)&sc->logging, UA_LOGCATEGORY_CLIENT,
                         "RegisterServer failed with statuscode %s",
                         UA_StatusCode_name(res));
            goto done;
        }
    }

    return;

 done:
    ar->shutdown = true;
    UA_Client_disconnectSecureChannelAsync(ar->client);
}

static void
discoveryClientStateCallback(UA_Client *client,
                             UA_SecureChannelState channelState,
                             UA_SessionState sessionState,
                             UA_StatusCode connectStatus) {
    asyncRegisterRequest *ar = (asyncRegisterRequest*)
        UA_Client_getContext(client);
    UA_ServerConfig *sc = &ar->dm->server->config;

    
    if(connectStatus != UA_STATUSCODE_GOOD) {
        if(connectStatus != UA_STATUSCODE_BADCONNECTIONCLOSED) {
            UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                         "Could not connect to the Discovery server with error %s",
                         UA_StatusCode_name(connectStatus));
        }

        
        if(channelState == UA_SECURECHANNELSTATE_CLOSED) {
            if(!ar->connectSuccess || ar->shutdown) {
                asyncRegisterRequest_clearAsync(ar); 
            } else {
                ar->connectSuccess = false;
                __UA_Client_connect(client, true);   
            }
        }
        return;
    }

    
    if(channelState != UA_SECURECHANNELSTATE_OPEN)
        return;

    
    ar->connectSuccess = true;

    UA_MessageSecurityMode msm = UA_MESSAGESECURITYMODE_INVALID;
    UA_Client_getConnectionAttribute_scalar(client, UA_QUALIFIEDNAME(0, "securityMode"),
                                            &UA_TYPES[UA_TYPES_MESSAGESECURITYMODE],
                                            &msm);
#ifdef UA_ENABLE_ENCRYPTION 
    if(msm != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return;
#endif

    const UA_DataType *reqType;
    const UA_DataType *respType;
    UA_RegisterServerRequest reg1;
    UA_RegisterServer2Request reg2;
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    UA_ExtensionObject mdnsConfig;
#endif
    void *request;

    
    if(ar->register2) {
        UA_RegisterServer2Request_init(&reg2);
        setupRegisterRequest(ar, &reg2.requestHeader, &reg2.server);
        reqType = &UA_TYPES[UA_TYPES_REGISTERSERVER2REQUEST];
        respType = &UA_TYPES[UA_TYPES_REGISTERSERVER2RESPONSE];
        request = &reg2;

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
        UA_ExtensionObject_setValueNoDelete(&mdnsConfig, &sc->mdnsConfig,
                                            &UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION]);
        reg2.discoveryConfigurationSize = 1;
        reg2.discoveryConfiguration = &mdnsConfig;
#endif
    } else {
        UA_RegisterServerRequest_init(&reg1);
        setupRegisterRequest(ar, &reg1.requestHeader, &reg1.server);
        reqType = &UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST];
        respType = &UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE];
        request = &reg1;
    }

    
    UA_StatusCode res =
        __UA_Client_AsyncService(client, request, reqType, registerAsyncResponse,
                                 respType, ar, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Client_disconnectSecureChannelAsync(ar->client);
        UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_CLIENT,
                     "RegisterServer2 failed with statuscode %s",
                     UA_StatusCode_name(res));
    }
}

static UA_StatusCode
UA_Server_register(UA_Server *server, UA_ClientConfig *cc, UA_Boolean unregister,
                   const UA_String discoveryServerUrl,
                   const UA_String semaphoreFilePath) {
    
    UA_DiscoveryManager *dm = (UA_DiscoveryManager*)
        getServerComponentByName(server, UA_STRING("discovery"));
    if(!dm) {
        UA_ClientConfig_clear(cc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    UA_ServerConfig *sc = &server->config;
    if(dm->sc.state != UA_LIFECYCLESTATE_STARTED) {
        UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                     "The server must be started for registering");
        UA_ClientConfig_clear(cc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    asyncRegisterRequest *ar = NULL;
    for(size_t i = 0; i < UA_MAXREGISTERREQUESTS; i++) {
        if(dm->registerRequests[i].client == NULL) {
            ar = &dm->registerRequests[i];
            break;
        }
    }
    if(!ar) {
        UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                     "Too many outstanding register requests. Cannot proceed.");
        UA_ClientConfig_clear(cc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    if(cc->eventLoop && !cc->externalEventLoop)
        cc->eventLoop->free(cc->eventLoop);
    cc->eventLoop = sc->eventLoop;
    cc->externalEventLoop = true;

    
    cc->stateCallback = discoveryClientStateCallback;
    cc->clientContext = ar;

    
#ifdef UA_ENABLE_ENCRYPTION
    cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
#endif

    
    cc->noSession = true;

    
    UA_String_clear(&cc->endpointUrl);
    UA_String_copy(&discoveryServerUrl, &cc->endpointUrl);

    
    ar->client = UA_Client_newWithConfig(cc);
    if(!ar->client) {
        UA_ClientConfig_clear(cc);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    
    memset(cc, 0, sizeof(UA_ClientConfig));

    
    ar->server = server;
    ar->dm = dm;
    ar->unregister = unregister;
    ar->register2 = true; 
    UA_String_copy(&semaphoreFilePath, &ar->semaphoreFilePath);

    ar->connectSuccess = false;
    return __UA_Client_connect(ar->client, true);
}

UA_StatusCode
UA_Server_registerDiscovery(UA_Server *server, UA_ClientConfig *cc,
                            const UA_String discoveryServerUrl,
                            const UA_String semaphoreFilePath) {
    UA_LOG_INFO(server->config.logging, UA_LOGCATEGORY_SERVER,
                "Registering at the DiscoveryServer: %S", discoveryServerUrl);
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res =
        UA_Server_register(server, cc, false, discoveryServerUrl, semaphoreFilePath);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_deregisterDiscovery(UA_Server *server, UA_ClientConfig *cc,
                              const UA_String discoveryServerUrl) {
    UA_LOG_INFO(server->config.logging, UA_LOGCATEGORY_SERVER,
                "Deregistering at the DiscoveryServer: %S", discoveryServerUrl);
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res =
        UA_Server_register(server, cc, true, discoveryServerUrl, UA_STRING_NULL);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

#endif 
