
#include "ua_client_internal.h"


void
Client_warnEndpointsResult(UA_Client *client,
                           const UA_GetEndpointsResponse *response,
                           const UA_String *endpointUrl) {
    if(response->endpointsSize == 0) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "The server did not return any endpoints. "
                       "Did you use the correct endpointUrl?");
        return;
    }

    if(!UA_String_equal(endpointUrl, &response->endpoints[0].endpointUrl) ||
       (response->endpoints[0].server.discoveryUrlsSize > 0 &&
        !UA_String_equal(endpointUrl, &response->endpoints[0].server.discoveryUrls[0]))) {
        UA_String *betterUrl = &response->endpoints[0].endpointUrl;
        if(response->endpoints[0].server.discoveryUrlsSize > 0)
            betterUrl = &response->endpoints[0].server.discoveryUrls[0];
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "The server returned Endpoints with a different EndpointUrl %S than was "
                       "used to initialize the connection: %S. Some servers require a complete "
                       "match of the EndpointUrl/DiscoveryUrl (including the path) "
                       "to return all endpoints.", *betterUrl, *endpointUrl);
    }
}


static UA_StatusCode
getEndpointsInternal(UA_Client *client, const UA_String endpointUrl,
                     size_t *endpointDescriptionsSize,
                     UA_EndpointDescription **endpointDescriptions) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    UA_GetEndpointsRequest request;
    UA_GetEndpointsRequest_init(&request);
    request.requestHeader.timeoutHint = 10000;
    // assume the endpointurl outlives the service call
    request.endpointUrl = endpointUrl;

    UA_GetEndpointsResponse response;
    __Client_Service(client, &request, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST],
                     &response, &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE]);

    if(response.responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_StatusCode retval = response.responseHeader.serviceResult;
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "GetEndpointRequest failed with error code %s",
                     UA_StatusCode_name(retval));
        UA_GetEndpointsResponse_clear(&response);
        return retval;
    }

    *endpointDescriptions = response.endpoints;
    *endpointDescriptionsSize = response.endpointsSize;
    response.endpoints = NULL;
    response.endpointsSize = 0;
    UA_GetEndpointsResponse_clear(&response);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Client_getEndpoints(UA_Client *client, const char *serverUrl,
                       size_t *endpointDescriptionsSize,
                       UA_EndpointDescription** endpointDescriptions) {
    UA_LOCK(&client->clientMutex);

    UA_Boolean connected = (client->channel.state == UA_SECURECHANNELSTATE_OPEN);
    
    if(connected && strncmp((const char*)client->config.endpoint.endpointUrl.data, serverUrl,
                            client->config.endpoint.endpointUrl.length) != 0) {
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode retval;
    const UA_String url = UA_STRING((char*)(uintptr_t)serverUrl);
    if(!connected) {
        retval = connectSecureChannel(client, serverUrl);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_UNLOCK(&client->clientMutex);
            return retval;
        }
    }
    retval = getEndpointsInternal(client, url, endpointDescriptionsSize,
                                  endpointDescriptions);
    UA_UNLOCK(&client->clientMutex);

    if(!connected)
        UA_Client_disconnect(client);
    return retval;
}

UA_StatusCode
UA_Client_findServers(UA_Client *client, const char *serverUrl,
                      size_t serverUrisSize, UA_String *serverUris,
                      size_t localeIdsSize, UA_String *localeIds,
                      size_t *registeredServersSize,
                      UA_ApplicationDescription **registeredServers) {
    UA_LOCK(&client->clientMutex);
    UA_Boolean connected = (client->channel.state == UA_SECURECHANNELSTATE_OPEN);
    
    if(connected && strncmp((const char*)client->config.endpoint.endpointUrl.data, serverUrl,
                            client->config.endpoint.endpointUrl.length) != 0) {
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode retval;
    if(!connected) {
        retval = connectSecureChannel(client, serverUrl);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_UNLOCK(&client->clientMutex);
            return retval;
        }
    }

    
    UA_FindServersRequest request;
    UA_FindServersRequest_init(&request);
    request.serverUrisSize = serverUrisSize;
    request.serverUris = serverUris;
    request.localeIdsSize = localeIdsSize;
    request.localeIds = localeIds;

    
    UA_FindServersResponse response;
    __Client_Service(client, &request, &UA_TYPES[UA_TYPES_FINDSERVERSREQUEST],
                     &response, &UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE]);

    UA_UNLOCK(&client->clientMutex);

    
    retval = response.responseHeader.serviceResult;
    if(retval == UA_STATUSCODE_GOOD) {
        *registeredServersSize = response.serversSize;
        *registeredServers = response.servers;
        response.serversSize = 0;
        response.servers = NULL;
    } else {
        *registeredServersSize = 0;
        *registeredServers = NULL;
    }

    
    UA_FindServersResponse_clear(&response);
    if(!connected)
        UA_Client_disconnect(client);
    return retval;
}

UA_StatusCode
UA_Client_findServersOnNetwork(UA_Client *client, const char *serverUrl,
                               UA_UInt32 startingRecordId, UA_UInt32 maxRecordsToReturn,
                               size_t serverCapabilityFilterSize, UA_String *serverCapabilityFilter,
                               size_t *serverOnNetworkSize, UA_ServerOnNetwork **serverOnNetwork) {
    UA_LOCK(&client->clientMutex);

    UA_Boolean connected = (client->channel.state == UA_SECURECHANNELSTATE_OPEN);
    
    if(connected && strncmp((const char*)client->config.endpoint.endpointUrl.data, serverUrl,
                            client->config.endpoint.endpointUrl.length) != 0) {
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode retval;
    if(!connected) {
        retval = connectSecureChannel(client, serverUrl);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOCK(&client->clientMutex);
            return retval;
        }
    }

    
    UA_FindServersOnNetworkRequest request;
    UA_FindServersOnNetworkRequest_init(&request);
    request.startingRecordId = startingRecordId;
    request.maxRecordsToReturn = maxRecordsToReturn;
    request.serverCapabilityFilterSize = serverCapabilityFilterSize;
    request.serverCapabilityFilter = serverCapabilityFilter;

    
    UA_FindServersOnNetworkResponse response;
    __Client_Service(client, &request, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKREQUEST],
                     &response, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKRESPONSE]);

    UA_UNLOCK(&client->clientMutex);

    
    retval = response.responseHeader.serviceResult;
    if(retval == UA_STATUSCODE_GOOD) {
        *serverOnNetworkSize = response.serversSize;
        *serverOnNetwork = response.servers;
        response.serversSize = 0;
        response.servers = NULL;
    } else {
        *serverOnNetworkSize = 0;
        *serverOnNetwork = NULL;
    }

    
    UA_FindServersOnNetworkResponse_clear(&response);
    if(!connected)
        UA_Client_disconnect(client);
    return retval;
}
