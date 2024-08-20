
#include "ua_server_internal.h"
#include "ua_services.h"


void
Service_OpenSecureChannel(UA_Server *server, UA_SecureChannel *channel,
                          UA_OpenSecureChannelRequest *request,
                          UA_OpenSecureChannelResponse *response) {
    const UA_SecurityPolicy *sp = channel->securityPolicy;

    switch(request->requestType) {
    
    case UA_SECURITYTOKENREQUESTTYPE_ISSUE:
        
        if(channel->state != UA_SECURECHANNELSTATE_ACK_SENT) {
            UA_LOG_ERROR_CHANNEL(server->config.logging, channel,
                                 "Called open on already open or closed channel");
            response->responseHeader.serviceResult = UA_STATUSCODE_BADINTERNALERROR;
            goto error;
        }

        
        if(request->securityMode != UA_MESSAGESECURITYMODE_NONE &&
           UA_ByteString_equal(&sp->policyUri, &UA_SECURITY_POLICY_NONE_URI)) {
            response->responseHeader.serviceResult = UA_STATUSCODE_BADSECURITYMODEREJECTED;
            goto error;
        }
        channel->securityMode = request->securityMode;
        break;

    
    case UA_SECURITYTOKENREQUESTTYPE_RENEW:
        
        if(channel->state != UA_SECURECHANNELSTATE_OPEN) {
            UA_LOG_ERROR_CHANNEL(server->config.logging, channel,
                                 "Called renew on channel which is not open");
            response->responseHeader.serviceResult = UA_STATUSCODE_BADINTERNALERROR;
            goto error;
        }

        
        if(channel->securityMode != UA_MESSAGESECURITYMODE_NONE &&
           UA_ByteString_equal(&channel->remoteNonce, &request->clientNonce)) {
            UA_LOG_ERROR_CHANNEL(server->config.logging, channel,
                                 "The client reused the last nonce");
            response->responseHeader.serviceResult = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
            goto error;
        }

        break;

    
    default:
        response->responseHeader.serviceResult = UA_STATUSCODE_BADINTERNALERROR;
        return;
    }

    UA_EventLoop *el = server->config.eventLoop;
    channel->altSecurityToken.channelId = channel->securityToken.channelId;
    channel->altSecurityToken.tokenId = server->lastTokenId++;
    channel->altSecurityToken.createdAt = el->dateTime_nowMonotonic(el);
    channel->altSecurityToken.revisedLifetime =
        (request->requestedLifetime > server->config.maxSecurityTokenLifetime) ?
        server->config.maxSecurityTokenLifetime : request->requestedLifetime;
    if(channel->altSecurityToken.revisedLifetime == 0)
        channel->altSecurityToken.revisedLifetime = server->config.maxSecurityTokenLifetime;

    
    UA_ByteString_clear(&channel->remoteNonce);
    channel->remoteNonce = request->clientNonce;
    UA_ByteString_init(&request->clientNonce);

    response->responseHeader.serviceResult = UA_SecureChannel_generateLocalNonce(channel);
    UA_CHECK_STATUS(response->responseHeader.serviceResult, goto error);

    
    channel->renewState = UA_SECURECHANNELRENEWSTATE_NEWTOKEN_SERVER;
    channel->state = UA_SECURECHANNELSTATE_OPEN;

    
    response->securityToken = channel->altSecurityToken;
    response->securityToken.createdAt = el->dateTime_now(el); 
    response->responseHeader.timestamp = response->securityToken.createdAt;
    response->responseHeader.requestHandle = request->requestHeader.requestHandle;
    response->responseHeader.serviceResult =
        UA_ByteString_copy(&channel->localNonce, &response->serverNonce);
    UA_CHECK_STATUS(response->responseHeader.serviceResult, goto error);

    
    if(request->requestType == UA_SECURITYTOKENREQUESTTYPE_ISSUE) {
        UA_LOG_INFO_CHANNEL(server->config.logging, channel,
                            "SecureChannel opened with SecurityPolicy %S "
                            "and a revised lifetime of %.2fs",
                            channel->securityPolicy->policyUri,
                            (UA_Float)response->securityToken.revisedLifetime / 1000);
    } else {
        UA_LOG_INFO_CHANNEL(server->config.logging, channel, "SecureChannel renewed "
                            "with a revised lifetime of %.2fs",
                            (UA_Float)response->securityToken.revisedLifetime / 1000);
    }

    return;

 error:
    if(request->requestType == UA_SECURITYTOKENREQUESTTYPE_ISSUE) {
        UA_LOG_INFO_CHANNEL(server->config.logging, channel,
                            "Opening a SecureChannel failed");
    } else {
        UA_LOG_DEBUG_CHANNEL(server->config.logging, channel,
                             "Renewing SecureChannel failed");
    }
}


void
Service_CloseSecureChannel(UA_Server *server, UA_SecureChannel *channel) {
    UA_SecureChannel_shutdown(channel, UA_SHUTDOWNREASON_CLOSE);
}
