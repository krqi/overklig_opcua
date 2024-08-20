
#include <opcua/types.h>

#include "opcua/transport_generated.h"
#include "ua_client_internal.h"
#include "ua_types_encoding_binary.h"


#define UA_MINMESSAGESIZE 8192
#define UA_SESSION_LOCALNONCELENGTH 32
#define MAX_DATA_SIZE 4096
#define REVERSE_CONNECT_INDICATOR (void *)(uintptr_t)0xFFFFFFFF

static void initConnect(UA_Client *client);
static UA_StatusCode createSessionAsync(UA_Client *client);

static UA_String
getEndpointUrl(UA_Client *client) {
    if(client->config.endpoint.endpointUrl.length > 0) {
        return client->config.endpoint.endpointUrl;
    } else if(client->discoveryUrl.length > 0) {
        return client->discoveryUrl;
    } else {
        return client->config.endpointUrl;
    }
}

static UA_StatusCode
fallbackEndpointUrl(UA_Client* client) {
    
    UA_String currentUrl = getEndpointUrl(client);
    if(UA_String_equal(&currentUrl, &client->config.endpointUrl)) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "Could not open a TCP connection to the Endpoint at %S",
                     client->config.endpointUrl);
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }

    if(client->config.endpoint.endpointUrl.length > 0) {
        
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "Could not open a TCP connection to the Endpoint at %S. "
                       "Overriding the endpoint description with the initial "
                       "EndpointUrl at %S.",
                       client->config.endpoint.endpointUrl,
                       client->config.endpointUrl);
        UA_String_clear(&client->config.endpoint.endpointUrl);
        return UA_String_copy(&client->config.endpointUrl,
                              &client->config.endpoint.endpointUrl);
    } else {
        
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "The DiscoveryUrl returned by the FindServers service (%S) "
                       "could not be connected. Continuing with the initial EndpointUrl "
                       "%S for the GetEndpoints service.",
                       client->config.endpointUrl, client->config.endpointUrl);
        UA_String_clear(&client->discoveryUrl);
        return UA_String_copy(&client->config.endpointUrl, &client->discoveryUrl);
    }
}

static UA_SecurityPolicy *
getSecurityPolicy(UA_Client *client, UA_String policyUri) {
    for(size_t i = 0; i < client->config.securityPoliciesSize; i++) {
        if(UA_String_equal(&policyUri, &client->config.securityPolicies[i].policyUri))
            return &client->config.securityPolicies[i];
    }
    return NULL;
}

static UA_SecurityPolicy *
getAuthSecurityPolicy(UA_Client *client, UA_String policyUri) {
    for(size_t i = 0; i < client->config.authSecurityPoliciesSize; i++) {
        if(UA_String_equal(&policyUri, &client->config.authSecurityPolicies[i].policyUri))
            return &client->config.authSecurityPolicies[i];
    }
    return NULL;
}


static UA_Boolean
endpointUnconfigured(UA_Client *client) {
    UA_EndpointDescription tmp;
    UA_EndpointDescription_init(&tmp);
    return UA_equal(&tmp, &client->config.endpoint,
                    &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
}

UA_Boolean
isFullyConnected(UA_Client *client) {
    
    if(client->sessionState != UA_SESSIONSTATE_ACTIVATED && !client->config.noSession)
        return false;

    
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN)
        return false;

    
    if(client->endpointsHandshake || endpointUnconfigured(client) ||
       client->findServersHandshake || client->discoveryUrl.length == 0)
        return false;

    return true;
}


static UA_StatusCode
signActivateSessionRequest(UA_Client *client, UA_SecureChannel *channel,
                           UA_ActivateSessionRequest *request) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_SignatureData *sd = &request->clientSignature;
    const UA_SecurityPolicySignatureAlgorithm *signAlg =
        &sp->asymmetricModule.cryptoModule.signatureAlgorithm;

    
    UA_StatusCode retval = UA_String_copy(&signAlg->uri, &sd->algorithm);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    size_t signatureSize = signAlg->getLocalSignatureSize(channel->channelContext);
    retval = UA_ByteString_allocBuffer(&sd->signature, signatureSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    UA_ByteString dataToSign;
    size_t dataToSignSize =
        channel->remoteCertificate.length + client->serverSessionNonce.length;
    if(dataToSignSize > MAX_DATA_SIZE)
        return UA_STATUSCODE_BADINTERNALERROR;
    retval = UA_ByteString_allocBuffer(&dataToSign, dataToSignSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval; 

    
    memcpy(dataToSign.data, channel->remoteCertificate.data,
           channel->remoteCertificate.length);
    memcpy(dataToSign.data + channel->remoteCertificate.length,
           client->serverSessionNonce.data, client->serverSessionNonce.length);
    retval = signAlg->sign(channel->channelContext, &dataToSign, &sd->signature);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    if(client->config.userTokenPolicy.tokenType == UA_USERTOKENTYPE_CERTIFICATE) {
        
        UA_SecurityPolicy *utsp =
            getAuthSecurityPolicy(client, client->config.authSecurityPolicyUri);
        if(!utsp) {
            UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                         "The configured SecurityPolicy for certificate "
                         "authentication could not be found");
            retval = UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
            goto cleanup;
        }

        UA_SignatureData *utsd = &request->userTokenSignature;
        UA_X509IdentityToken *token = (UA_X509IdentityToken *)
            request->userIdentityToken.content.decoded.data;
        UA_SecurityPolicySignatureAlgorithm *utpSignAlg =
            &utsp->asymmetricModule.cryptoModule.signatureAlgorithm;

        
        UA_ByteString signData = UA_BYTESTRING_NULL;
        size_t signDataSize =
            channel->remoteCertificate.length + client->serverSessionNonce.length;
        if(dataToSignSize > MAX_DATA_SIZE) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }

        
        retval = UA_String_copy(&utpSignAlg->uri, &utsd->algorithm);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;

        void *tmpCtx;
        retval = utsp->channelModule.newContext(utsp, &token->certificateData, &tmpCtx);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;

        
        retval = UA_ByteString_allocBuffer(&utsd->signature,
                                           utpSignAlg->getLocalSignatureSize(tmpCtx));
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup_utp;

        
        retval = UA_ByteString_allocBuffer(&signData, signDataSize);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup_utp;

        
        memcpy(signData.data, channel->remoteCertificate.data,
               channel->remoteCertificate.length);
        memcpy(signData.data + channel->remoteCertificate.length,
               client->serverSessionNonce.data, client->serverSessionNonce.length);
        retval = utpSignAlg->sign(tmpCtx, &signData, &utsd->signature);

    cleanup_utp:
        UA_ByteString_clear(&signData);
        utsp->channelModule.deleteContext(tmpCtx);
    }

 cleanup:
    UA_ByteString_clear(&dataToSign);
    return retval;
}

static UA_StatusCode
encryptUserIdentityToken(UA_Client *client, const UA_String *userTokenSecurityPolicy,
                         UA_ExtensionObject *userIdentityToken) {
    UA_IssuedIdentityToken *iit = NULL;
    UA_UserNameIdentityToken *unit = NULL;
    UA_ByteString *tokenData;
    const UA_DataType *tokenType = userIdentityToken->content.decoded.type;
    if(tokenType == &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]) {
        iit = (UA_IssuedIdentityToken*)userIdentityToken->content.decoded.data;
        tokenData = &iit->tokenData;
    } else if(tokenType == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
        unit = (UA_UserNameIdentityToken*)userIdentityToken->content.decoded.data;
        tokenData = &unit->password;
    } else {
        return UA_STATUSCODE_GOOD;
    }

    
    const UA_String none = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None");
    if(userTokenSecurityPolicy->length == 0 ||
       UA_String_equal(userTokenSecurityPolicy, &none)) {
        return UA_STATUSCODE_GOOD;
    }

    UA_SecurityPolicy *sp = getSecurityPolicy(client, *userTokenSecurityPolicy);
    if(!sp) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_NETWORK,
                       "Could not find the required SecurityPolicy for the UserToken");
        return UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
    }

    

    void *channelContext;
    UA_StatusCode retval = sp->channelModule.
        newContext(sp, &client->config.endpoint.serverCertificate, &channelContext);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_NETWORK,
                       "Could not instantiate the SecurityPolicy for the UserToken");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    size_t plainTextBlockSize = sp->asymmetricModule.cryptoModule.
        encryptionAlgorithm.getRemotePlainTextBlockSize(channelContext);
    size_t encryptedBlockSize = sp->asymmetricModule.cryptoModule.
        encryptionAlgorithm.getRemoteBlockSize(channelContext);
    UA_UInt32 length = (UA_UInt32)(tokenData->length +
                                   client->serverSessionNonce.length);
    UA_UInt32 totalLength = length + 4; 
    size_t blocks = totalLength / plainTextBlockSize;
    if(totalLength % plainTextBlockSize != 0)
        blocks++;
    size_t encryptedLength = blocks * encryptedBlockSize;

    
    UA_ByteString encrypted;
    retval = UA_ByteString_allocBuffer(&encrypted, encryptedLength);
    if(retval != UA_STATUSCODE_GOOD) {
        sp->channelModule.deleteContext(channelContext);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_Byte *pos = encrypted.data;
    const UA_Byte *end = &encrypted.data[encrypted.length];
    retval = UA_UInt32_encodeBinary(&length, &pos, end);
    memcpy(pos, tokenData->data, tokenData->length);
    memcpy(&pos[tokenData->length], client->serverSessionNonce.data,
           client->serverSessionNonce.length);
    UA_assert(retval == UA_STATUSCODE_GOOD);

    size_t paddedLength = plainTextBlockSize * blocks;
    for(size_t i = totalLength; i < paddedLength; i++)
        encrypted.data[i] = 0;
    encrypted.length = paddedLength;

    retval = sp->asymmetricModule.cryptoModule.encryptionAlgorithm.
        encrypt(channelContext, &encrypted);
    encrypted.length = encryptedLength;

    if(iit) {
        retval |= UA_String_copy(&sp->asymmetricModule.cryptoModule.encryptionAlgorithm.uri,
                                 &iit->encryptionAlgorithm);
    } else {
        retval |= UA_String_copy(&sp->asymmetricModule.cryptoModule.encryptionAlgorithm.uri,
                                 &unit->encryptionAlgorithm);
    }

    UA_ByteString_clear(tokenData);
    *tokenData = encrypted;

    
    sp->channelModule.deleteContext(channelContext);

    return retval;
}

static UA_StatusCode
checkCreateSessionSignature(UA_Client *client, const UA_SecureChannel *channel,
                            const UA_CreateSessionResponse *response) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    if(!channel->securityPolicy)
        return UA_STATUSCODE_BADINTERNALERROR;

    const UA_SecurityPolicy *sp = channel->securityPolicy;
    const UA_ByteString *lc = &sp->localCertificate;

    size_t dataToVerifySize = lc->length + client->clientSessionNonce.length;
    UA_ByteString dataToVerify = UA_BYTESTRING_NULL;
    UA_StatusCode retval = UA_ByteString_allocBuffer(&dataToVerify, dataToVerifySize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    memcpy(dataToVerify.data, lc->data, lc->length);
    memcpy(dataToVerify.data + lc->length, client->clientSessionNonce.data,
           client->clientSessionNonce.length);

    const UA_SecurityPolicySignatureAlgorithm *signAlg =
        &sp->asymmetricModule.cryptoModule.signatureAlgorithm;
    retval = signAlg->verify(channel->channelContext, &dataToVerify,
                             &response->serverSignature.signature);
    UA_ByteString_clear(&dataToVerify);
    return retval;
}





void
processERRResponse(UA_Client *client, const UA_ByteString *chunk) {
    size_t offset = 0;
    UA_TcpErrorMessage errMessage;
    client->connectStatus =
        UA_decodeBinaryInternal(chunk, &offset, &errMessage,
                                &UA_TRANSPORT[UA_TRANSPORT_TCPERRORMESSAGE], NULL);
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(client->config.logging, &client->channel,
                             "Received an ERR response that could not be decoded "
                             "with StatusCode %s",
                             UA_StatusCode_name(client->connectStatus));
        closeSecureChannel(client);
        return;
    }

    UA_LOG_ERROR_CHANNEL(client->config.logging, &client->channel,
                         "Received an ERR response with StatusCode %s and "
                         "the following ireason: %S",
                         UA_StatusCode_name(errMessage.error),
                         errMessage.reason);
    client->connectStatus = errMessage.error;
    closeSecureChannel(client);
    UA_TcpErrorMessage_clear(&errMessage);
}

void
processACKResponse(UA_Client *client, const UA_ByteString *chunk) {
    UA_SecureChannel *channel = &client->channel;
    if(channel->state != UA_SECURECHANNELSTATE_HEL_SENT) {
        UA_LOG_ERROR_CHANNEL(client->config.logging, channel,
                             "SecureChannel not in the HEL-sent state");
        client->connectStatus = UA_STATUSCODE_BADSECURECHANNELCLOSED;
        closeSecureChannel(client);
        return;
    }

    
    size_t offset = 0;
    UA_TcpAcknowledgeMessage ackMessage;
    client->connectStatus =
        UA_decodeBinaryInternal(chunk, &offset, &ackMessage,
                                &UA_TRANSPORT[UA_TRANSPORT_TCPACKNOWLEDGEMESSAGE], NULL);
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_NETWORK,
                     "Decoding ACK message failed");
        closeSecureChannel(client);
        return;
    }

    client->connectStatus =
        UA_SecureChannel_processHELACK(channel, &ackMessage);
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_NETWORK,
                     "Processing the ACK message failed with StatusCode %s",
                     UA_StatusCode_name(client->connectStatus));
        closeSecureChannel(client);
        return;
    }

    client->channel.state = UA_SECURECHANNELSTATE_ACK_RECEIVED;
}

static UA_StatusCode
sendHELMessage(UA_Client *client) {
    UA_ConnectionManager *cm = client->channel.connectionManager;
    if(!UA_SecureChannel_isConnected(&client->channel))
        return UA_STATUSCODE_BADNOTCONNECTED;

    
    UA_ByteString message;
    UA_StatusCode retval = cm->allocNetworkBuffer(cm, client->channel.connectionId,
                                                  &message, UA_MINMESSAGESIZE);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    UA_TcpHelloMessage hello;
    hello.protocolVersion = 0;
    hello.receiveBufferSize = client->config.localConnectionConfig.recvBufferSize;
    hello.sendBufferSize = client->config.localConnectionConfig.sendBufferSize;
    hello.maxMessageSize = client->config.localConnectionConfig.localMaxMessageSize;
    hello.maxChunkCount = client->config.localConnectionConfig.localMaxChunkCount;
    hello.endpointUrl = getEndpointUrl(client);

    UA_Byte *bufPos = &message.data[8]; 
    const UA_Byte *bufEnd = &message.data[message.length];
    client->connectStatus =
        UA_encodeBinaryInternal(&hello, &UA_TRANSPORT[UA_TRANSPORT_TCPHELLOMESSAGE],
                                &bufPos, &bufEnd, NULL, NULL);

    
    UA_TcpMessageHeader messageHeader;
    messageHeader.messageTypeAndChunkType = UA_CHUNKTYPE_FINAL + UA_MESSAGETYPE_HEL;
    messageHeader.messageSize = (UA_UInt32) ((uintptr_t)bufPos - (uintptr_t)message.data);
    bufPos = message.data;
    retval = UA_encodeBinaryInternal(&messageHeader,
                                     &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER],
                                     &bufPos, &bufEnd, NULL, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        cm->freeNetworkBuffer(cm, client->channel.connectionId, &message);
        return retval;
    }

    
    message.length = messageHeader.messageSize;
    retval = cm->sendWithConnection(cm, client->channel.connectionId,
                                    &UA_KEYVALUEMAP_NULL, &message);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT, "Sending HEL failed");
        closeSecureChannel(client);
        return retval;
    }

    UA_LOG_DEBUG(client->config.logging, UA_LOGCATEGORY_CLIENT, "Sent HEL message");
    client->channel.state = UA_SECURECHANNELSTATE_HEL_SENT;
    return UA_STATUSCODE_GOOD;
}

void processRHEMessage(UA_Client *client, const UA_ByteString *chunk) {
    UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT, "RHE received");

    size_t offset = 0; 
    UA_TcpReverseHelloMessage rheMessage;
    UA_StatusCode retval =
        UA_decodeBinaryInternal(chunk, &offset, &rheMessage,
                                &UA_TRANSPORT[UA_TRANSPORT_TCPREVERSEHELLOMESSAGE], NULL);

    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_NETWORK,
                     "Decoding RHE message failed");
        closeSecureChannel(client);
        return;
    }

    UA_String_clear(&client->discoveryUrl);
    UA_String_copy(&rheMessage.endpointUrl, &client->discoveryUrl);

    UA_TcpReverseHelloMessage_clear(&rheMessage);

    sendHELMessage(client);
}

void
processOPNResponse(UA_Client *client, const UA_ByteString *message) {
    
    size_t offset = 0;
    UA_NodeId responseId;
    UA_NodeId expectedId = UA_NS0ID(OPENSECURECHANNELRESPONSE_ENCODING_DEFAULTBINARY);
    UA_StatusCode retval = UA_NodeId_decodeBinary(message, &offset, &responseId);
    if(retval != UA_STATUSCODE_GOOD) {
        closeSecureChannel(client);
        return;
    }

    if(!UA_NodeId_equal(&responseId, &expectedId)) {
        UA_NodeId_clear(&responseId);
        closeSecureChannel(client);
        return;
    }

    
    UA_OpenSecureChannelResponse response;
    retval = UA_decodeBinaryInternal(message, &offset, &response,
                                     &UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE], NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        closeSecureChannel(client);
        return;
    }

    
    if(client->channel.securityMode != UA_MESSAGESECURITYMODE_NONE &&
       UA_ByteString_equal(&client->channel.remoteNonce,
                           &response.serverNonce)) {
        UA_LOG_ERROR_CHANNEL(client->config.logging, &client->channel,
                             "The server reused the last nonce");
        client->connectStatus = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        closeSecureChannel(client);
        return;
    }

    UA_EventLoop *el = client->config.eventLoop;
    client->nextChannelRenewal = el->dateTime_nowMonotonic(el)
            + (UA_DateTime) (response.securityToken.revisedLifetime
                    * (UA_Double) UA_DATETIME_MSEC * 0.75);

    
    UA_ByteString_clear(&client->channel.remoteNonce);
    client->channel.remoteNonce = response.serverNonce;
    UA_ByteString_init(&response.serverNonce);
    UA_ResponseHeader_clear(&response.responseHeader);

    client->channel.altSecurityToken = client->channel.securityToken;
    client->channel.securityToken = response.securityToken;
    client->channel.renewState = UA_SECURECHANNELRENEWSTATE_NEWTOKEN_CLIENT;

    retval = UA_SecureChannel_generateLocalKeys(&client->channel);
    if(retval != UA_STATUSCODE_GOOD) {
        closeSecureChannel(client);
        return;
    }

    UA_Float lifetime = (UA_Float)response.securityToken.revisedLifetime / 1000;
    UA_Boolean renew = (client->channel.state == UA_SECURECHANNELSTATE_OPEN);
    if(renew) {
        UA_LOG_INFO_CHANNEL(client->config.logging, &client->channel, "SecureChannel "
                            "renewed with a revised lifetime of %.2fs", lifetime);
    } else {
        UA_LOG_INFO_CHANNEL(client->config.logging, &client->channel,
                            "SecureChannel opened with SecurityPolicy %S "
                            "and a revised lifetime of %.2fs",
                            client->channel.securityPolicy->policyUri,
                            lifetime);
    }

    client->channel.state = UA_SECURECHANNELSTATE_OPEN;
}


static void
sendOPNAsync(UA_Client *client, UA_Boolean renew) {
    if(!UA_SecureChannel_isConnected(&client->channel)) {
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
        return;
    }

    client->connectStatus =
        UA_SecureChannel_generateLocalNonce(&client->channel);
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        return;

    UA_EventLoop *el = client->config.eventLoop;

    
    UA_OpenSecureChannelRequest opnSecRq;
    UA_OpenSecureChannelRequest_init(&opnSecRq);
    opnSecRq.requestHeader.timestamp = el->dateTime_now(el);
    opnSecRq.requestHeader.authenticationToken = client->authenticationToken;
    opnSecRq.securityMode = client->channel.securityMode;
    opnSecRq.clientNonce = client->channel.localNonce;
    opnSecRq.requestedLifetime = client->config.secureChannelLifeTime;
    if(renew) {
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_RENEW;
        UA_LOG_DEBUG_CHANNEL(client->config.logging, &client->channel,
                             "Requesting to renew the SecureChannel");
    } else {
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_ISSUE;
        UA_LOG_DEBUG_CHANNEL(client->config.logging, &client->channel,
                             "Requesting to open a SecureChannel");
    }

    
    UA_UInt32 requestId = ++client->requestId;

    
    UA_LOG_DEBUG(client->config.logging, UA_LOGCATEGORY_SECURECHANNEL,
                 "Requesting to open a SecureChannel");
    client->connectStatus =
        UA_SecureChannel_sendAsymmetricOPNMessage(&client->channel, requestId, &opnSecRq,
                                                  &UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_SECURECHANNEL,
                      "Sending OPN message failed with error %s",
                      UA_StatusCode_name(client->connectStatus));
        closeSecureChannel(client);
        return;
    }

    
    client->channel.renewState = UA_SECURECHANNELRENEWSTATE_SENT;
    if(client->channel.state < UA_SECURECHANNELSTATE_OPN_SENT)
        client->channel.state = UA_SECURECHANNELSTATE_OPN_SENT;

    UA_LOG_DEBUG(client->config.logging, UA_LOGCATEGORY_SECURECHANNEL,
                 "OPN message sent");
}

UA_StatusCode
__Client_renewSecureChannel(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    UA_EventLoop *el = client->config.eventLoop;
    UA_DateTime now = el->dateTime_nowMonotonic(el);

    
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN ||
       client->channel.renewState == UA_SECURECHANNELRENEWSTATE_SENT ||
       client->nextChannelRenewal > now)
        return UA_STATUSCODE_GOODCALLAGAIN;

    sendOPNAsync(client, true);

    return client->connectStatus;
}

UA_StatusCode
UA_Client_renewSecureChannel(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    UA_StatusCode res = __Client_renewSecureChannel(client);
    UA_UNLOCK(&client->clientMutex);
    return res;
}

static void
responseActivateSession(UA_Client *client, void *userdata,
                        UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);

    UA_ActivateSessionResponse *ar = (UA_ActivateSessionResponse*)response;
    if(ar->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        
        cleanupSession(client);

        
        if(client->config.noNewSession) {
            UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                         "Session cannot be activated with StatusCode %s. "
                         "The client is configured not to create a new Session.",
                         UA_StatusCode_name(ar->responseHeader.serviceResult));
            client->connectStatus = ar->responseHeader.serviceResult;
            closeSecureChannel(client);
            UA_UNLOCK(&client->clientMutex);
            return;
        }

        
        if(ar->responseHeader.serviceResult == UA_STATUSCODE_BADSESSIONIDINVALID ||
           ar->responseHeader.serviceResult == UA_STATUSCODE_BADSESSIONCLOSED) {
            UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                           "Session to be activated no longer exists. Create a new Session.");
            client->connectStatus = createSessionAsync(client);
            UA_UNLOCK(&client->clientMutex);
            return;
        }

        
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "Session cannot be activated with StatusCode %s. "
                     "The client cannot recover from this, closing the connection.",
                     UA_StatusCode_name(ar->responseHeader.serviceResult));
        client->connectStatus = ar->responseHeader.serviceResult;
        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    
    UA_ByteString_clear(&client->serverSessionNonce);
    client->serverSessionNonce = ar->serverNonce;
    UA_ByteString_init(&ar->serverNonce);

    client->sessionState = UA_SESSIONSTATE_ACTIVATED;
    notifyClientState(client);

#ifdef UA_ENABLE_SUBSCRIPTIONS
    __Client_Subscriptions_backgroundPublish(client);
#endif

    UA_UNLOCK(&client->clientMutex);
}

static UA_StatusCode
activateSessionAsync(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    if(client->sessionState != UA_SESSIONSTATE_CREATED &&
       client->sessionState != UA_SESSIONSTATE_ACTIVATED) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "Can not activate session, session neither created nor activated. "
                     "Actual state: '%u'", client->sessionState);
        return UA_STATUSCODE_BADSESSIONCLOSED;
    }

    UA_ActivateSessionRequest request;
    UA_ActivateSessionRequest_init(&request);
    UA_StatusCode retval =
        UA_ExtensionObject_copy(&client->config.userIdentityToken,
                                &request.userIdentityToken);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    if(client->config.sessionLocaleIdsSize && client->config.sessionLocaleIds) {
        retval = UA_Array_copy(client->config.sessionLocaleIds,
                               client->config.sessionLocaleIdsSize,
                               (void **)&request.localeIds, &UA_TYPES[UA_TYPES_LOCALEID]);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        request.localeIdsSize = client->config.sessionLocaleIdsSize;
    }

    
    if(request.userIdentityToken.encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY) {
        UA_AnonymousIdentityToken *t = UA_AnonymousIdentityToken_new();
        if(!t) {
            UA_ActivateSessionRequest_clear(&request);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        request.userIdentityToken.content.decoded.data = t;
        request.userIdentityToken.content.decoded.type =
            &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN];
        request.userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
    }

    
    UA_String_clear((UA_String*)request.userIdentityToken.content.decoded.data);
    retval = UA_String_copy(&client->config.userTokenPolicy.policyId,
                            (UA_String*)request.userIdentityToken.content.decoded.data);

    
    const UA_String *userTokenPolicy = &client->channel.securityPolicy->policyUri;
    if(client->config.userTokenPolicy.securityPolicyUri.length > 0)
        userTokenPolicy = &client->config.userTokenPolicy.securityPolicyUri;
    retval |= encryptUserIdentityToken(client, userTokenPolicy, &request.userIdentityToken);
    retval |= signActivateSessionRequest(client, &client->channel, &request);

    if(retval == UA_STATUSCODE_GOOD)
        retval = __Client_AsyncService(client, &request,
                                       &UA_TYPES[UA_TYPES_ACTIVATESESSIONREQUEST],
                                       (UA_ClientAsyncServiceCallback)responseActivateSession,
                                       &UA_TYPES[UA_TYPES_ACTIVATESESSIONRESPONSE],
                                       NULL, NULL);

    UA_ActivateSessionRequest_clear(&request);
    if(retval == UA_STATUSCODE_GOOD)
        client->sessionState = UA_SESSIONSTATE_ACTIVATE_REQUESTED;
    else
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "ActivateSession failed when sending the request with error code %s",
                     UA_StatusCode_name(retval));

    return retval;
}


static void
responseGetEndpoints(UA_Client *client, void *userdata,
                     UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);

    client->endpointsHandshake = false;

    UA_LOG_DEBUG(client->config.logging, UA_LOGCATEGORY_CLIENT,
                 "Received GetEndpointsResponse");

    UA_GetEndpointsResponse *resp = (UA_GetEndpointsResponse*)response;

    
    if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        if(UA_SecureChannel_isConnected(&client->channel)) {
           client->connectStatus = resp->responseHeader.serviceResult;
           closeSecureChannel(client);
           UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                        "GetEndpointRequest failed with error code %s",
                        UA_StatusCode_name(client->connectStatus));
        }

        UA_GetEndpointsResponse_clear(resp);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    
    Client_warnEndpointsResult(client, resp, &client->discoveryUrl);

    const size_t notFound = (size_t)-1;
    size_t bestEndpointIndex = notFound;
    size_t bestTokenIndex = notFound;
    UA_Byte bestEndpointLevel = 0;
    const UA_String binaryTransport =
        UA_STRING("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");

    
    for(size_t i = 0; i < resp->endpointsSize; ++i) {
        UA_EndpointDescription* endpoint = &resp->endpoints[i];

        
        if(endpoint->securityLevel < bestEndpointLevel)
            continue;

        
        if(client->config.applicationUri.length > 0 &&
           !UA_String_equal(&client->config.applicationUri,
                            &endpoint->server.applicationUri))
            continue;

        if(endpoint->transportProfileUri.length != 0 &&
           !UA_String_equal(&endpoint->transportProfileUri, &binaryTransport))
            continue;

        
        if(endpoint->securityMode < 1 || endpoint->securityMode > 3) {
            UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: invalid security mode",
                        (long unsigned)i);
            continue;
        }

        
        if(client->config.securityMode > 0 &&
           client->config.securityMode != endpoint->securityMode) {
            UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security mode doesn't match",
                        (long unsigned)i);
            continue;
        }

        
        if(client->config.securityPolicyUri.length > 0 &&
           !UA_String_equal(&client->config.securityPolicyUri,
                            &endpoint->securityPolicyUri)) {
            UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security policy doesn't match",
                        (long unsigned)i);
            continue;
        }

        
        if(!getSecurityPolicy(client, endpoint->securityPolicyUri)) {
            UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security policy not available",
                        (long unsigned)i);
            continue;
        }

        bestEndpointIndex = i;

        
        for(size_t j = 0; j < endpoint->userIdentityTokensSize; ++j) {
            UA_UserTokenPolicy *tokenPolicy = &endpoint->userIdentityTokens[j];
            const UA_DataType *tokenType =
                client->config.userIdentityToken.content.decoded.type;

            
            if(tokenPolicy->tokenType != UA_USERTOKENTYPE_ANONYMOUS &&
               tokenPolicy->securityPolicyUri.length > 0 &&
               !getSecurityPolicy(client, tokenPolicy->securityPolicyUri)) {
                UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu in endpoint %lu: "
                            "security policy \"%S\" not available",
                            (long unsigned)j, (long unsigned)i,
                            tokenPolicy->securityPolicyUri);
                continue;
            }

            if(tokenPolicy->tokenType > 3) {
                UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu in endpoint %lu: "
                            "invalid token type",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }

            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_ANONYMOUS &&
               tokenType != &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN] &&
               tokenType != NULL) {
                UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (anonymous) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_USERNAME &&
               tokenType != &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
                UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (username) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_CERTIFICATE &&
               tokenType != &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN]) {
                UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (certificate) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_ISSUEDTOKEN &&
               tokenType != &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]) {
                UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (token) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }

            

            UA_String *securityPolicyUri = &tokenPolicy->securityPolicyUri;
            if(securityPolicyUri->length == 0)
                securityPolicyUri = &endpoint->securityPolicyUri;
            if(UA_String_isEmpty(&client->config.authSecurityPolicyUri))
                UA_String_copy(securityPolicyUri, &client->config.authSecurityPolicyUri);

            
            bestEndpointLevel = endpoint->securityLevel;
            bestTokenIndex = j;

            break;
        }
    }

    if(bestEndpointIndex == notFound) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "No suitable endpoint found");
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    if(!client->config.noSession && bestTokenIndex == notFound) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "No suitable UserTokenPolicy found for the possible endpoints");
        client->connectStatus = UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    
    UA_EndpointDescription *endpoint = &resp->endpoints[bestEndpointIndex];
    UA_ApplicationDescription_clear(&client->serverDescription);
    UA_ApplicationDescription_copy(&endpoint->server, &client->serverDescription);
    UA_EndpointDescription_clear(&client->config.endpoint);
    client->config.endpoint = *endpoint;

#if UA_LOGLEVEL <= 300
    const char *securityModeNames[3] = {"None", "Sign", "SignAndEncrypt"};
    UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                "Selected endpoint %lu in URL %S with SecurityMode "
                "%s and SecurityPolicy %S",
                (long unsigned)bestEndpointIndex, endpoint->endpointUrl,
                securityModeNames[endpoint->securityMode - 1],
                endpoint->securityPolicyUri);
#endif

    
    if(bestTokenIndex != notFound) {
        UA_UserTokenPolicy *tokenPolicy = &endpoint->userIdentityTokens[bestTokenIndex];
        UA_assert(tokenPolicy);
#if UA_LOGLEVEL <= 300
        const char *userTokenTypeNames[4] = {"Anonymous", "UserName", "Certificate", "IssuedToken"};
        UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                    "Selected UserTokenPolicy %S with UserTokenType %s "
                    "and SecurityPolicy %S", tokenPolicy->policyId,
                    userTokenTypeNames[tokenPolicy->tokenType],
                    tokenPolicy->securityPolicyUri);
#endif
        UA_UserTokenPolicy_clear(&client->config.userTokenPolicy);
        client->config.userTokenPolicy = *tokenPolicy;
        UA_UserTokenPolicy_init(tokenPolicy);
    }

    
    UA_EndpointDescription_init(endpoint);

    if(client->config.endpoint.securityMode != client->channel.securityMode ||
       !UA_String_equal(&client->config.endpoint.securityPolicyUri,
                        &client->channel.securityPolicy->policyUri)) {
        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    if(client->discoveryUrl.length > 0 &&
       !UA_String_equal(&client->discoveryUrl,
                        &client->config.endpoint.endpointUrl)) {
        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    UA_UNLOCK(&client->clientMutex);
}

static UA_StatusCode
requestGetEndpoints(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    UA_GetEndpointsRequest request;
    UA_GetEndpointsRequest_init(&request);
    request.endpointUrl = getEndpointUrl(client);

    UA_StatusCode retval =
        __Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST],
                              (UA_ClientAsyncServiceCallback) responseGetEndpoints,
                              &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE], NULL, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "RequestGetEndpoints failed when sending the request with error code %s",
                     UA_StatusCode_name(retval));
        return retval;
    }

    client->endpointsHandshake = true;
    return UA_STATUSCODE_GOOD;
}

static void
responseFindServers(UA_Client *client, void *userdata,
                    UA_UInt32 requestId, void *response) {
    client->findServersHandshake = false;

    UA_LOG_DEBUG(client->config.logging, UA_LOGCATEGORY_CLIENT,
                 "Received FindServersResponse");

    UA_FindServersResponse *fsr = (UA_FindServersResponse*)response;
    if(fsr->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "FindServers failed with error code %s. Continue with the "
                       "EndpointURL %S.",
                       UA_StatusCode_name(fsr->responseHeader.serviceResult),
                       client->config.endpointUrl);
        UA_String_copy(&client->config.endpointUrl, &client->discoveryUrl);
        return;
    }

    
    for(size_t i = 0; i < fsr->serversSize; i++) {
        UA_ApplicationDescription *server = &fsr->servers[i];

        
        if(client->config.applicationUri.length > 0 &&
           !UA_String_equal(&client->config.applicationUri,
                            &server->applicationUri))
            continue;

        for(size_t j = 0; j < server->discoveryUrlsSize; j++) {
            if(UA_String_equal(&client->config.endpointUrl, &server->discoveryUrls[j])) {
                UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                            "The initially defined EndpointURL %S "
                            "is valid for the server", client->config.endpointUrl);
                UA_String_copy(&client->config.endpointUrl, &client->discoveryUrl);
                return;
            }
        }
    }

    for(size_t i = 0; i < fsr->serversSize; i++) {
        UA_ApplicationDescription *server = &fsr->servers[i];
        if(server->applicationType != UA_APPLICATIONTYPE_SERVER &&
            server->applicationType != UA_APPLICATIONTYPE_CLIENTANDSERVER &&
            server->applicationType != UA_APPLICATIONTYPE_DISCOVERYSERVER)
            continue;

        
        if(client->config.applicationUri.length > 0 &&
           !UA_String_equal(&client->config.applicationUri,
                            &server->applicationUri))
            continue;

        for(size_t j = 0; j < server->discoveryUrlsSize; j++) {
            UA_String hostname, path;
            UA_UInt16 port;
            UA_StatusCode res =
                UA_parseEndpointUrl(&server->discoveryUrls[j], &hostname,
                                    &port, &path);
            if(res != UA_STATUSCODE_GOOD)
                continue;

            
            UA_String_clear(&client->discoveryUrl);
            client->discoveryUrl = server->discoveryUrls[j];
            UA_String_init(&server->discoveryUrls[j]);

            UA_LOG_INFO(client->config.logging, UA_LOGCATEGORY_CLIENT,
                        "Use the EndpointURL %S returned from FindServers",
                        client->discoveryUrl);

            closeSecureChannel(client);
            return;
        }
    }

    UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                   "FindServers did not returned a suitable DiscoveryURL. "
                   "Continue with the EndpointURL %S.", client->config.endpointUrl);
    UA_String_clear(&client->discoveryUrl);
    UA_String_copy(&client->config.endpointUrl, &client->discoveryUrl);
}

static UA_StatusCode
requestFindServers(UA_Client *client) {
    UA_FindServersRequest request;
    UA_FindServersRequest_init(&request);
    request.requestHeader.timeoutHint = 10000;
    request.endpointUrl = client->config.endpointUrl;
    UA_StatusCode retval =
        __Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_FINDSERVERSREQUEST],
                              (UA_ClientAsyncServiceCallback) responseFindServers,
                              &UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE], NULL, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "FindServers failed when sending the request with error code %s",
                     UA_StatusCode_name(retval));
        return retval;
    }

    client->findServersHandshake = true;
    return UA_STATUSCODE_GOOD;
}

static void
createSessionCallback(UA_Client *client, void *userdata,
                      UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);

    UA_CreateSessionResponse *sessionResponse = (UA_CreateSessionResponse*)response;
    UA_StatusCode res = sessionResponse->responseHeader.serviceResult;
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        if(!UA_ByteString_equal(&sessionResponse->serverCertificate,
                                &client->channel.remoteCertificate)) {
            res = UA_STATUSCODE_BADCERTIFICATEINVALID;
            goto cleanup;
        }

        
        res = checkCreateSessionSignature(client, &client->channel, sessionResponse);
        if(res != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    
    UA_ByteString_clear(&client->serverSessionNonce);
    UA_NodeId_clear(&client->authenticationToken);
    res |= UA_ByteString_copy(&sessionResponse->serverNonce,
                              &client->serverSessionNonce);
    res |= UA_NodeId_copy(&sessionResponse->authenticationToken,
                          &client->authenticationToken);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    client->sessionState = UA_SESSIONSTATE_CREATED;

 cleanup:
    client->connectStatus = res;
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        client->sessionState = UA_SESSIONSTATE_CLOSED;

    UA_UNLOCK(&client->clientMutex);
}

static UA_StatusCode
createSessionAsync(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        if(client->clientSessionNonce.length != UA_SESSION_LOCALNONCELENGTH) {
           UA_ByteString_clear(&client->clientSessionNonce);
            res = UA_ByteString_allocBuffer(&client->clientSessionNonce,
                                            UA_SESSION_LOCALNONCELENGTH);
            if(res != UA_STATUSCODE_GOOD)
                return res;
        }
        res = client->channel.securityPolicy->symmetricModule.
                 generateNonce(client->channel.securityPolicy->policyContext,
                               &client->clientSessionNonce);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    
    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);
    request.clientNonce = client->clientSessionNonce;
    request.requestedSessionTimeout = client->config.requestedSessionTimeout;
    request.maxResponseMessageSize = UA_INT32_MAX;
    request.endpointUrl = client->config.endpoint.endpointUrl;
    request.clientDescription = client->config.clientDescription;
    request.sessionName = client->config.sessionName;
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        request.clientCertificate = client->channel.securityPolicy->localCertificate;
    }

    res = __Client_AsyncService(client, &request,
                                &UA_TYPES[UA_TYPES_CREATESESSIONREQUEST],
                                (UA_ClientAsyncServiceCallback)createSessionCallback,
                                &UA_TYPES[UA_TYPES_CREATESESSIONRESPONSE], NULL, NULL);

    if(res == UA_STATUSCODE_GOOD)
        client->sessionState = UA_SESSIONSTATE_CREATE_REQUESTED;
    else
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "CreateSession failed when sending the request with "
                     "error code %s", UA_StatusCode_name(res));

    return res;
}

static UA_StatusCode
initSecurityPolicy(UA_Client *client) {
    
    UA_SecurityPolicy *sp = NULL;
    if(client->config.endpoint.securityPolicyUri.length == 0) {
        sp = getSecurityPolicy(client,
                               UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None"));
    } else {
        sp = getSecurityPolicy(client, client->config.endpoint.securityPolicyUri);
    }

    
    if(!sp)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    if(client->channel.securityPolicy)
        return (client->channel.securityPolicy == sp) ?
            UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINTERNALERROR;

    
    client->channel.securityMode = client->config.endpoint.securityMode;
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_INVALID)
        client->channel.securityMode = UA_MESSAGESECURITYMODE_NONE;

    
    return UA_SecureChannel_setSecurityPolicy(&client->channel, sp,
                                              &client->config.endpoint.serverCertificate);
}

static void
connectActivity(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);
    UA_LOG_TRACE(client->config.logging, UA_LOGCATEGORY_CLIENT,
                 "Client connect iterate");

    
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        return;

    
    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
        return;

    
    switch(client->channel.state) {
        
    case UA_SECURECHANNELSTATE_CONNECTING:
    case UA_SECURECHANNELSTATE_CLOSING:
    case UA_SECURECHANNELSTATE_HEL_SENT:
    case UA_SECURECHANNELSTATE_OPN_SENT:
        return;

        
    case UA_SECURECHANNELSTATE_CONNECTED:
        client->connectStatus = sendHELMessage(client);
        return;

        
    case UA_SECURECHANNELSTATE_ACK_RECEIVED:
        sendOPNAsync(client, false); 
        return;

        
    case UA_SECURECHANNELSTATE_OPEN:
        break;

    case UA_SECURECHANNELSTATE_CLOSED:
        if(client->config.noReconnect)
            client->connectStatus = UA_STATUSCODE_BADNOTCONNECTED;
        else
            initConnect(client); 
        return;

        
    default:
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
        return;
    }

    

    
    if(client->endpointsHandshake || client->findServersHandshake)
        return;

    if(client->discoveryUrl.length == 0) {
        client->connectStatus = requestFindServers(client);
        return;
    }

    if(endpointUnconfigured(client)) {
        client->connectStatus = requestGetEndpoints(client);
        return;
    }

    
    if(client->config.noSession)
        return;

    
    switch(client->sessionState) {
        
    case UA_SESSIONSTATE_CLOSED:
        client->connectStatus = createSessionAsync(client);
        return;

        
    case UA_SESSIONSTATE_CREATED:
        client->connectStatus = activateSessionAsync(client);
        return;

    case UA_SESSIONSTATE_CREATE_REQUESTED:
    case UA_SESSIONSTATE_ACTIVATE_REQUESTED:
    case UA_SESSIONSTATE_ACTIVATED:
    case UA_SESSIONSTATE_CLOSING:
        return; 

        
    default:
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
        break;
    }
}

static UA_StatusCode
verifyClientSecureChannelHeader(void *application, UA_SecureChannel *channel,
                                const UA_AsymmetricAlgorithmSecurityHeader *asymHeader) {
    UA_Client *client = (UA_Client*)application;
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_assert(sp != NULL);

    
    if(asymHeader->securityPolicyUri.length > 0 &&
       !UA_String_equal(&sp->policyUri, &asymHeader->securityPolicyUri)) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "The server uses a different SecurityPolicy from the client");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_ByteString serverCert = getLeafCertificate(asymHeader->senderCertificate);
    if(client->config.endpoint.serverCertificate.length > 0 &&
       !UA_String_equal(&client->config.endpoint.serverCertificate, &serverCert)) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "The server certificate is different from the EndpointDescription");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    
    UA_StatusCode res = sp->asymmetricModule.
        compareCertificateThumbprint(sp, &asymHeader->receiverCertificateThumbprint);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "The server does not use the client certificate "
                     "used for the selected SecurityPolicy");
        return res;
    }

    return UA_STATUSCODE_GOOD;
}

static void
verifyClientApplicationURI(const UA_Client *client) {
#if UA_LOGLEVEL <= 400
    for(size_t i = 0; i < client->config.securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &client->config.securityPolicies[i];
        if(!sp->localCertificate.data) {
            UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                           "skip verifying ApplicationURI for the SecurityPolicy %S",
                           sp->policyUri);
            continue;
        }

        UA_StatusCode retval =
            UA_CertificateUtils_verifyApplicationURI(client->allowAllCertificateUris, &sp->localCertificate,
                                                     &client->config.clientDescription.applicationUri);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                           "The configured ApplicationURI does not match the URI "
                           "specified in the certificate for the SecurityPolicy %S",
                           sp->policyUri.length);
        }
    }
#endif
}

static void
__Client_networkCallback(UA_ConnectionManager *cm, uintptr_t connectionId,
                         void *application, void **connectionContext,
                         UA_ConnectionState state, const UA_KeyValueMap *params,
                         UA_ByteString msg) {
    
    UA_Client *client = (UA_Client*)application;
    UA_LOCK(&client->clientMutex);

    UA_LOG_TRACE(client->config.logging, UA_LOGCATEGORY_CLIENT, "Client network callback");

    
    if(!*connectionContext) {
        if(client->channel.state != UA_SECURECHANNELSTATE_CLOSED &&
           client->channel.state != UA_SECURECHANNELSTATE_REVERSE_LISTENING) {
            UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                         "Cannot open a connection, the SecureChannel is already used");
            client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
            notifyClientState(client);
            UA_UNLOCK(&client->clientMutex);
            return;
        }

        
        client->channel.connectionManager = cm;
        client->channel.connectionId = connectionId;
        *connectionContext = &client->channel;
    }

    if(state == UA_CONNECTIONSTATE_CLOSING) {
        UA_LOG_INFO_CHANNEL(client->config.logging, &client->channel,
                            "SecureChannel closed");

        UA_SecureChannelState oldState = client->channel.state;
        client->channel.state = UA_SECURECHANNELSTATE_CLOSING;

        
        if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
            client->sessionState = UA_SESSIONSTATE_CREATED;

        __Client_AsyncService_removeAll(client, UA_STATUSCODE_BADSECURECHANNELCLOSED);

        
        UA_SecureChannel_clear(&client->channel);

        if(oldState == UA_SECURECHANNELSTATE_CONNECTING &&
           client->connectStatus == UA_STATUSCODE_GOOD)
            client->connectStatus = fallbackEndpointUrl(client);

        
        goto continue_connect;
    }

    
    if(UA_LIKELY(state == UA_CONNECTIONSTATE_ESTABLISHED)) {
        if(client->channel.state == UA_SECURECHANNELSTATE_REVERSE_LISTENING)
            client->channel.state = UA_SECURECHANNELSTATE_REVERSE_CONNECTED;
        if(client->channel.state < UA_SECURECHANNELSTATE_CONNECTED)
            client->channel.state = UA_SECURECHANNELSTATE_CONNECTED;
    } else  {
        client->channel.state = UA_SECURECHANNELSTATE_CONNECTING;
    }

    
    UA_EventLoop *el = client->config.eventLoop;
    UA_DateTime nowMonotonic = el->dateTime_nowMonotonic(el);
    UA_StatusCode res =
        UA_SecureChannel_processBuffer(&client->channel, client,
                                       processServiceResponse,
                                       &msg, nowMonotonic);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "Processing the message returned the error code %s",
                     UA_StatusCode_name(res));

        if(client->channel.state != UA_SECURECHANNELSTATE_OPEN)
            client->connectStatus = res;

        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

 continue_connect:
    
    if(!isFullyConnected(client))
        connectActivity(client);
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
}


static void
initConnect(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);
    if(client->channel.state != UA_SECURECHANNELSTATE_CLOSED) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "Client connection already initiated");
        return;
    }

    
    client->connectStatus = __UA_Client_startup(client);
    UA_CHECK_STATUS(client->connectStatus, return);

    verifyClientApplicationURI(client);

    
    UA_SecureChannel_clear(&client->channel);
    client->channel.config = client->config.localConnectionConfig;
    client->channel.certificateVerification = &client->config.certificateVerification;
    client->channel.processOPNHeader = verifyClientSecureChannelHeader;

    
    client->connectStatus = initSecurityPolicy(client);
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        return;

    
    UA_String hostname = UA_STRING_NULL;
    UA_String path = UA_STRING_NULL;
    UA_UInt16 port = 4840;

    client->connectStatus =
        UA_parseEndpointUrl(&client->config.endpointUrl, &hostname, &port, &path);
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_NETWORK,
                       "Endpoint URL is invalid: %S", client->config.endpointUrl);
        return;
    }

    
    UA_String tcpString = UA_STRING("tcp");
    for(UA_EventSource *es = client->config.eventLoop->eventSources;
        es != NULL; es = es->next) {
        
        if(es->eventSourceType != UA_EVENTSOURCETYPE_CONNECTIONMANAGER)
            continue;
        UA_ConnectionManager *cm = (UA_ConnectionManager*)es;
        if(!UA_String_equal(&tcpString, &cm->protocol))
            continue;

        
        UA_KeyValuePair params[3];
        params[0].key = UA_QUALIFIEDNAME(0, "port");
        UA_Variant_setScalar(&params[0].value, &port, &UA_TYPES[UA_TYPES_UINT16]);
        params[1].key = UA_QUALIFIEDNAME(0, "address");
        UA_Variant_setScalar(&params[1].value, &hostname, &UA_TYPES[UA_TYPES_STRING]);
        params[2].key = UA_QUALIFIEDNAME(0, "reuse");
        UA_Variant_setScalar(&params[2].value, &client->config.tcpReuseAddr,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);

        UA_KeyValueMap paramMap;
        paramMap.map = params;
        paramMap.mapSize = 3;

        
        UA_UNLOCK(&client->clientMutex);
        UA_StatusCode res =
            cm->openConnection(cm, &paramMap, client, NULL, __Client_networkCallback);
        UA_LOCK(&client->clientMutex);
        if(res == UA_STATUSCODE_GOOD)
            break;
    }

    
    if(client->channel.state == UA_SECURECHANNELSTATE_CLOSED)
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;

    
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "Could not open a TCP connection to %S",
                       client->config.endpointUrl);
        client->connectStatus = UA_STATUSCODE_BADCONNECTIONCLOSED;
    }
}

void
connectSync(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    
    UA_EventLoop *el = client->config.eventLoop;
    UA_assert(el);

    UA_DateTime now = el->dateTime_nowMonotonic(el);
    UA_DateTime maxDate = now + ((UA_DateTime)client->config.timeout * UA_DATETIME_MSEC);

    
    initConnect(client);
    notifyClientState(client);
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        return;

    while(client->connectStatus == UA_STATUSCODE_GOOD &&
          !isFullyConnected(client)) {

        
        now = el->dateTime_nowMonotonic(el);
        if(maxDate < now) {
            UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                         "The connection has timed out before it could be fully opened");
            client->connectStatus = UA_STATUSCODE_BADTIMEOUT;
            closeSecureChannel(client);
        }

        
        UA_UNLOCK(&client->clientMutex);
        UA_StatusCode res = el->run(el, (UA_UInt32)((maxDate - now) / UA_DATETIME_MSEC));
        UA_LOCK(&client->clientMutex);
        if(res != UA_STATUSCODE_GOOD) {
            client->connectStatus = res;
            closeSecureChannel(client);
        }

        notifyClientState(client);
    }
}

UA_StatusCode
connectInternal(UA_Client *client, UA_Boolean async) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    client->connectStatus = UA_STATUSCODE_GOOD;

    if(async)
        initConnect(client);
    else
        connectSync(client);
    notifyClientState(client);
    return client->connectStatus;
}

UA_StatusCode
connectSecureChannel(UA_Client *client, const char *endpointUrl) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    UA_ClientConfig *cc = UA_Client_getConfig(client);
    cc->noSession = true;
    UA_String_clear(&cc->endpointUrl);
    cc->endpointUrl = UA_STRING_ALLOC(endpointUrl);
    return connectInternal(client, false);
}

UA_StatusCode
__UA_Client_connect(UA_Client *client, UA_Boolean async) {
    UA_LOCK(&client->clientMutex);
    connectInternal(client, async);
    UA_UNLOCK(&client->clientMutex);
    return client->connectStatus;
}

static UA_StatusCode
activateSessionSync(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    
    UA_EventLoop *el = client->config.eventLoop;
    UA_assert(el);

    UA_DateTime now = el->dateTime_nowMonotonic(el);
    UA_DateTime maxDate = now + ((UA_DateTime)client->config.timeout * UA_DATETIME_MSEC);

    
    UA_StatusCode res = activateSessionAsync(client);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    while(client->sessionState != UA_SESSIONSTATE_ACTIVATED &&
          client->connectStatus == UA_STATUSCODE_GOOD) {

        
        now = el->dateTime_nowMonotonic(el);
        if(maxDate < now) {
            UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                         "The connection has timed out before it could be fully opened");
            client->connectStatus = UA_STATUSCODE_BADTIMEOUT;
            closeSecureChannel(client);
        }

        
        UA_UNLOCK(&client->clientMutex);
        res = el->run(el, (UA_UInt32)((maxDate - now) / UA_DATETIME_MSEC));
        UA_LOCK(&client->clientMutex);
        if(res != UA_STATUSCODE_GOOD) {
            client->connectStatus = res;
            closeSecureChannel(client);
        }

        notifyClientState(client);
    }

    return client->connectStatus;
}

UA_StatusCode
UA_Client_activateCurrentSession(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    UA_StatusCode res = activateSessionSync(client);
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
    return res != UA_STATUSCODE_GOOD ? res : client->connectStatus;
}

UA_StatusCode
UA_Client_activateCurrentSessionAsync(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    UA_StatusCode res = activateSessionAsync(client);
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
    return res != UA_STATUSCODE_GOOD ? res : client->connectStatus;
}

UA_StatusCode
UA_Client_getSessionAuthenticationToken(UA_Client *client, UA_NodeId *authenticationToken,
                                        UA_ByteString *serverNonce) {
    UA_LOCK(&client->clientMutex);
    if(client->sessionState != UA_SESSIONSTATE_CREATED &&
       client->sessionState != UA_SESSIONSTATE_ACTIVATED) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "There is no current session");
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_BADSESSIONCLOSED;
    }

    UA_StatusCode res = UA_NodeId_copy(&client->authenticationToken, authenticationToken);
    res |= UA_ByteString_copy(&client->serverSessionNonce, serverNonce);
    UA_UNLOCK(&client->clientMutex);
    return res;
}

static UA_StatusCode
switchSession(UA_Client *client,
              const UA_NodeId authenticationToken,
              const UA_ByteString serverNonce) {
    
    if(client->sessionState != UA_SESSIONSTATE_CLOSED) {
        UA_LOG_ERROR(client->config.logging, UA_LOGCATEGORY_CLIENT,
                     "Cannot activate a session with a different AuthenticationToken "
                     "when the client already has a Session.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    UA_NodeId_clear(&client->authenticationToken);
    UA_ByteString_clear(&client->serverSessionNonce);
    UA_StatusCode res = UA_NodeId_copy(&authenticationToken, &client->authenticationToken);
    res |= UA_ByteString_copy(&serverNonce, &client->serverSessionNonce);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    
    client->sessionState = UA_SESSIONSTATE_CREATED;
    notifyClientState(client);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Client_activateSession(UA_Client *client,
                          const UA_NodeId authenticationToken,
                          const UA_ByteString serverNonce) {
    UA_LOCK(&client->clientMutex);
    UA_StatusCode res = switchSession(client, authenticationToken, serverNonce);
    if(res != UA_STATUSCODE_GOOD) {
        UA_UNLOCK(&client->clientMutex);
        return res;
    }
    res = activateSessionSync(client);
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
    return res != UA_STATUSCODE_GOOD ? res : client->connectStatus;
}

UA_StatusCode
UA_Client_activateSessionAsync(UA_Client *client,
                               const UA_NodeId authenticationToken,
                               const UA_ByteString serverNonce) {
    UA_LOCK(&client->clientMutex);
    UA_StatusCode res = switchSession(client, authenticationToken, serverNonce);
    if(res != UA_STATUSCODE_GOOD) {
        UA_UNLOCK(&client->clientMutex);
        return res;
    }
    res = activateSessionAsync(client);
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
    return res != UA_STATUSCODE_GOOD ? res : client->connectStatus;
}

static void
__Client_reverseConnectCallback(UA_ConnectionManager *cm, uintptr_t connectionId,
                         void *application, void **connectionContext,
                         UA_ConnectionState state, const UA_KeyValueMap *params,
                         UA_ByteString msg) {

    UA_Client *client = (UA_Client*)application;

    UA_LOCK(&client->clientMutex);

    if(!client->channel.connectionId) {
        client->channel.connectionId = connectionId;
        *connectionContext = REVERSE_CONNECT_INDICATOR;
    }

    if(*connectionContext == REVERSE_CONNECT_INDICATOR &&
       state == UA_CONNECTIONSTATE_CLOSING) {
        if(client->channel.connectionId == connectionId) {
            client->channel.state = UA_SECURECHANNELSTATE_CLOSED;
            notifyClientState(client);
        }
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    if(client->channel.connectionId == connectionId &&
       *connectionContext == REVERSE_CONNECT_INDICATOR) {
        client->channel.state = UA_SECURECHANNELSTATE_REVERSE_LISTENING;
        notifyClientState(client);
    }

    if(client->channel.connectionId != connectionId) {
        cm->closeConnection(cm, client->channel.connectionId);
        client->channel.connectionId = 0;
        *connectionContext = NULL;
    }

    if(*connectionContext != REVERSE_CONNECT_INDICATOR) {
        UA_UNLOCK(&client->clientMutex);
        __Client_networkCallback(cm, connectionId, application,
                                 connectionContext, state, params, msg);
        return;
    }

    UA_UNLOCK(&client->clientMutex);
}

UA_StatusCode
UA_Client_startListeningForReverseConnect(UA_Client *client,
                                          const UA_String *listenHostnames,
                                          size_t listenHostnamesLength,
                                          UA_UInt16 port) {
    UA_LOCK(&client->clientMutex);

    if(client->channel.state != UA_SECURECHANNELSTATE_CLOSED) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "Unable to listen for reverse connect while the client "
                       "is connected or already listening");
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_BADINVALIDSTATE;
    }

    const UA_String tcpString = UA_STRING_STATIC("tcp");
    UA_StatusCode res = UA_STATUSCODE_BADINTERNALERROR;

    client->connectStatus = UA_STATUSCODE_GOOD;
    client->channel.renewState = UA_SECURECHANNELRENEWSTATE_NORMAL;

    UA_SecureChannel_init(&client->channel);
    client->channel.config = client->config.localConnectionConfig;
    client->channel.certificateVerification = &client->config.certificateVerification;
    client->channel.processOPNHeader = verifyClientSecureChannelHeader;
    client->channel.connectionId = 0;

    client->connectStatus = initSecurityPolicy(client);
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        return client->connectStatus;

    UA_EventLoop *el = client->config.eventLoop;
    if(!el) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "No EventLoop configured");
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(el->state != UA_EVENTLOOPSTATE_STARTED) {
        res = el->start(el);
        UA_CHECK_STATUS(res, UA_UNLOCK(&client->clientMutex); return res);
    }

    UA_ConnectionManager *cm = NULL;
    for(UA_EventSource *es = el->eventSources; es != NULL; es = es->next) {
        if(es->eventSourceType != UA_EVENTSOURCETYPE_CONNECTIONMANAGER)
            continue;
        cm = (UA_ConnectionManager*)es;
        if(UA_String_equal(&tcpString, &cm->protocol))
            break;
        cm = NULL;
    }

    if(!cm) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "Could not find a TCP connection manager, unable to "
                       "listen for reverse connect");
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    client->channel.connectionManager = cm;

    UA_KeyValuePair params[4];
    bool booleanTrue = true;
    params[0].key = UA_QUALIFIEDNAME(0, "port");
    UA_Variant_setScalar(&params[0].value, &port, &UA_TYPES[UA_TYPES_UINT16]);
    params[1].key = UA_QUALIFIEDNAME(0, "address");
    UA_Variant_setArray(&params[1].value, (void *)(uintptr_t)listenHostnames,
            listenHostnamesLength, &UA_TYPES[UA_TYPES_STRING]);
    params[2].key = UA_QUALIFIEDNAME(0, "listen");
    UA_Variant_setScalar(&params[2].value, &booleanTrue, &UA_TYPES[UA_TYPES_BOOLEAN]);
    params[3].key = UA_QUALIFIEDNAME(0, "reuse");
    UA_Variant_setScalar(&params[3].value, &client->config.tcpReuseAddr,
                         &UA_TYPES[UA_TYPES_BOOLEAN]);

    UA_KeyValueMap paramMap;
    paramMap.map = params;
    paramMap.mapSize = 4;

    UA_UNLOCK(&client->clientMutex);
    res = cm->openConnection(cm, &paramMap, client, NULL, __Client_reverseConnectCallback);
    UA_LOCK(&client->clientMutex);

    
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(client->config.logging, UA_LOGCATEGORY_CLIENT,
                       "Failed to open a listening TCP socket for reverse connect");
        res = UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    UA_UNLOCK(&client->clientMutex);
    return res;
}





void
closeSecureChannel(UA_Client *client) {
    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
        client->sessionState = UA_SESSIONSTATE_CREATED;

    
    if(client->channel.state == UA_SECURECHANNELSTATE_CLOSING ||
       client->channel.state == UA_SECURECHANNELSTATE_CLOSED)
        return;

    UA_LOG_DEBUG_CHANNEL(client->config.logging, &client->channel,
                         "Closing the channel");

    
    if(client->channel.state == UA_SECURECHANNELSTATE_OPEN) {
        UA_LOG_DEBUG_CHANNEL(client->config.logging, &client->channel,
                             "Sending the CLO message");

        UA_EventLoop *el = client->config.eventLoop;

        
        UA_CloseSecureChannelRequest request;
        UA_CloseSecureChannelRequest_init(&request);
        request.requestHeader.requestHandle = ++client->requestHandle;
        request.requestHeader.timestamp = el->dateTime_now(el);
        request.requestHeader.timeoutHint = client->config.timeout;
        request.requestHeader.authenticationToken = client->authenticationToken;
        UA_SecureChannel_sendSymmetricMessage(&client->channel, ++client->requestId,
                                              UA_MESSAGETYPE_CLO, &request,
                                              &UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
    }

    UA_SecureChannel_shutdown(&client->channel, UA_SHUTDOWNREASON_CLOSE);
}

static void
sendCloseSession(UA_Client *client) {
    UA_CloseSessionRequest request;
    UA_CloseSessionRequest_init(&request);
    request.deleteSubscriptions = true;
    UA_CloseSessionResponse response;
    __Client_Service(client, &request, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST],
                        &response, &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE]);
    UA_CloseSessionRequest_clear(&request);
    UA_CloseSessionResponse_clear(&response);

    client->sessionState = UA_SESSIONSTATE_CLOSING;
}

void
cleanupSession(UA_Client *client) {
    UA_NodeId_clear(&client->authenticationToken);
    client->requestHandle = 0;

#ifdef UA_ENABLE_SUBSCRIPTIONS
    
    __Client_Subscriptions_clear(client);
#endif

    
    __Client_AsyncService_removeAll(client, UA_STATUSCODE_BADSESSIONCLOSED);

#ifdef UA_ENABLE_SUBSCRIPTIONS
    client->currentlyOutStandingPublishRequests = 0;
#endif

    client->sessionState = UA_SESSIONSTATE_CLOSED;
}

static void
disconnectSecureChannel(UA_Client *client, UA_Boolean sync) {
    
    UA_String_clear(&client->discoveryUrl);

    
    closeSecureChannel(client);

    
    if(client->connectStatus == UA_STATUSCODE_GOOD)
        client->connectStatus = UA_STATUSCODE_BADCONNECTIONCLOSED;

    
    UA_EventLoop *el = client->config.eventLoop;
    if(sync && el &&
       el->state != UA_EVENTLOOPSTATE_FRESH &&
       el->state != UA_EVENTLOOPSTATE_STOPPED) {
        UA_UNLOCK(&client->clientMutex);
        while(client->channel.state != UA_SECURECHANNELSTATE_CLOSED) {
            el->run(el, 100);
        }
        UA_LOCK(&client->clientMutex);
    }

    notifyClientState(client);
}

UA_StatusCode
UA_Client_disconnectSecureChannel(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    disconnectSecureChannel(client, true);
    UA_UNLOCK(&client->clientMutex);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Client_disconnectSecureChannelAsync(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    disconnectSecureChannel(client, false);
    UA_UNLOCK(&client->clientMutex);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Client_disconnect(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
        sendCloseSession(client);
    cleanupSession(client);
    disconnectSecureChannel(client, true);
    UA_UNLOCK(&client->clientMutex);
    return UA_STATUSCODE_GOOD;
}

static void
closeSessionCallback(UA_Client *client, void *userdata,
                     UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);
    cleanupSession(client);
    disconnectSecureChannel(client, false);
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
}

UA_StatusCode
UA_Client_disconnectAsync(UA_Client *client) {
    UA_LOCK(&client->clientMutex);

    if(client->sessionState == UA_SESSIONSTATE_CLOSED ||
       client->sessionState == UA_SESSIONSTATE_CLOSING) {
        disconnectSecureChannel(client, false);
        notifyClientState(client);
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_GOOD;
    }

    
    client->sessionState = UA_SESSIONSTATE_CLOSING;

    UA_CloseSessionRequest request;
    UA_CloseSessionRequest_init(&request);
    request.deleteSubscriptions = true;
    UA_StatusCode res =
        __Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST],
                              (UA_ClientAsyncServiceCallback)closeSessionCallback,
                              &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE], NULL, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        cleanupSession(client);
        disconnectSecureChannel(client, false);
    }

    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
    return res;
}
