
#include "ua_server_internal.h"
#include "ua_services.h"


static void
removeSessionCallback(UA_Server *server, session_list_entry *entry) {
    UA_LOCK(&server->serviceMutex);
    UA_Session_clear(&entry->session, server);
    UA_UNLOCK(&server->serviceMutex);
    UA_free(entry);
}

void
UA_Server_removeSession(UA_Server *server, session_list_entry *sentry,
                        UA_ShutdownReason shutdownReason) {
    UA_Session *session = &sentry->session;

    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
#ifdef UA_ENABLE_SUBSCRIPTIONS
    UA_Subscription *sub, *tempsub;
    TAILQ_FOREACH_SAFE(sub, &session->subscriptions, sessionListEntry, tempsub) {
        UA_Subscription_delete(server, sub);
    }

    UA_PublishResponseEntry *entry;
    while((entry = UA_Session_dequeuePublishReq(session))) {
        UA_PublishResponse_clear(&entry->response);
        UA_free(entry);
    }
#endif

    
    if(server->config.accessControl.closeSession) {
        UA_UNLOCK(&server->serviceMutex);
        server->config.accessControl.
            closeSession(server, &server->config.accessControl,
                         &session->sessionId, session->context);
        UA_LOCK(&server->serviceMutex);
    }

    
    UA_Session_detachFromSecureChannel(session);

    
    if(sentry->session.activated) {
        sentry->session.activated = false;
        server->activeSessionCount--;
    }

    LIST_REMOVE(sentry, pointers);
    server->sessionCount--;

    switch(shutdownReason) {
    case UA_SHUTDOWNREASON_CLOSE:
    case UA_SHUTDOWNREASON_PURGE:
        break;
    case UA_SHUTDOWNREASON_TIMEOUT:
        server->serverDiagnosticsSummary.sessionTimeoutCount++;
        break;
    case UA_SHUTDOWNREASON_REJECT:
        server->serverDiagnosticsSummary.rejectedSessionCount++;
        break;
    case UA_SHUTDOWNREASON_SECURITYREJECT:
        server->serverDiagnosticsSummary.securityRejectedSessionCount++;
        break;
    case UA_SHUTDOWNREASON_ABORT:
        server->serverDiagnosticsSummary.sessionAbortCount++;
        break;
    default:
        UA_assert(false);
        break;
    }

    sentry->cleanupCallback.callback = (UA_Callback)removeSessionCallback;
    sentry->cleanupCallback.application = server;
    sentry->cleanupCallback.context = sentry;
    UA_EventLoop *el = server->config.eventLoop;
    el->addDelayedCallback(el, &sentry->cleanupCallback);
}

UA_StatusCode
UA_Server_removeSessionByToken(UA_Server *server, const UA_NodeId *token,
                               UA_ShutdownReason shutdownReason) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    session_list_entry *entry;
    LIST_FOREACH(entry, &server->sessions, pointers) {
        if(UA_NodeId_equal(&entry->session.authenticationToken, token)) {
            UA_Server_removeSession(server, entry, shutdownReason);
            return UA_STATUSCODE_GOOD;
        }
    }
    return UA_STATUSCODE_BADSESSIONIDINVALID;
}

void
UA_Server_cleanupSessions(UA_Server *server, UA_DateTime nowMonotonic) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    session_list_entry *sentry, *temp;
    LIST_FOREACH_SAFE(sentry, &server->sessions, pointers, temp) {
        
        if(sentry->session.validTill >= nowMonotonic)
            continue;
        UA_LOG_INFO_SESSION(server->config.logging, &sentry->session,
                            "Session has timed out");
        UA_Server_removeSession(server, sentry, UA_SHUTDOWNREASON_TIMEOUT);
    }
}





UA_Session *
getSessionByToken(UA_Server *server, const UA_NodeId *token) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    session_list_entry *current = NULL;
    LIST_FOREACH(current, &server->sessions, pointers) {
        
        if(!UA_NodeId_equal(&current->session.authenticationToken, token))
            continue;

        
        UA_EventLoop *el = server->config.eventLoop;
        UA_DateTime now = el->dateTime_nowMonotonic(el);
        if(now > current->session.validTill) {
            UA_LOG_INFO_SESSION(server->config.logging, &current->session,
                                "Client tries to use a session that has timed out");
            return NULL;
        }

        return &current->session;
    }

    return NULL;
}

UA_Session *
getSessionById(UA_Server *server, const UA_NodeId *sessionId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    session_list_entry *current = NULL;
    LIST_FOREACH(current, &server->sessions, pointers) {
        
        if(!UA_NodeId_equal(&current->session.sessionId, sessionId))
            continue;

        
        UA_EventLoop *el = server->config.eventLoop;
        UA_DateTime now = el->dateTime_nowMonotonic(el);
        if(now > current->session.validTill) {
            UA_LOG_INFO_SESSION(server->config.logging, &current->session,
                                "Client tries to use a session that has timed out");
            return NULL;
        }

        return &current->session;
    }

    if(UA_NodeId_equal(sessionId, &server->adminSession.sessionId))
        return &server->adminSession;

    return NULL;
}

static UA_StatusCode
signCreateSessionResponse(UA_Server *server, UA_SecureChannel *channel,
                          const UA_CreateSessionRequest *request,
                          UA_CreateSessionResponse *response) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    const UA_SecurityPolicy *securityPolicy = channel->securityPolicy;
    UA_SignatureData *signatureData = &response->serverSignature;

    
    const UA_SecurityPolicySignatureAlgorithm *signAlg =
        &securityPolicy->asymmetricModule.cryptoModule.signatureAlgorithm;
    size_t signatureSize = signAlg->getLocalSignatureSize(channel->channelContext);
    UA_StatusCode retval = UA_String_copy(&signAlg->uri, &signatureData->algorithm);
    retval |= UA_ByteString_allocBuffer(&signatureData->signature, signatureSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    size_t dataToSignSize =
        request->clientCertificate.length + request->clientNonce.length;
    UA_ByteString dataToSign;
    retval = UA_ByteString_allocBuffer(&dataToSign, dataToSignSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval; 

    
    memcpy(dataToSign.data, request->clientCertificate.data,
           request->clientCertificate.length);
    memcpy(dataToSign.data + request->clientCertificate.length,
           request->clientNonce.data, request->clientNonce.length);
    retval = securityPolicy->asymmetricModule.cryptoModule.signatureAlgorithm.
        sign(channel->channelContext, &dataToSign, &signatureData->signature);

    
    UA_ByteString_clear(&dataToSign);
    return retval;
}


UA_StatusCode
UA_Server_createSession(UA_Server *server, UA_SecureChannel *channel,
                        const UA_CreateSessionRequest *request, UA_Session **session) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(server->sessionCount >= server->config.maxSessions) {
        UA_LOG_WARNING_CHANNEL(server->config.logging, channel,
                               "Could not create a Session - Server limits reached");
        return UA_STATUSCODE_BADTOOMANYSESSIONS;
    }

    session_list_entry *newentry = (session_list_entry*)
        UA_malloc(sizeof(session_list_entry));
    if(!newentry)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    
    UA_Session_init(&newentry->session);
    newentry->session.sessionId = UA_NODEID_GUID(1, UA_Guid_random());
    newentry->session.authenticationToken = UA_NODEID_GUID(1, UA_Guid_random());

    newentry->session.timeout = server->config.maxSessionTimeout;
    if(request->requestedSessionTimeout <= server->config.maxSessionTimeout &&
       request->requestedSessionTimeout > 0)
        newentry->session.timeout = request->requestedSessionTimeout;

    
    if(channel)
        UA_Session_attachToSecureChannel(&newentry->session, channel);

    UA_EventLoop *el = server->config.eventLoop;
    UA_DateTime now = el->dateTime_now(el);
    UA_DateTime nowMonotonic = el->dateTime_nowMonotonic(el);
    UA_Session_updateLifetime(&newentry->session, now, nowMonotonic);

    
    LIST_INSERT_HEAD(&server->sessions, newentry, pointers);
    server->sessionCount++;

    *session = &newentry->session;
    return UA_STATUSCODE_GOOD;
}

void
Service_CreateSession(UA_Server *server, UA_SecureChannel *channel,
                      const UA_CreateSessionRequest *request,
                      UA_CreateSessionResponse *response) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_LOG_DEBUG_CHANNEL(server->config.logging, channel, "Trying to create session");

    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        UA_StatusCode retval = channel->securityPolicy->channelModule.
            compareCertificate(channel->channelContext, &request->clientCertificate);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING_CHANNEL(server->config.logging, channel,
                                   "The client certificate did not validate");
            response->responseHeader.serviceResult = UA_STATUSCODE_BADCERTIFICATEINVALID;
            return;
        }
    }

    UA_assert(channel->securityToken.channelId != 0);

    if(!UA_ByteString_equal(&channel->securityPolicy->policyUri,
                            &UA_SECURITY_POLICY_NONE_URI) &&
       request->clientNonce.length < 32) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADNONCEINVALID;
        return;
    }

    if(request->clientCertificate.length > 0) {
        response->responseHeader.serviceResult =
            UA_CertificateUtils_verifyApplicationURI(server->config.allowAllCertificateUris,
                                                     &request->clientCertificate,
                                                     &request->clientDescription.applicationUri);
        if(response->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING_CHANNEL(server->config.logging, channel,
                                   "The client's ApplicationURI did not match the certificate");
            server->serverDiagnosticsSummary.securityRejectedSessionCount++;
            server->serverDiagnosticsSummary.rejectedSessionCount++;
            return;
        }
    }

    
    UA_Session *newSession = NULL;
    response->responseHeader.serviceResult =
        UA_Server_createSession(server, channel, request, &newSession);
    if(response->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_CHANNEL(server->config.logging, channel,
                               "Processing CreateSessionRequest failed");
        server->serverDiagnosticsSummary.rejectedSessionCount++;
        return;
    }

    
    response->responseHeader.serviceResult |=
        UA_String_copy(&request->sessionName, &newSession->sessionName);
    if(newSession->sessionName.length == 0)
        response->responseHeader.serviceResult |=
            UA_NodeId_print(&newSession->sessionId, &newSession->sessionName);

    response->responseHeader.serviceResult |= UA_Session_generateNonce(newSession);
    newSession->maxResponseMessageSize = request->maxResponseMessageSize;
    newSession->maxRequestMessageSize = channel->config.localMaxMessageSize;
    response->responseHeader.serviceResult |=
        UA_ApplicationDescription_copy(&request->clientDescription,
                                       &newSession->clientDescription);

#ifdef UA_ENABLE_DIAGNOSTICS
    response->responseHeader.serviceResult |=
        UA_String_copy(&request->serverUri, &newSession->diagnostics.serverUri);
    response->responseHeader.serviceResult |=
        UA_String_copy(&request->endpointUrl, &newSession->diagnostics.endpointUrl);
#endif

    
    response->sessionId = newSession->sessionId;
    response->revisedSessionTimeout = (UA_Double)newSession->timeout;
    response->authenticationToken = newSession->authenticationToken;
    response->responseHeader.serviceResult |=
        UA_ByteString_copy(&newSession->serverNonce, &response->serverNonce);

    
    response->responseHeader.serviceResult =
        setCurrentEndPointsArray(server, request->endpointUrl, NULL, 0,
                                 &response->serverEndpoints,
                                 &response->serverEndpointsSize);
    if(response->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_Server_removeSessionByToken(server, &newSession->authenticationToken,
                                       UA_SHUTDOWNREASON_REJECT);
        return;
    }

    const UA_SecurityPolicy *sp = channel->securityPolicy;
    if(UA_String_equal(&UA_SECURITY_POLICY_NONE_URI, &sp->policyUri) ||
       sp->localCertificate.length == 0)
        sp = getDefaultEncryptedSecurityPolicy(server);
    if(sp)
        response->responseHeader.serviceResult |=
            UA_ByteString_copy(&sp->localCertificate, &response->serverCertificate);

    
    response->responseHeader.serviceResult |=
       signCreateSessionResponse(server, channel, request, response);

    
    if(response->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_Server_removeSessionByToken(server, &newSession->authenticationToken,
                                       UA_SHUTDOWNREASON_REJECT);
        return;
    }

#ifdef UA_ENABLE_DIAGNOSTICS
    UA_EventLoop *el = server->config.eventLoop;
    newSession->diagnostics.clientConnectionTime = el->dateTime_now(el);
    newSession->diagnostics.clientLastContactTime =
        newSession->diagnostics.clientConnectionTime;

    
    createSessionObject(server, newSession);
#endif

    UA_LOG_INFO_SESSION(server->config.logging, newSession, "Session created");
}

static UA_StatusCode
checkCertificateSignature(const UA_Server *server, const UA_SecurityPolicy *securityPolicy,
                          void *channelContext, const UA_ByteString *serverNonce,
                          const UA_SignatureData *signature,
                          const bool isUserTokenSignature) {
    
    if(signature->signature.length == 0) {
        if(isUserTokenSignature)
            return UA_STATUSCODE_BADUSERSIGNATUREINVALID;
        return UA_STATUSCODE_BADAPPLICATIONSIGNATUREINVALID;
    }

    if(!securityPolicy)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    const UA_ByteString *localCertificate = &securityPolicy->localCertificate;
    
    UA_ByteString dataToVerify;
    size_t dataToVerifySize = localCertificate->length + serverNonce->length;
    UA_StatusCode retval = UA_ByteString_allocBuffer(&dataToVerify, dataToVerifySize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    memcpy(dataToVerify.data, localCertificate->data, localCertificate->length);
    memcpy(dataToVerify.data + localCertificate->length,
           serverNonce->data, serverNonce->length);
    retval = securityPolicy->asymmetricModule.cryptoModule.signatureAlgorithm.
        verify(channelContext, &dataToVerify, &signature->signature);
    UA_ByteString_clear(&dataToVerify);
    if(retval != UA_STATUSCODE_GOOD) {
        if(isUserTokenSignature)
            retval = UA_STATUSCODE_BADUSERSIGNATUREINVALID;
        else
            retval = UA_STATUSCODE_BADAPPLICATIONSIGNATUREINVALID;
    }
    return retval;
}

static void
selectEndpointAndTokenPolicy(UA_Server *server, UA_SecureChannel *channel,
                             const UA_ExtensionObject *identityToken,
                             const UA_EndpointDescription **ed,
                             const UA_UserTokenPolicy **utp,
                             const UA_SecurityPolicy **tokenSp) {
    for(size_t i = 0; i < server->config.endpointsSize; ++i) {
        const UA_EndpointDescription *desc = &server->config.endpoints[i];

        
        if(desc->securityMode != channel->securityMode)
            continue;

        
        if(!UA_String_equal(&desc->securityPolicyUri, &channel->securityPolicy->policyUri))
            continue;

        size_t identPoliciesSize = desc->userIdentityTokensSize;
        const UA_UserTokenPolicy *identPolicies = desc->userIdentityTokens;
        if(identPoliciesSize == 0) {
            identPoliciesSize = server->config.accessControl.userTokenPoliciesSize;
            identPolicies = server->config.accessControl.userTokenPolicies;
        }

        
        const UA_DataType *tokenDataType = identityToken->content.decoded.type;
        for(size_t j = 0; j < identPoliciesSize ; j++) {
            const UA_UserTokenPolicy *pol = &identPolicies[j];

            if(!UA_String_equal(&desc->securityPolicyUri, &pol->securityPolicyUri))
                continue;

            if(identityToken->encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY &&
               pol->tokenType == UA_USERTOKENTYPE_ANONYMOUS) {
                *ed = desc;
                *utp = pol;
                return;
            }

            
            if(!tokenDataType)
                continue;

            if(pol->tokenType == UA_USERTOKENTYPE_ANONYMOUS) {
                if(tokenDataType != &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN])
                    continue;
            } else if(pol->tokenType == UA_USERTOKENTYPE_USERNAME) {
                if(tokenDataType != &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN])
                    continue;
            } else if(pol->tokenType == UA_USERTOKENTYPE_CERTIFICATE) {
                if(tokenDataType != &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN])
                    continue;
            } else if(pol->tokenType == UA_USERTOKENTYPE_ISSUEDTOKEN) {
                if(tokenDataType != &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN])
                    continue;
            } else {
                continue;
            }

            
            UA_AnonymousIdentityToken *token = (UA_AnonymousIdentityToken*)
                identityToken->content.decoded.data;

            if(pol->policyId.length > token->policyId.length)
                continue;
            UA_String tmpId = token->policyId;
            tmpId.length = pol->policyId.length;
            if(!UA_String_equal(&tmpId, &pol->policyId))
                continue;

            
            *ed = desc;
            *utp = pol;

            *tokenSp = channel->securityPolicy;
            if(pol->securityPolicyUri.length > 0)
                *tokenSp = getSecurityPolicyByUri(server, &pol->securityPolicyUri);

#ifdef UA_ENABLE_ENCRYPTION
            if(!*tokenSp ||
               (!server->config.allowNonePolicyPassword &&
                ((*tokenSp)->localCertificate.length == 0 ||
                 UA_String_equal(&UA_SECURITY_POLICY_NONE_URI, &(*tokenSp)->policyUri))))
                *tokenSp = getDefaultEncryptedSecurityPolicy(server);
#endif

            
            return;
        }
    }
}

static UA_StatusCode
decryptUserNamePW(UA_Server *server, UA_Session *session,
                  const UA_SecurityPolicy *sp,
                  UA_UserNameIdentityToken *userToken) {
    
    if(UA_String_equal(&sp->policyUri, &UA_SECURITY_POLICY_NONE_URI)) {
        if(userToken->encryptionAlgorithm.length > 0)
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

        UA_LOG_WARNING_SESSION(server->config.logging, session, "ActivateSession: "
                               "Received an unencrypted username/passwort. "
                               "Is the server misconfigured to allow that?");
        return UA_STATUSCODE_GOOD;
    }

    
    if(!UA_String_equal(&userToken->encryptionAlgorithm,
                        &sp->asymmetricModule.cryptoModule.encryptionAlgorithm.uri))
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

    void *tempChannelContext = NULL;
    UA_UNLOCK(&server->serviceMutex);
    UA_StatusCode res =
        sp->channelModule.newContext(sp, &sp->localCertificate, &tempChannelContext);
    UA_LOCK(&server->serviceMutex);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "ActivateSession: Failed to create a context for "
                               "the SecurityPolicy %S", sp->policyUri);
        return res;
    }

    UA_UInt32 secretLen = 0;
    UA_ByteString secret, tokenNonce;
    size_t tokenpos = 0;
    size_t offset = 0;
    UA_ByteString *sn = &session->serverNonce;
    const UA_SecurityPolicyEncryptionAlgorithm *asymEnc =
        &sp->asymmetricModule.cryptoModule.encryptionAlgorithm;

    res = UA_STATUSCODE_BADIDENTITYTOKENINVALID;

    
    if(UA_ByteString_copy(&userToken->password, &secret) != UA_STATUSCODE_GOOD ||
       asymEnc->decrypt(tempChannelContext, &secret) != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    if(UA_UInt32_decodeBinary(&secret, &offset,
                              &secretLen) != UA_STATUSCODE_GOOD)
        goto cleanup;

    if(secret.length < sizeof(UA_UInt32) + sn->length ||
       secret.length < sizeof(UA_UInt32) + secretLen ||
       secretLen < sn->length)
        goto cleanup;

    for(size_t i = sizeof(UA_UInt32) + secretLen; i < secret.length; i++) {
        if(secret.data[i] != 0)
            goto cleanup;
    }

    tokenpos = sizeof(UA_UInt32) + secretLen - sn->length;
    tokenNonce.length = sn->length;
    tokenNonce.data = &secret.data[tokenpos];
    if(!UA_ByteString_equal(sn, &tokenNonce))
        goto cleanup;

    memcpy(userToken->password.data,
           &secret.data[sizeof(UA_UInt32)], secretLen - sn->length);
    userToken->password.length = secretLen - sn->length;
    res = UA_STATUSCODE_GOOD;

 cleanup:
    UA_ByteString_clear(&secret);

    
    UA_UNLOCK(&server->serviceMutex);
    sp->channelModule.deleteContext(tempChannelContext);
    UA_LOCK(&server->serviceMutex);

    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "ActivateSession: Failed to decrypt the "
                               "password with the StatusCode %s",
                               UA_StatusCode_name(res));
    }
    return res;
}

static UA_StatusCode
checkActivateSessionX509(UA_Server *server, UA_Session *session,
                         const UA_SecurityPolicy *sp, UA_X509IdentityToken* token,
                         const UA_SignatureData *tokenSignature) {
    
    if(UA_String_equal(&sp->policyUri, &UA_SECURITY_POLICY_NONE_URI))
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

    void *tempChannelContext;
    UA_UNLOCK(&server->serviceMutex);
    UA_StatusCode res = sp->channelModule.
        newContext(sp, &token->certificateData, &tempChannelContext);
    UA_LOCK(&server->serviceMutex);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "ActivateSession: Failed to create a context "
                               "for the SecurityPolicy %S", sp->policyUri);
        return res;
    }

    
    res = checkCertificateSignature(server, sp, tempChannelContext,
                                    &session->serverNonce, tokenSignature, true);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "ActivateSession: User token signature check "
                               "failed with StatusCode %s", UA_StatusCode_name(res));
    }

    
    UA_UNLOCK(&server->serviceMutex);
    sp->channelModule.deleteContext(tempChannelContext);
    UA_LOCK(&server->serviceMutex);
    return res;
}


void
Service_ActivateSession(UA_Server *server, UA_SecureChannel *channel,
                        const UA_ActivateSessionRequest *req,
                        UA_ActivateSessionResponse *resp) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    const UA_EndpointDescription *ed = NULL;
    const UA_UserTokenPolicy *utp = NULL;
    const UA_SecurityPolicy *tokenSp = NULL;
    UA_String *tmpLocaleIds;

    
    UA_Session *session = getSessionByToken(server, &req->requestHeader.authenticationToken);
    if(!session) {
        UA_LOG_WARNING_CHANNEL(server->config.logging, channel,
                               "ActivateSession: Session not found");
        resp->responseHeader.serviceResult = UA_STATUSCODE_BADSESSIONIDINVALID;
        goto rejected;
    }

    if(!session->activated && session->channel != channel) {
        UA_LOG_WARNING_CHANNEL(server->config.logging, channel,
                               "ActivateSession: The Session has to be initially activated "
                               "on the SecureChannel that created it");
        resp->responseHeader.serviceResult = UA_STATUSCODE_BADSESSIONIDINVALID;
        goto rejected;
    }

    
    UA_EventLoop *el = server->config.eventLoop;
    UA_DateTime nowMonotonic = el->dateTime_nowMonotonic(el);
    if(session->validTill < nowMonotonic) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "ActivateSession: The Session has timed out");
        resp->responseHeader.serviceResult = UA_STATUSCODE_BADSESSIONIDINVALID;
        goto rejected;
    }

    
    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        resp->responseHeader.serviceResult =
            checkCertificateSignature(server, channel->securityPolicy,
                                      channel->channelContext,
                                      &session->serverNonce,
                                      &req->clientSignature, false);
        if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING_SESSION(server->config.logging, session,
                                   "ActivateSession: Client signature check failed "
                                   "with StatusCode %s",
                                   UA_StatusCode_name(resp->responseHeader.serviceResult));
            goto securityRejected;
        }
    }

    selectEndpointAndTokenPolicy(server, channel, &req->userIdentityToken,
                                 &ed, &utp, &tokenSp);
    if(!ed || !tokenSp) {
        resp->responseHeader.serviceResult = UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        goto rejected;
    }

    if(utp->tokenType == UA_USERTOKENTYPE_USERNAME) {
        
       UA_UserNameIdentityToken *userToken = (UA_UserNameIdentityToken *)
           req->userIdentityToken.content.decoded.data;
       resp->responseHeader.serviceResult =
           decryptUserNamePW(server, session, tokenSp, userToken);
       if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD)
           goto securityRejected;
    } else if(utp->tokenType == UA_USERTOKENTYPE_CERTIFICATE) {
        UA_X509IdentityToken* token = (UA_X509IdentityToken*)
            req->userIdentityToken.content.decoded.data;
       resp->responseHeader.serviceResult =
           checkActivateSessionX509(server, session, tokenSp,
                                    token, &req->userTokenSignature);
       if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD)
           goto securityRejected;
    }

    
    UA_UNLOCK(&server->serviceMutex);
    resp->responseHeader.serviceResult = server->config.accessControl.
        activateSession(server, &server->config.accessControl, ed,
                        &channel->remoteCertificate, &session->sessionId,
                        &req->userIdentityToken, &session->context);
    UA_LOCK(&server->serviceMutex);
    if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "ActivateSession: The AccessControl "
                               "plugin denied the activation with the StatusCode %s",
                               UA_StatusCode_name(resp->responseHeader.serviceResult));
        goto securityRejected;
    }

    if(!session->channel || session->channel != channel) {
        
        UA_Session_attachToSecureChannel(session, channel);
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "ActivateSession: Session attached to new channel");
    }

    
    resp->responseHeader.serviceResult = UA_Session_generateNonce(session);
    resp->responseHeader.serviceResult |=
        UA_ByteString_copy(&session->serverNonce, &resp->serverNonce);
    if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_Session_detachFromSecureChannel(session);
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "ActivateSession: Could not generate the server nonce");
        goto rejected;
    }

    
    if(req->localeIdsSize > 0) {
        resp->responseHeader.serviceResult |=
            UA_Array_copy(req->localeIds, req->localeIdsSize,
                          (void**)&tmpLocaleIds, &UA_TYPES[UA_TYPES_STRING]);
        if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
            UA_Session_detachFromSecureChannel(session);
            UA_LOG_WARNING_SESSION(server->config.logging, session,
                                   "ActivateSession: Could not store the Session LocaleIds");
            goto rejected;
        }
        UA_Array_delete(session->localeIds, session->localeIdsSize,
                        &UA_TYPES[UA_TYPES_STRING]);
        session->localeIds = tmpLocaleIds;
        session->localeIdsSize = req->localeIdsSize;
    }

    
    nowMonotonic = el->dateTime_nowMonotonic(el);
    UA_DateTime now = el->dateTime_now(el);
    UA_Session_updateLifetime(session, now, nowMonotonic);

    
    if(!session->activated) {
        session->activated = true;
        server->activeSessionCount++;
        server->serverDiagnosticsSummary.cumulatedSessionCount++;
    }

    
    UA_String_clear(&session->clientUserIdOfSession);
    const UA_DataType *tokenType = req->userIdentityToken.content.decoded.type;
    if(tokenType == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
        const UA_UserNameIdentityToken *userToken = (UA_UserNameIdentityToken*)
            req->userIdentityToken.content.decoded.data;
        UA_String_copy(&userToken->userName, &session->clientUserIdOfSession);
    } else if(tokenType == &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN]) {
        UA_X509IdentityToken* userCertToken = (UA_X509IdentityToken*)
            req->userIdentityToken.content.decoded.data;
        UA_CertificateUtils_getSubjectName(&session->clientUserIdOfSession,
                                           &userCertToken->certificateData);
    } else {
        
    }

#ifdef UA_ENABLE_DIAGNOSTICS
    
    UA_SessionSecurityDiagnosticsDataType *ssd = &session->securityDiagnostics;
    UA_StatusCode res =
        UA_Array_appendCopy((void**)&ssd->clientUserIdHistory,
                            &ssd->clientUserIdHistorySize,
                            &ssd->clientUserIdOfSession,
                            &UA_TYPES[UA_TYPES_STRING]);
    (void)res;

    
    UA_String_clear(&ssd->authenticationMechanism);
    switch(utp->tokenType) {
    case UA_USERTOKENTYPE_ANONYMOUS:
        ssd->authenticationMechanism = UA_STRING_ALLOC("Anonymous"); break;
    case UA_USERTOKENTYPE_USERNAME:
        ssd->authenticationMechanism = UA_STRING_ALLOC("UserName"); break;
    case UA_USERTOKENTYPE_CERTIFICATE:
        ssd->authenticationMechanism = UA_STRING_ALLOC("Certificate"); break;
    case UA_USERTOKENTYPE_ISSUEDTOKEN:
        ssd->authenticationMechanism = UA_STRING_ALLOC("IssuedToken"); break;
    default: break;
    }
#endif

    
    UA_LOG_INFO_SESSION(server->config.logging, session,
                        "ActivateSession: Session activated with ClientUserId \"%S\"",
                        session->clientUserIdOfSession);
    return;

securityRejected:
    server->serverDiagnosticsSummary.securityRejectedSessionCount++;
rejected:
    server->serverDiagnosticsSummary.rejectedSessionCount++;
}

void
Service_CloseSession(UA_Server *server, UA_SecureChannel *channel,
                     const UA_CloseSessionRequest *request,
                     UA_CloseSessionResponse *response) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Session *session = NULL;
    response->responseHeader.serviceResult =
        getBoundSession(server, channel, &request->requestHeader.authenticationToken, &session);
    if(!session && response->responseHeader.serviceResult == UA_STATUSCODE_GOOD)
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSESSIONIDINVALID;
    if(response->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_CHANNEL(server->config.logging, channel,
                               "CloseSession: No Session activated to the SecureChannel");
        return;
    }

    UA_assert(session); 
    UA_LOG_INFO_SESSION(server->config.logging, session, "Closing the Session");

#ifdef UA_ENABLE_SUBSCRIPTIONS
    
    if(!request->deleteSubscriptions) {
        UA_Subscription *sub, *sub_tmp;
        TAILQ_FOREACH_SAFE(sub, &session->subscriptions, sessionListEntry, sub_tmp) {
            UA_LOG_INFO_SUBSCRIPTION(server->config.logging, sub,
                                     "Detaching the Subscription from the Session");
            UA_Session_detachSubscription(server, session, sub, true);
        }
    }
#endif

    
    response->responseHeader.serviceResult =
        UA_Server_removeSessionByToken(server, &session->authenticationToken,
                                       UA_SHUTDOWNREASON_CLOSE);
}

void Service_Cancel(UA_Server *server, UA_Session *session,
                    const UA_CancelRequest *request, UA_CancelResponse *response) {
#if UA_MULTITHREADING >= 100
    response->cancelCount = UA_AsyncManager_cancel(server, session, request->requestHandle);
#endif

    
#ifdef UA_ENABLE_SUBSCRIPTIONS
    UA_PublishResponseEntry *pre, *pre_tmp;
    UA_PublishResponseEntry *prev = NULL;
    SIMPLEQ_FOREACH_SAFE(pre, &session->responseQueue, listEntry, pre_tmp) {
        
        if(pre->response.responseHeader.requestHandle != request->requestHandle) {
            prev = pre;
            continue;
        }

        
        if(prev)
            SIMPLEQ_REMOVE_AFTER(&session->responseQueue, prev, listEntry);
        else
            SIMPLEQ_REMOVE_HEAD(&session->responseQueue, listEntry);
        session->responseQueueSize--;

        
        response->responseHeader.serviceResult = UA_STATUSCODE_BADREQUESTCANCELLEDBYCLIENT;
        sendResponse(server, session->channel, pre->requestId, (UA_Response *)response,
                     &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);
        UA_PublishResponse_clear(&pre->response);
        UA_free(pre);

        
        response->cancelCount++;
    }
#endif
}
