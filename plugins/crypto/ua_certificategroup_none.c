
#include <opcua/plugin/certificategroup_default.h>

static UA_StatusCode
verifyCertificateAllowAll(UA_CertificateGroup *certGroup,
                          const UA_ByteString *certificate) {
    UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_USERLAND,
                   "No certificate store configured. Accepting the certificate.");
    return UA_STATUSCODE_GOOD;
}

static void
clearVerifyAllowAll(UA_CertificateGroup *certGroup) {

}

void UA_CertificateGroup_AcceptAll(UA_CertificateGroup *certGroup) {
    
    UA_NodeId groupId = certGroup->certificateGroupId;
    if(certGroup->clear)
        certGroup->clear(certGroup);
    UA_NodeId_copy(&groupId, &certGroup->certificateGroupId);
    certGroup->verifyCertificate = verifyCertificateAllowAll;
    certGroup->clear = clearVerifyAllowAll;
    certGroup->getTrustList = NULL;
    certGroup->setTrustList = NULL;
    certGroup->addToTrustList = NULL;
    certGroup->removeFromTrustList = NULL;
}

#ifndef UA_ENABLE_ENCRYPTION
UA_StatusCode
UA_CertificateUtils_verifyApplicationURI(UA_RuleHandling ruleHandling,
                                         const UA_ByteString *certificate,
                                         const UA_String *applicationURI){
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_CertificateUtils_getExpirationDate(UA_ByteString *certificate,
                                      UA_DateTime *expiryDateTime){
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

UA_StatusCode
UA_CertificateUtils_getSubjectName(UA_ByteString *certificate,
                                   UA_String *subjectName){
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

UA_StatusCode
UA_CertificateUtils_getThumbprint(UA_ByteString *certificate,
                                  UA_String *thumbprint){
    return UA_STATUSCODE_BADNOTSUPPORTED;
}
#endif
