
#ifndef UA_PLUGIN_CERTIFICATEGROUP_H
#define UA_PLUGIN_CERTIFICATEGROUP_H

#include <opcua/types.h>
#include <opcua/plugin/log.h>

_UA_BEGIN_DECLS

struct UA_CertificateGroup;
typedef struct UA_CertificateGroup UA_CertificateGroup;

struct UA_CertificateGroup {
    
    UA_NodeId certificateGroupId;
    void *context;
    const UA_Logger *logging;

    UA_StatusCode (*getTrustList)(UA_CertificateGroup *certGroup, UA_TrustListDataType *trustList);
    UA_StatusCode (*setTrustList)(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList);

    UA_StatusCode (*addToTrustList)(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList);
    UA_StatusCode (*removeFromTrustList)(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList);

    UA_StatusCode (*getRejectedList)(UA_CertificateGroup *certGroup, UA_ByteString **rejectedList, size_t *rejectedListSize);

    UA_StatusCode (*verifyCertificate)(UA_CertificateGroup *certGroup, const UA_ByteString *certificate);

    void (*clear)(UA_CertificateGroup *certGroup);
};


UA_EXPORT UA_StatusCode
UA_CertificateUtils_verifyApplicationURI(UA_RuleHandling ruleHandling,
                                         const UA_ByteString *certificate,
                                         const UA_String *applicationURI);


UA_EXPORT UA_StatusCode
UA_CertificateUtils_getExpirationDate(UA_ByteString *certificate,
                                      UA_DateTime *expiryDateTime);

UA_EXPORT UA_StatusCode
UA_CertificateUtils_getSubjectName(UA_ByteString *certificate,
                                   UA_String *subjectName);

UA_EXPORT UA_StatusCode
UA_CertificateUtils_getThumbprint(UA_ByteString *certificate,
                                  UA_String *thumbprint);

UA_EXPORT UA_StatusCode
UA_CertificateUtils_getKeySize(UA_ByteString *certificate,
                               size_t *keySize);

UA_EXPORT UA_StatusCode
UA_CertificateUtils_decryptPrivateKey(const UA_ByteString privateKey, const UA_ByteString password,
                                      UA_ByteString *outDerKey);

_UA_END_DECLS

#endif 
