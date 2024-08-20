
#ifndef UA_PLUGIN_SECURITYPOLICY_H_
#define UA_PLUGIN_SECURITYPOLICY_H_

#include <opcua/util.h>
#include <opcua/plugin/log.h>
#include <opcua/plugin/certificategroup.h>

_UA_BEGIN_DECLS

extern UA_EXPORT const UA_String UA_SECURITY_POLICY_NONE_URI;

struct UA_SecurityPolicy;
typedef struct UA_SecurityPolicy UA_SecurityPolicy;


typedef struct {
    UA_String uri;

    UA_StatusCode (*verify)(void *channelContext, const UA_ByteString *message,
                            const UA_ByteString *signature) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*sign)(void *channelContext, const UA_ByteString *message,
                          UA_ByteString *signature) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    size_t (*getLocalSignatureSize)(const void *channelContext);

    size_t (*getRemoteSignatureSize)(const void *channelContext);

    size_t (*getLocalKeyLength)(const void *channelContext);

    size_t (*getRemoteKeyLength)(const void *channelContext);
} UA_SecurityPolicySignatureAlgorithm;

typedef struct {
    UA_String uri;

    UA_StatusCode (*encrypt)(void *channelContext,
                             UA_ByteString *data) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*decrypt)(void *channelContext,
                             UA_ByteString *data) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    size_t (*getLocalKeyLength)(const void *channelContext);

    size_t (*getRemoteKeyLength)(const void *channelContext);

    size_t (*getRemoteBlockSize)(const void *channelContext);

    size_t (*getRemotePlainTextBlockSize)(const void *channelContext);
} UA_SecurityPolicyEncryptionAlgorithm;

typedef struct {
    
    UA_SecurityPolicySignatureAlgorithm signatureAlgorithm;

    
    UA_SecurityPolicyEncryptionAlgorithm encryptionAlgorithm;

} UA_SecurityPolicyCryptoModule;

typedef struct {
    UA_StatusCode (*makeCertificateThumbprint)(const UA_SecurityPolicy *securityPolicy,
                                               const UA_ByteString *certificate,
                                               UA_ByteString *thumbprint)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*compareCertificateThumbprint)(const UA_SecurityPolicy *securityPolicy,
                                                  const UA_ByteString *certificateThumbprint)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_SecurityPolicyCryptoModule cryptoModule;
} UA_SecurityPolicyAsymmetricModule;

typedef struct {
    UA_StatusCode (*generateKey)(void *policyContext, const UA_ByteString *secret,
                                 const UA_ByteString *seed, UA_ByteString *out)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*generateNonce)(void *policyContext, UA_ByteString *out)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    size_t secureChannelNonceLength;

    UA_SecurityPolicyCryptoModule cryptoModule;
} UA_SecurityPolicySymmetricModule;

typedef struct {
    UA_StatusCode (*newContext)(const UA_SecurityPolicy *securityPolicy,
                                const UA_ByteString *remoteCertificate,
                                void **channelContext)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    
    void (*deleteContext)(void *channelContext);

    UA_StatusCode (*setLocalSymEncryptingKey)(void *channelContext,
                                              const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*setLocalSymSigningKey)(void *channelContext,
                                           const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*setLocalSymIv)(void *channelContext,
                                   const UA_ByteString *iv)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*setRemoteSymEncryptingKey)(void *channelContext,
                                               const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*setRemoteSymSigningKey)(void *channelContext,
                                            const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*setRemoteSymIv)(void *channelContext,
                                    const UA_ByteString *iv)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode (*compareCertificate)(const void *channelContext,
                                        const UA_ByteString *certificate)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;
} UA_SecurityPolicyChannelModule;

struct UA_SecurityPolicy {
    
    void *policyContext;

    
    UA_String policyUri;

    
    UA_Byte securityLevel;

    UA_ByteString localCertificate;

    UA_NodeId certificateGroupId;
    UA_NodeId certificateTypeId;

    
    UA_SecurityPolicyAsymmetricModule asymmetricModule;
    UA_SecurityPolicySymmetricModule symmetricModule;
    UA_SecurityPolicySignatureAlgorithm certificateSigningAlgorithm;
    UA_SecurityPolicyChannelModule channelModule;

    const UA_Logger *logger;

    UA_StatusCode (*updateCertificateAndPrivateKey)(UA_SecurityPolicy *policy,
                                                    const UA_ByteString newCertificate,
                                                    const UA_ByteString newPrivateKey);

    UA_StatusCode (*createSigningRequest)(UA_SecurityPolicy *securityPolicy,
                                          const UA_String *subjectName,
                                          const UA_ByteString *nonce,
                                          const UA_KeyValueMap *params,
                                          UA_ByteString *csr,
                                          UA_ByteString *newPrivateKey);

    
    void (*clear)(UA_SecurityPolicy *policy);
};


struct UA_PubSubSecurityPolicy;
typedef struct UA_PubSubSecurityPolicy UA_PubSubSecurityPolicy;

struct UA_PubSubSecurityPolicy {
    UA_SecurityPolicySymmetricModule symmetricModule;

    UA_StatusCode
    (*newContext)(void *policyContext,
                  const UA_ByteString *signingKey,
                  const UA_ByteString *encryptingKey,
                  const UA_ByteString *keyNonce,
                  void **wgContext);

    
    void (*deleteContext)(void *wgContext);

    UA_StatusCode
    (*setSecurityKeys)(void *wgContext,
                       const UA_ByteString *signingKey,
                       const UA_ByteString *encryptingKey,
                       const UA_ByteString *keyNonce)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_StatusCode
    (*setMessageNonce)(void *wgContext,
                       const UA_ByteString *nonce)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    const UA_Logger *logger;

    
    void (*clear)(UA_PubSubSecurityPolicy *policy);
    void *policyContext;
};

_UA_END_DECLS

#endif 
