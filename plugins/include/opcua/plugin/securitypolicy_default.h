
#ifndef UA_SECURITYPOLICIES_H_
#define UA_SECURITYPOLICIES_H_

#include <opcua/plugin/securitypolicy.h>

_UA_BEGIN_DECLS

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_None(UA_SecurityPolicy *policy,
                       const UA_ByteString localCertificate,
                       const UA_Logger *logger);

#ifdef UA_ENABLE_ENCRYPTION

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Basic128Rsa15(UA_SecurityPolicy *policy,
                                const UA_ByteString localCertificate,
                                const UA_ByteString localPrivateKey,
                                const UA_Logger *logger);

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Basic256(UA_SecurityPolicy *policy,
                           const UA_ByteString localCertificate,
                           const UA_ByteString localPrivateKey,
                           const UA_Logger *logger);

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Basic256Sha256(UA_SecurityPolicy *policy,
                                 const UA_ByteString localCertificate,
                                 const UA_ByteString localPrivateKey,
                                 const UA_Logger *logger);

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Aes128Sha256RsaOaep(UA_SecurityPolicy *policy,
                                      const UA_ByteString localCertificate,
                                      const UA_ByteString localPrivateKey,
                                      const UA_Logger *logger);

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Aes256Sha256RsaPss(UA_SecurityPolicy *policy,
                                     const UA_ByteString localCertificate,
                                     const UA_ByteString localPrivateKey,
                                     const UA_Logger *logger);

#ifdef __linux__ 
UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Filestore(UA_SecurityPolicy *policy,
                            UA_SecurityPolicy *innerPolicy,
                            const UA_String storePath);
#endif

#endif

UA_EXPORT UA_StatusCode
UA_PubSubSecurityPolicy_Aes128Ctr(UA_PubSubSecurityPolicy *policy,
                                  const UA_Logger *logger);
UA_EXPORT UA_StatusCode
UA_PubSubSecurityPolicy_Aes256Ctr(UA_PubSubSecurityPolicy *policy,
                                  const UA_Logger *logger);

#ifdef UA_ENABLE_TPM2_SECURITY

UA_EXPORT UA_StatusCode
UA_PubSubSecurityPolicy_Aes128CtrTPM(UA_PubSubSecurityPolicy *policy, char *userpin, unsigned long slotId,
                                     char *encryptionKeyLabel, char *signingKeyLabel, const UA_Logger *logger);
UA_EXPORT UA_StatusCode
UA_PubSubSecurityPolicy_Aes256CtrTPM(UA_PubSubSecurityPolicy *policy, char *userpin, unsigned long slotId,
                                     char *encryptionKeyLabel, char *signingKeyLabel, const UA_Logger *logger);

#endif

_UA_END_DECLS

#endif 
