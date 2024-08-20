
#ifndef UA_SERVER_CONFIG_DEFAULT_H_
#define UA_SERVER_CONFIG_DEFAULT_H_

#include <opcua/server.h>

_UA_BEGIN_DECLS





extern const UA_EXPORT
UA_ConnectionConfig UA_ConnectionConfig_default;





UA_EXPORT UA_StatusCode
UA_ServerConfig_setMinimalCustomBuffer(UA_ServerConfig *config,
                                       UA_UInt16 portNumber,
                                       const UA_ByteString *certificate,
                                       UA_UInt32 sendBufferSize,
                                       UA_UInt32 recvBufferSize);

UA_INLINABLE( UA_StatusCode
UA_ServerConfig_setMinimal(UA_ServerConfig *config, UA_UInt16 portNumber,
                           const UA_ByteString *certificate) ,{
    return UA_ServerConfig_setMinimalCustomBuffer(config, portNumber,
                                                  certificate, 0, 0);
})

#ifdef UA_ENABLE_ENCRYPTION

UA_EXPORT UA_StatusCode
UA_ServerConfig_setDefaultWithSecurityPolicies(UA_ServerConfig *conf,
                                               UA_UInt16 portNumber,
                                               const UA_ByteString *certificate,
                                               const UA_ByteString *privateKey,
                                               const UA_ByteString *trustList,
                                               size_t trustListSize,
                                               const UA_ByteString *issuerList,
                                               size_t issuerListSize,
                                               const UA_ByteString *revocationList,
                                               size_t revocationListSize);

UA_EXPORT UA_StatusCode
UA_ServerConfig_setDefaultWithSecureSecurityPolicies(UA_ServerConfig *conf,
                                                     UA_UInt16 portNumber,
                                                     const UA_ByteString *certificate,
                                                     const UA_ByteString *privateKey,
                                                     const UA_ByteString *trustList,
                                                     size_t trustListSize,
                                                     const UA_ByteString *issuerList,
                                                     size_t issuerListSize,
                                                     const UA_ByteString *revocationList,
                                                     size_t revocationListSize);

#ifdef __linux__ 

UA_EXPORT UA_StatusCode
UA_ServerConfig_setDefaultWithFilestore(UA_ServerConfig *conf,
                                        UA_UInt16 portNumber,
                                        const UA_ByteString *certificate,
                                        const UA_ByteString *privateKey,
                                        const UA_String storePath);

#endif

#endif

UA_INLINABLE( UA_StatusCode
UA_ServerConfig_setDefault(UA_ServerConfig *config) ,{
    return UA_ServerConfig_setMinimal(config, 4840, NULL);
})

UA_EXPORT UA_StatusCode
UA_ServerConfig_setBasics(UA_ServerConfig *conf);

UA_EXPORT UA_StatusCode
UA_ServerConfig_setBasics_withPort(UA_ServerConfig *conf,
                                   UA_UInt16 portNumber);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyNone(UA_ServerConfig *config,
                                      const UA_ByteString *certificate);

#ifdef UA_ENABLE_ENCRYPTION

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyBasic128Rsa15(UA_ServerConfig *config,
                                               const UA_ByteString *certificate,
                                               const UA_ByteString *privateKey);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyBasic256(UA_ServerConfig *config,
                                          const UA_ByteString *certificate,
                                          const UA_ByteString *privateKey);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyBasic256Sha256(UA_ServerConfig *config,
                                                const UA_ByteString *certificate,
                                                const UA_ByteString *privateKey);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyAes128Sha256RsaOaep(UA_ServerConfig *config,
                                                     const UA_ByteString *certificate,
                                                     const UA_ByteString *privateKey);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyAes256Sha256RsaPss(UA_ServerConfig *config,
                                                    const UA_ByteString *certificate,
                                                    const UA_ByteString *privateKey);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addAllSecurityPolicies(UA_ServerConfig *config,
                                       const UA_ByteString *certificate,
                                       const UA_ByteString *privateKey);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addAllSecureSecurityPolicies(UA_ServerConfig *config,
                                       const UA_ByteString *certificate,
                                       const UA_ByteString *privateKey);

#ifdef __linux__ 

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicy_Filestore(UA_ServerConfig *config,
                                            UA_SecurityPolicy *innerPolicy,
                                            const UA_String storePath);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicies_Filestore(UA_ServerConfig *config,
                                              const UA_ByteString *certificate,
                                              const UA_ByteString *privateKey,
                                              const UA_String storePath);
#endif

#endif

UA_EXPORT UA_StatusCode
UA_ServerConfig_addEndpoint(UA_ServerConfig *config, const UA_String securityPolicyUri,
                            UA_MessageSecurityMode securityMode);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addAllEndpoints(UA_ServerConfig *config);

UA_EXPORT UA_StatusCode
UA_ServerConfig_addAllSecureEndpoints(UA_ServerConfig *config);

_UA_END_DECLS

#endif 
