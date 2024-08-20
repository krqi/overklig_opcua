
#ifndef UA_CERTIFICATEGROUP_CERTIFICATE_H_
#define UA_CERTIFICATEGROUP_CERTIFICATE_H_

#include <opcua/plugin/certificategroup.h>
#include <opcua/util.h>

_UA_BEGIN_DECLS


UA_EXPORT void
UA_CertificateGroup_AcceptAll(UA_CertificateGroup *certGroup);

#ifdef UA_ENABLE_ENCRYPTION
UA_EXPORT UA_StatusCode
UA_CertificateGroup_Memorystore(UA_CertificateGroup *certGroup,
                                UA_NodeId *certificateGroupId,
                                const UA_TrustListDataType *trustList,
                                const UA_Logger *logger,
                                const UA_KeyValueMap *params);

#ifdef __linux__ 
UA_EXPORT UA_StatusCode
UA_CertificateGroup_Filestore(UA_CertificateGroup *certGroup,
                              UA_NodeId *certificateGroupId,
                              const UA_String storePath,
                              const UA_Logger *logger,
                              const UA_KeyValueMap *params);
#endif

#endif

_UA_END_DECLS

#endif 
