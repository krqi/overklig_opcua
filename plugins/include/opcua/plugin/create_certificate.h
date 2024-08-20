
#ifndef CREATE_CERTIFICATE_H_
#define CREATE_CERTIFICATE_H_

#include <opcua/plugin/log.h>
#include <opcua/types.h>
#include <opcua/util.h>

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_ENCRYPTION
typedef enum {
    UA_CERTIFICATEFORMAT_DER,
    UA_CERTIFICATEFORMAT_PEM
} UA_CertificateFormat;

UA_StatusCode UA_EXPORT
UA_CreateCertificate(const UA_Logger *logger, const UA_String *subject,
                     size_t subjectSize, const UA_String *subjectAltName,
                     size_t subjectAltNameSize, UA_CertificateFormat certFormat,
                     UA_KeyValueMap *params, UA_ByteString *outPrivateKey,
                     UA_ByteString *outCertificate);
#endif

_UA_END_DECLS

#endif 
