
#ifndef UA_ACCESSCONTROL_DEFAULT_H_
#define UA_ACCESSCONTROL_DEFAULT_H_

#include <opcua/plugin/accesscontrol.h>
#include <opcua/server.h>

_UA_BEGIN_DECLS

typedef struct {
    UA_String username;
    UA_String password;
} UA_UsernamePasswordLogin;

typedef UA_StatusCode (*UA_UsernamePasswordLoginCallback)
    (const UA_String *userName, const UA_ByteString *password,
    size_t usernamePasswordLoginSize, const UA_UsernamePasswordLogin
    *usernamePasswordLogin, void **sessionContext, void *loginContext);

UA_EXPORT UA_StatusCode
UA_AccessControl_default(UA_ServerConfig *config,
                         UA_Boolean allowAnonymous,
                         const UA_ByteString *userTokenPolicyUri,
                         size_t usernamePasswordLoginSize,
                         const UA_UsernamePasswordLogin *usernamePasswordLogin);

UA_EXPORT UA_StatusCode
UA_AccessControl_defaultWithLoginCallback(UA_ServerConfig *config,
                                          UA_Boolean allowAnonymous,
                                          const UA_ByteString *userTokenPolicyUri,
                                          size_t usernamePasswordLoginSize,
                                          const UA_UsernamePasswordLogin *usernamePasswordLogin,
                                          UA_UsernamePasswordLoginCallback loginCallback,
                                          void *loginContext);

_UA_END_DECLS

#endif 
