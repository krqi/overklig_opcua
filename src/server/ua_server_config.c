
#include <opcua/server.h>

#include "ua_server_internal.h"

void
UA_ServerConfig_clear(UA_ServerConfig *config) {
    if(!config)
        return;

    
    UA_BuildInfo_clear(&config->buildInfo);
    UA_ApplicationDescription_clear(&config->applicationDescription);
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    UA_MdnsDiscoveryConfiguration_clear(&config->mdnsConfig);
    UA_String_clear(&config->mdnsInterfaceIP);
# if !defined(UA_HAS_GETIFADDR)
    if (config->mdnsIpAddressListSize) {
        UA_free(config->mdnsIpAddressList);
    }
# endif
#endif

    
    UA_EventLoop *el = config->eventLoop;
    if(el && !config->externalEventLoop) {
        if(el->state != UA_EVENTLOOPSTATE_FRESH &&
           el->state != UA_EVENTLOOPSTATE_STOPPED) {
            el->stop(el);
            while(el->state != UA_EVENTLOOPSTATE_STOPPED) {
                el->run(el, 100);
            }
        }
        el->free(el);
        config->eventLoop = NULL;
    }

    
    UA_Array_delete(config->serverUrls, config->serverUrlsSize,
                    &UA_TYPES[UA_TYPES_STRING]);
    config->serverUrls = NULL;
    config->serverUrlsSize = 0;

    
    for(size_t i = 0; i < config->securityPoliciesSize; ++i) {
        UA_SecurityPolicy *policy = &config->securityPolicies[i];
        policy->clear(policy);
    }
    UA_free(config->securityPolicies);
    config->securityPolicies = NULL;
    config->securityPoliciesSize = 0;

    for(size_t i = 0; i < config->endpointsSize; ++i)
        UA_EndpointDescription_clear(&config->endpoints[i]);

    UA_free(config->endpoints);
    config->endpoints = NULL;
    config->endpointsSize = 0;

    
    if(config->nodestore.context && config->nodestore.clear) {
        config->nodestore.clear(config->nodestore.context);
        config->nodestore.context = NULL;
    }

    
    if(config->secureChannelPKI.clear)
        config->secureChannelPKI.clear(&config->secureChannelPKI);
    if(config->sessionPKI.clear)
        config->sessionPKI.clear(&config->sessionPKI);

    
    if(config->accessControl.clear)
        config->accessControl.clear(&config->accessControl);

    
#ifdef UA_ENABLE_HISTORIZING
    if(config->historyDatabase.clear)
        config->historyDatabase.clear(&config->historyDatabase);
#endif

#ifdef UA_ENABLE_PUBSUB
    if(config->pubSubConfig.securityPolicies != NULL) {
        for(size_t i = 0; i < config->pubSubConfig.securityPoliciesSize; i++) {
            config->pubSubConfig.securityPolicies[i].clear(&config->pubSubConfig.securityPolicies[i]);
        }
        UA_free(config->pubSubConfig.securityPolicies);
        config->pubSubConfig.securityPolicies = NULL;
        config->pubSubConfig.securityPoliciesSize = 0;
    }
#endif 

    
    if(config->logging != NULL && config->logging->clear != NULL)
        config->logging->clear(config->logging);
    config->logging = NULL;

    
    UA_cleanupDataTypeWithCustom(config->customDataTypes);
    config->customDataTypes = NULL;
}
