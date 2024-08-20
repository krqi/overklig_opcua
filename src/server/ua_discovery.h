
#ifndef UA_DISCOVERY_MANAGER_H_
#define UA_DISCOVERY_MANAGER_H_

#include "ua_server_internal.h"

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_DISCOVERY

typedef struct registeredServer {
    LIST_ENTRY(registeredServer) pointers;
    UA_RegisteredServer registeredServer;
    UA_DateTime lastSeen;
} registeredServer;

typedef struct {
    UA_DelayedCallback cleanupCallback; 
    UA_Server *server;
    UA_DiscoveryManager *dm;
    UA_Client *client;
    UA_String semaphoreFilePath;
    UA_Boolean unregister;

    UA_Boolean register2;
    UA_Boolean shutdown;
    UA_Boolean connectSuccess;
} asyncRegisterRequest;
#define UA_MAXREGISTERREQUESTS 4

#ifdef UA_ENABLE_DISCOVERY_MULTICAST

#include "mdnsd/libmdnsd/mdnsd.h"
#define UA_MAXMDNSRECVSOCKETS 8


typedef struct serverOnNetwork {
    LIST_ENTRY(serverOnNetwork) pointers;
    UA_ServerOnNetwork serverOnNetwork;
    UA_DateTime created;
    UA_DateTime lastSeen;
    UA_Boolean txtSet;
    UA_Boolean srvSet;
    char* pathTmp;
} serverOnNetwork;

#define SERVER_ON_NETWORK_HASH_SIZE 1000
typedef struct serverOnNetwork_hash_entry {
    serverOnNetwork *entry;
    struct serverOnNetwork_hash_entry* next;
} serverOnNetwork_hash_entry;

#endif

struct UA_DiscoveryManager {
    UA_ServerComponent sc;

    UA_UInt64 discoveryCallbackId;

    UA_Server *server; 

    
    asyncRegisterRequest registerRequests[UA_MAXREGISTERREQUESTS];

    LIST_HEAD(, registeredServer) registeredServers;
    size_t registeredServersSize;
    UA_Server_registerServerCallback registerServerCallback;
    void* registerServerCallbackData;

# ifdef UA_ENABLE_DISCOVERY_MULTICAST
    mdns_daemon_t *mdnsDaemon;
    UA_ConnectionManager *cm;
    uintptr_t mdnsSendConnection;
    uintptr_t mdnsRecvConnections[UA_MAXMDNSRECVSOCKETS];
    size_t mdnsRecvConnectionsSize;
    UA_Boolean mdnsMainSrvAdded;

    UA_String selfFqdnMdnsRecord;

    LIST_HEAD(, serverOnNetwork) serverOnNetwork;

    UA_UInt32 serverOnNetworkRecordIdCounter;
    UA_DateTime serverOnNetworkRecordIdLastReset;

    
    struct serverOnNetwork_hash_entry* serverOnNetworkHash[SERVER_ON_NETWORK_HASH_SIZE];

    UA_Server_serverOnNetworkCallback serverOnNetworkCallback;
    void *serverOnNetworkCallbackData;

    UA_UInt64 mdnsCallbackId;
# endif 
};

void
UA_DiscoveryManager_setState(UA_Server *server,
                             UA_DiscoveryManager *dm,
                             UA_LifecycleState state);

#ifdef UA_ENABLE_DISCOVERY_MULTICAST

void
UA_Discovery_updateMdnsForDiscoveryUrl(UA_DiscoveryManager *dm, const UA_String serverName,
                                       const UA_MdnsDiscoveryConfiguration *mdnsConfig,
                                       const UA_String discoveryUrl, UA_Boolean isOnline,
                                       UA_Boolean updateTxt);

void UA_DiscoveryManager_startMulticast(UA_DiscoveryManager *dm);
void UA_DiscoveryManager_stopMulticast(UA_DiscoveryManager *dm);
void UA_DiscoveryManager_sendMulticastMessages(UA_DiscoveryManager *dm);

UA_StatusCode
UA_DiscoveryManager_addEntryToServersOnNetwork(UA_DiscoveryManager *dm,
                                               const char *fqdnMdnsRecord,
                                               UA_String serverName,
                                               struct serverOnNetwork **addedEntry);

UA_StatusCode
UA_DiscoveryManager_removeEntryFromServersOnNetwork(UA_DiscoveryManager *dm,
                                                    const char *fqdnMdnsRecord,
                                                    UA_String serverName);

void mdns_record_received(const struct resource *r, void *data);

void mdns_create_txt(UA_DiscoveryManager *dm, const char *fullServiceDomain,
                     const char *path, const UA_String *capabilites,
                     const size_t capabilitiesSize,
                     void (*conflict)(char *host, int type, void *arg));

void mdns_set_address_record(UA_DiscoveryManager *dm, const char *fullServiceDomain,
                             const char *localDomain);

mdns_record_t *
mdns_find_record(mdns_daemon_t *mdnsDaemon, unsigned short type,
                 const char *host, const char *rdname);

#endif 

#endif 

_UA_END_DECLS

#endif 
