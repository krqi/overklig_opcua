
#ifndef UA_PUBSUB_KEYSTORAGE
#define UA_PUBSUB_KEYSTORAGE

#include <opcua/plugin/securitypolicy.h>
#include <opcua/client_highlevel_async.h>
#include <opcua/client_config_default.h>
#include <opcua/server.h>
#include <opcua/client.h>

#include "opcua_queue.h"

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_PUBSUB_SKS


typedef struct UA_PubSubKeyListItem {
    
    UA_UInt32 keyID;

    UA_ByteString key;

    
    TAILQ_ENTRY(UA_PubSubKeyListItem) keyListEntry;
} UA_PubSubKeyListItem;


typedef TAILQ_HEAD(keyListItems, UA_PubSubKeyListItem) keyListItems;

typedef struct UA_PubSubSKSConfig {
    UA_ClientConfig clientConfig;
    const char *endpointUrl;
    UA_Server_sksPullRequestCallback userNotifyCallback;
    void *context;
    UA_UInt32 reqId;
} UA_PubSubSKSConfig;

typedef struct UA_PubSubKeyStorage {

    UA_String securityGroupID;

    UA_PubSubSecurityPolicy *policy;

    UA_UInt32 referenceCount;

    keyListItems keyList;

    size_t keyListSize;

    UA_UInt32 maxPastKeyCount;

    UA_UInt32 maxFutureKeyCount;

    UA_UInt32 maxKeyListSize;

    UA_UInt32 currentTokenId;

    UA_PubSubKeyListItem *currentItem;

    UA_Duration keyLifeTime;

    UA_UInt64 callBackId;

    UA_PubSubSKSConfig sksConfig;

    LIST_ENTRY(UA_PubSubKeyStorage) keyStorageList;

} UA_PubSubKeyStorage;

UA_PubSubKeyStorage *
UA_PubSubKeyStorage_findKeyStorage(UA_Server *server, UA_String securityGroupId);

UA_PubSubSecurityPolicy *
findPubSubSecurityPolicy(UA_Server *server, const UA_String *securityPolicyUri);

void
UA_PubSubKeyStorage_delete(UA_Server *server, UA_PubSubKeyStorage *keyStorage);

UA_StatusCode
UA_PubSubKeyStorage_init(UA_Server *server, UA_PubSubKeyStorage *keyStorage,
                         const UA_String *securityGroupId,
                         UA_PubSubSecurityPolicy *policy,
                         UA_UInt32 maxPastKeyCount, UA_UInt32 maxFutureKeyCount);

UA_StatusCode
UA_PubSubKeyStorage_storeSecurityKeys(UA_Server *server, UA_PubSubKeyStorage *keyStorage,
                                      UA_UInt32 currentTokenId, const UA_ByteString *currentKey,
                                      UA_ByteString *futureKeys, size_t futureKeyCount,
                                      UA_Duration msKeyLifeTime);

UA_StatusCode
UA_PubSubKeyStorage_getKeyByKeyID(const UA_UInt32 keyId, UA_PubSubKeyStorage *keyStorage,
                                  UA_PubSubKeyListItem **keyItem);

UA_PubSubKeyListItem *
UA_PubSubKeyStorage_push(UA_PubSubKeyStorage *keyStorage, const UA_ByteString *key,
                         UA_UInt32 keyID);

UA_StatusCode
UA_PubSubKeyStorage_addKeyRolloverCallback(UA_Server *server,
                                          UA_PubSubKeyStorage *keyStorage,
                                          UA_ServerCallback callback,
                                          UA_Duration timeToNextMs,
                                          UA_UInt64 *callbackID);

UA_StatusCode
UA_PubSubKeyStorage_activateKeyToChannelContext(UA_Server *server, const UA_NodeId pubSubGroupId,
                                                const UA_String securityGroupId);

void
UA_PubSubKeyStorage_keyRolloverCallback(UA_Server *server, UA_PubSubKeyStorage *keyStorage);

UA_StatusCode
UA_PubSubKeyStorage_update(UA_Server *server, UA_PubSubKeyStorage *keyStorage,
                           const UA_ByteString *currentKey, UA_UInt32 currentKeyID,
                           const size_t futureKeySize, UA_ByteString *futureKeys,
                           UA_Duration msKeyLifeTime);

void
UA_PubSubKeyStorage_detachKeyStorage(UA_Server *server, UA_PubSubKeyStorage *keyStorage);


UA_StatusCode
getSecurityKeysAndStoreFetchedKeys(UA_Server *server, UA_PubSubKeyStorage *keyStorage);

#endif

_UA_END_DECLS

#endif 
