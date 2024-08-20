

#include <opcua/plugin/eventloop.h>

#ifdef UA_ENABLE_MQTT

#include "../../deps/opcua_queue.h"
#include <limits.h>

#if defined(_MSC_VER)
# include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
# include <unistd.h> 
#endif

struct MQTTConnectionManager;
typedef struct MQTTConnectionManager MQTTConnectionManager;

struct MQTTBrokerConnection;
typedef struct MQTTBrokerConnection MQTTBrokerConnection;

struct MQTTTopicConnection;
typedef struct MQTTTopicConnection MQTTTopicConnection;

#define __MQTT_PAL_H__


static UA_INLINE uint16_t
MQTT_PAL_HTONS(uint16_t s) {
    union {uint16_t t; uint8_t b[2];} v;
    v.b[0] = (uint8_t)(s>>8);
    v.b[1] = (uint8_t)s;
    return v.t;
}

static UA_INLINE uint16_t
MQTT_PAL_NTOHS(uint16_t s) {
    union {uint16_t t; uint8_t b[2];} v;
    v.t = s;
    return (uint16_t)((uint16_t)v.b[1] + (((uint16_t)v.b[0])<<8));
}


typedef long int mqtt_pal_time_t;
#define MQTT_PAL_TIME() (long int)(UA_DateTime_nowMonotonic() / UA_DATETIME_SEC)


typedef UA_Byte mqtt_pal_mutex_t;
#define MQTT_PAL_MUTEX_INIT(mtx_ptr) *mtx_ptr = 0
#define MQTT_PAL_MUTEX_LOCK(mtx_ptr) {}
#define MQTT_PAL_MUTEX_UNLOCK(mtx_ptr) {}


typedef MQTTBrokerConnection * mqtt_pal_socket_handle;
static ssize_t mqtt_pal_sendall(mqtt_pal_socket_handle fd, const void* buf, size_t len, int flags);
static ssize_t mqtt_pal_recvall(mqtt_pal_socket_handle fd, void* buf, size_t bufsz, int flags);


#include "../../deps/mqtt-c/include/mqtt.h"
#include "../../deps/mqtt-c/src/mqtt.c"

#define MQTT_MESSAGE_MAXLEN (1u << 20) 
#define MQTT_PARAMETERSSIZE 8

static const struct {
    UA_QualifiedName name;
    const UA_DataType *type;
    UA_Boolean required;
} MQTTConnectionParameters[MQTT_PARAMETERSSIZE] = {
    {{0, UA_STRING_STATIC("address")}, &UA_TYPES[UA_TYPES_STRING], true},
    {{0, UA_STRING_STATIC("port")}, &UA_TYPES[UA_TYPES_UINT16], false},
    {{0, UA_STRING_STATIC("keep-alive")}, &UA_TYPES[UA_TYPES_UINT16], false},
    {{0, UA_STRING_STATIC("username")}, &UA_TYPES[UA_TYPES_STRING], false},
    {{0, UA_STRING_STATIC("password")}, &UA_TYPES[UA_TYPES_STRING], false},
    {{0, UA_STRING_STATIC("validate")}, &UA_TYPES[UA_TYPES_BOOLEAN], false},
    {{0, UA_STRING_STATIC("subscribe")}, &UA_TYPES[UA_TYPES_BOOLEAN], false},
    {{0, UA_STRING_STATIC("topic")}, &UA_TYPES[UA_TYPES_STRING], true}
};

struct MQTTBrokerConnection {
    LIST_ENTRY(MQTTBrokerConnection) next;

    
    MQTTConnectionManager *mcm;

    
    uintptr_t tcpConnectionId;
    UA_ConnectionState tcpConnectionState;
    struct mqtt_client client;

    UA_DateTime lastSendTime; 
    UA_UInt16 keepalive;      
    UA_UInt64 keepAliveCallbackId; 

    
    LIST_HEAD(, MQTTTopicConnection) topicConnections;
    uintptr_t lastTopicConnectionId;

    UA_KeyValueMap params;
};

struct MQTTTopicConnection {
    LIST_ENTRY(MQTTTopicConnection) next;

    
    uintptr_t topicConnectionId; 
    UA_ConnectionState topicConnectionState;

    UA_String topic;      
    UA_Boolean subscribe; 

    
    MQTTBrokerConnection *brokerConnection;

    
    void *application;
    void *context;
    UA_ConnectionManager_connectionCallback callback;

    
    UA_DelayedCallback dc;
};


struct MQTTConnectionManager {
    UA_ConnectionManager cm;
    LIST_HEAD(, MQTTBrokerConnection) connections;
};


ssize_t
mqtt_pal_sendall(MQTTBrokerConnection *bc, const void* buf, size_t len, int flags) {
    if(bc->tcpConnectionState != UA_CONNECTIONSTATE_ESTABLISHED)
        return MQTT_ERROR_SOCKET_ERROR;

    UA_ByteString msg = UA_BYTESTRING_NULL;
    UA_ConnectionManager *tcpCM = bc->mcm->tcpCM;
    UA_StatusCode res = tcpCM->allocNetworkBuffer(tcpCM, bc->tcpConnectionId, &msg, len);
    if(res != UA_STATUSCODE_GOOD)
        return MQTT_ERROR_SOCKET_ERROR;
        
    memcpy(msg.data, buf, len);
    res = tcpCM->sendWithConnection(tcpCM, bc->tcpConnectionId,
                                    &UA_KEYVALUEMAP_NULL, &msg);
    if(res != UA_STATUSCODE_GOOD)
        return MQTT_ERROR_SOCKET_ERROR;

    bc->lastSendTime = UA_DateTime_nowMonotonic();
    return (ssize_t)len;
}

ssize_t
mqtt_pal_recvall(MQTTBrokerConnection *bc, void* buf, size_t bufsz, int flags) {
    return 0;
}

static UA_StatusCode
MQTT_eventSourceStart(UA_ConnectionManager *cm) {
    MQTTConnectionManager *mcm = (MQTTConnectionManager*)cm;
    UA_EventLoop *el = cm->eventSource.eventLoop;
    if(!el)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    if(cm->eventSource.state != UA_EVENTSOURCESTATE_STOPPED) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "MQTT\t| To start the ConnectionManager, it has to be "
                     "registered in an EventLoop and not started yet");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    UA_String tcp = UA_STRING("tcp");
    for(UA_EventSource *es = el->eventSources; es; es = es->next) {
        if(es->eventSourceType != UA_EVENTSOURCETYPE_CONNECTIONMANAGER)
            continue;
        UA_ConnectionManager *cm2 = (UA_ConnectionManager*)es;
        if(UA_String_equal(&tcp, &cm2->protocol)) {
            mcm->tcpCM = cm2;
            cm->eventSource.state = UA_EVENTSOURCESTATE_STARTED;
            return UA_STATUSCODE_GOOD;
        }
    }
    return UA_STATUSCODE_BADINTERNALERROR;
}

static void
shutdownBrokerConnection(MQTTBrokerConnection *bc) {
    if(bc->tcpConnectionState == UA_CONNECTIONSTATE_CLOSED ||
       bc->tcpConnectionState == UA_CONNECTIONSTATE_CLOSING)
        return;

    UA_LOG_DEBUG(bc->mcm->cm.eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                 "MQTT-TCP %u\t| Closing the broker connection",
                 (unsigned)bc->tcpConnectionId);


    
    if(bc->tcpConnectionState == UA_CONNECTIONSTATE_ESTABLISHED) {
        mqtt_disconnect(&bc->client);
        __mqtt_send(&bc->client);
    }

    
    UA_ConnectionManager *tcpCM = bc->mcm->tcpCM;
    tcpCM->closeConnection(tcpCM, bc->tcpConnectionId);

    bc->tcpConnectionState = UA_CONNECTIONSTATE_CLOSING;
}

static void
MQTT_eventSourceStop(UA_ConnectionManager *cm) {
    if(cm->eventSource.state == UA_EVENTSOURCESTATE_STOPPING ||
       cm->eventSource.state == UA_EVENTSOURCESTATE_STOPPED)
        return;

    UA_LOG_INFO(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "MQTT\t| Shutting down the ConnectionManager");

    MQTTConnectionManager *mcm = (MQTTConnectionManager*)cm;
    if(LIST_EMPTY(&mcm->connections)) {
        cm->eventSource.state = UA_EVENTSOURCESTATE_STOPPED;
        return;
    }

    cm->eventSource.state = UA_EVENTSOURCESTATE_STOPPING;
    MQTTBrokerConnection *bc, *bc_tmp;
    LIST_FOREACH_SAFE(bc, &mcm->connections, next, bc_tmp) {
        shutdownBrokerConnection(bc);
    }
}

static UA_StatusCode
MQTT_eventSourceDelete(UA_ConnectionManager *cm) {
    UA_String_clear(&cm->eventSource.name);
    UA_free(cm);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
MQTT_allocNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                        UA_ByteString *buf, size_t bufSize) {
    UA_ConnectionManager *tcpCM = ((MQTTConnectionManager*)cm)->tcpCM;
    return tcpCM->allocNetworkBuffer(tcpCM, connectionId, buf, bufSize);
}

static void
MQTT_freeNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                       UA_ByteString *buf) {
    UA_ConnectionManager *tcpCM = ((MQTTConnectionManager*)cm)->tcpCM;
    tcpCM->freeNetworkBuffer(tcpCM, connectionId, buf);
}

static void
removeTopicConnection(MQTTTopicConnection *tc) {
    UA_LOG_INFO(tc->brokerConnection->mcm->cm.eventSource.eventLoop->logger,
                UA_LOGCATEGORY_NETWORK, "MQTT %u\t| Closing the connection",
                (unsigned)tc->topicConnectionId);

    
    MQTTBrokerConnection *bc = tc->brokerConnection;
    if(tc->subscribe &&
       tc->topicConnectionState == UA_CONNECTIONSTATE_ESTABLISHED &&
       bc->tcpConnectionState == UA_CONNECTIONSTATE_ESTABLISHED) {
        mqtt_unsubscribe(&bc->client, (const char*)tc->topic.data);
        __mqtt_send(&bc->client);
    }

    
    LIST_REMOVE(tc, next);

    
    UA_KeyValuePair kvp[2];
    kvp[0].key = UA_QUALIFIEDNAME(0, "topic");
    UA_Variant_setScalar(&kvp[0].value, &tc->topic, &UA_TYPES[UA_TYPES_STRING]);
    kvp[1].key = UA_QUALIFIEDNAME(0, "subscribe");
    UA_Variant_setScalar(&kvp[0].value, &tc->subscribe, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_KeyValueMap kvm = {2, kvp};

    
    if(tc->callback)
        tc->callback(&bc->mcm->cm, tc->topicConnectionId, tc->application, &tc->context,
                     UA_CONNECTIONSTATE_CLOSING, &kvm, UA_BYTESTRING_NULL);

    
    UA_String_clear(&tc->topic);
    UA_free(tc);

    
    if(LIST_EMPTY(&bc->topicConnections))
        shutdownBrokerConnection(bc);
}

static void
removeTopicConnectionDelayed(void *application, void *context) {
    MQTTTopicConnection *tc = (MQTTTopicConnection*)context;
    removeTopicConnection(tc);
}

static void
removeBrokerConnection(MQTTBrokerConnection *bc) {
    MQTTConnectionManager *mcm = bc->mcm;
    UA_EventLoop *el = mcm->cm.eventSource.eventLoop;

    UA_LOG_DEBUG(bc->mcm->cm.eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                 "MQTT-TCP %u\t| Removing the broker connection", (unsigned)bc->tcpConnectionId);

    
    if(bc->keepAliveCallbackId > 0)
        el->removeCyclicCallback(el, bc->keepAliveCallbackId);
    
    
    LIST_REMOVE(bc, next);

    
    MQTTTopicConnection *tc, *tc_tmp;
    LIST_FOREACH_SAFE(tc, &bc->topicConnections, next, tc_tmp) {
        removeTopicConnection(tc);
    }

    UA_KeyValueMap_clear(&bc->params);
    UA_free(bc->client.recv_buffer.mem_start);
    UA_free(bc->client.mq.mem_start);
    UA_free(bc);

    
    if(mcm->cm.eventSource.state == UA_EVENTSOURCESTATE_STOPPING &&
       LIST_EMPTY(&mcm->connections))
        mcm->cm.eventSource.state = UA_EVENTSOURCESTATE_STOPPED;
}


static MQTTBrokerConnection *
findIdenticalBrokerConnection(MQTTConnectionManager *mcm, const UA_KeyValueMap *kvm) {
    MQTTBrokerConnection *bc;
    LIST_FOREACH(bc, &mcm->connections, next) {
        UA_Boolean found = true;
        for(size_t i = 0; i < MQTT_BROKERPARAMETERSSIZE; i++) {
            const UA_Variant *v1 = UA_KeyValueMap_get(kvm, MQTTConnectionParameters[i].name);
            const UA_Variant *v2 = UA_KeyValueMap_get(kvm, MQTTConnectionParameters[i].name);
            if(v1 == v2)
                continue;
            if(!v2)
                continue; 
            if(!v1 || UA_order(v1, v2, &UA_TYPES[UA_TYPES_VARIANT]) != UA_ORDER_EQ) {
                found = false;
                break;
            }
        }
        if(found)
            return bc;
    }
    return NULL;
}

static MQTTBrokerConnection *
findBrokerConnection(MQTTConnectionManager *mcm, uintptr_t id) {
    uintptr_t brokerId = id / 1000;
    MQTTBrokerConnection *bc;
    LIST_FOREACH(bc, &mcm->connections, next) {
        if(bc->tcpConnectionId == brokerId)
            return bc;
    }
    return NULL;
}

static MQTTTopicConnection *
findTopicConnection(MQTTConnectionManager *mcm, uintptr_t id) {
    MQTTBrokerConnection *bc = findBrokerConnection(mcm, id);
    if(!bc)
        return NULL;
    MQTTTopicConnection *tc;
    LIST_FOREACH(tc, &bc->topicConnections, next) {
        if(tc->topicConnectionId == id)
            return tc;
    }
    return NULL;
}

static void
MQTTKeepAliveCallback(void *app, MQTTBrokerConnection *bc) {
    (void)app;
    mqtt_ping(&bc->client);
    __mqtt_send(&bc->client);
}

static void
MQTTPublishResponseCallback(void** state, struct mqtt_response_publish *publish) {
    MQTTBrokerConnection *bc = *(MQTTBrokerConnection**)state;

    
    UA_String topic = {publish->topic_name_size,
                       (UA_Byte*)(uintptr_t)publish->topic_name};
    UA_ByteString msg = {publish->application_message_size,
                         (UA_Byte*)(uintptr_t)publish->application_message};

    
    UA_Boolean subscribe = true;
    UA_KeyValuePair kvp[2];
    kvp[0].key = UA_QUALIFIEDNAME(0, "topic");
    UA_Variant_setScalar(&kvp[0].value, &topic, &UA_TYPES[UA_TYPES_STRING]);
    kvp[1].key = UA_QUALIFIEDNAME(0, "subscribe");
    UA_Variant_setScalar(&kvp[1].value, &subscribe, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_KeyValueMap kvm = {2, kvp};

    
    MQTTTopicConnection *tc;
    LIST_FOREACH(tc, &bc->topicConnections, next) {
        if(!tc->subscribe || !UA_String_equal(&topic, &tc->topic))
            continue;

        UA_LOG_DEBUG(tc->brokerConnection->mcm->cm.eventSource.eventLoop->logger,
                     UA_LOGCATEGORY_NETWORK, "MQTT %u\t| Received a message of "
                     "%u bytes", (unsigned)tc->topicConnectionId, (unsigned)msg.length);

        if(tc->topicConnectionState != UA_CONNECTIONSTATE_ESTABLISHED) {
            tc->topicConnectionState = UA_CONNECTIONSTATE_ESTABLISHED;
            tc->callback(&bc->mcm->cm, tc->topicConnectionId,
                         tc->application, &tc->context,
                         UA_CONNECTIONSTATE_ESTABLISHED, &kvm,
                         UA_BYTESTRING_NULL);
        }

        
        tc->callback(&bc->mcm->cm, tc->topicConnectionId, tc->application,
                     &tc->context, UA_CONNECTIONSTATE_ESTABLISHED, &kvm, msg);
    }
}

static void
MQTTNetworkCallback(UA_ConnectionManager *tcpCM, uintptr_t connectionId,
                    void *application, void **connectionContext, UA_ConnectionState state,
                    const UA_KeyValueMap *params, UA_ByteString msg) {
    MQTTBrokerConnection *bc = *(MQTTBrokerConnection**)connectionContext;
    MQTTConnectionManager *mcm = bc->mcm;
    UA_assert(bc);

    
    UA_ConnectionState oldState = bc->tcpConnectionState;
    bc->tcpConnectionState = state;

    
    if(oldState == UA_CONNECTIONSTATE_CLOSED) {
        
        bc->tcpConnectionId = connectionId;

        
        bc->client.publish_response_callback_state = bc;
    }

    UA_LOG_DEBUG(bc->mcm->cm.eventSource.eventLoop->logger,
                 UA_LOGCATEGORY_NETWORK, "MQTT-TCP %u\t| Network callback",
                 (unsigned)bc->tcpConnectionId);

    if(state == UA_CONNECTIONSTATE_CLOSING || state == UA_CONNECTIONSTATE_CLOSED) {
        removeBrokerConnection(bc);
        return;
    }

    
    if(state == UA_CONNECTIONSTATE_ESTABLISHED &&
       oldState != UA_CONNECTIONSTATE_ESTABLISHED) {
        mqtt_init(&bc->client, bc,
                  (uint8_t*)UA_calloc(1,1024), 1024,
                  (uint8_t*)UA_calloc(1,1024), 1024,
                  MQTTPublishResponseCallback);

        
        enum MQTTErrors err = mqtt_connect(&bc->client, NULL, NULL, NULL, 0,
                                           NULL, NULL, MQTT_CONNECT_CLEAN_SESSION, 400);
        if(err != MQTT_OK) {
            bc->tcpConnectionState = UA_CONNECTIONSTATE_OPENING; 
            shutdownBrokerConnection(bc);
            return;
        }

        MQTTTopicConnection *tc;
        LIST_FOREACH(tc, &bc->topicConnections, next) {
            if(tc->subscribe) {
                err = mqtt_subscribe(&bc->client, (const char*)tc->topic.data, 0);
                if(err == MQTT_OK)
                    err = (enum MQTTErrors)__mqtt_send(&bc->client);
                if(err != MQTT_OK)
                    removeTopicConnection(tc);
                UA_LOG_INFO(bc->mcm->cm.eventSource.eventLoop->logger,
                            UA_LOGCATEGORY_NETWORK, "MQTT %u\t| Created connection "
                            "subscribed on topic \"%s\"",
                            (unsigned)tc->topicConnectionId, (char*)tc->topic.data);
            } else {
                UA_LOG_INFO(bc->mcm->cm.eventSource.eventLoop->logger,
                            UA_LOGCATEGORY_NETWORK, "MQTT %u\t| Created connection "
                            "publishing on topic \"%s\"",
                            (unsigned)tc->topicConnectionId, (char*)tc->topic.data);
                tc->topicConnectionState = UA_CONNECTIONSTATE_ESTABLISHED;
                tc->callback(&mcm->cm, tc->topicConnectionId, tc->application, &tc->context,
                             tc->topicConnectionState, &UA_KEYVALUEMAP_NULL,
                             UA_BYTESTRING_NULL);
            }
        }
    }

    
    if(msg.length == 0)
        return;

    if(bc->client.recv_buffer.curr_sz < msg.length) {
        if(bc->client.recv_buffer.mem_size + msg.length > MQTT_MESSAGE_MAXLEN)
            return;
        uint8_t *mem = (uint8_t*)
            UA_realloc(bc->client.recv_buffer.mem_start,
                       bc->client.recv_buffer.mem_size + msg.length);
        if(!mem)
            return;
        size_t prev_len = bc->client.recv_buffer.mem_size - bc->client.recv_buffer.curr_sz;
        bc->client.recv_buffer.mem_start = mem;
        bc->client.recv_buffer.mem_size += msg.length;
        bc->client.recv_buffer.curr = &mem[prev_len];
        bc->client.recv_buffer.curr_sz += msg.length;
    }
    memcpy(bc->client.recv_buffer.curr, msg.data, msg.length);
    bc->client.recv_buffer.curr += msg.length;
    bc->client.recv_buffer.curr_sz -= msg.length;

    __mqtt_recv(&bc->client);
}

static MQTTBrokerConnection *
createBrokerConnection(MQTTConnectionManager *mcm, const UA_KeyValueMap *params,
                       UA_Boolean validate) {
    
    MQTTBrokerConnection *bc = (MQTTBrokerConnection*)
        UA_calloc(1, sizeof(MQTTBrokerConnection));
    if(!bc)
        return NULL;

    
    UA_StatusCode res = UA_KeyValueMap_copy(params, &bc->params);

    bc->mcm = mcm;

    
    LIST_INSERT_HEAD(&mcm->connections, bc, next);

    
    UA_String *broker = (UA_String*)(uintptr_t)
        UA_KeyValueMap_getScalar(params,
                                 UA_QUALIFIEDNAME(0, "address"),
                                 &UA_TYPES[UA_TYPES_STRING]);
    UA_assert(broker != NULL);

    UA_UInt16 *port = (UA_UInt16*)(uintptr_t)
        UA_KeyValueMap_getScalar(params,
                                 UA_QUALIFIEDNAME(0, "port"),
                                 &UA_TYPES[UA_TYPES_UINT16]);
    UA_UInt16 _port = 1883;
    if(!port)
        port = &_port;

    const UA_UInt16 *keepAlive = (const UA_UInt16*)
        UA_KeyValueMap_getScalar(params,
                                 UA_QUALIFIEDNAME(0, "keep-alive"),
                                 &UA_TYPES[UA_TYPES_UINT16]);

    
    bc->keepalive = 400; 
    if(keepAlive && *keepAlive > 0)
        bc->keepalive = *keepAlive;

    
    UA_KeyValuePair tcpParams[3];
    tcpParams[0].key = UA_QUALIFIEDNAME(0, "address");
    UA_Variant_setScalar(&tcpParams[0].value, broker, &UA_TYPES[UA_TYPES_STRING]);
    tcpParams[1].key = UA_QUALIFIEDNAME(0, "port");
    UA_Variant_setScalar(&tcpParams[1].value, port, &UA_TYPES[UA_TYPES_UINT16]);
    tcpParams[2].key = UA_QUALIFIEDNAME(0, "validate");
    UA_Variant_setScalar(&tcpParams[2].value, &validate, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_KeyValueMap kvm = {3, tcpParams};

    UA_ConnectionManager *tcpCM = mcm->tcpCM;
    res = tcpCM->openConnection(tcpCM, &kvm, NULL, bc, MQTTNetworkCallback);
    if(res != UA_STATUSCODE_GOOD) {
        removeBrokerConnection(bc);
        return NULL;
    }

    
    if(validate) {
        removeBrokerConnection(bc);
        return (MQTTBrokerConnection*)0x01;
    }

    UA_EventLoop *el = mcm->cm.eventSource.eventLoop;
    res = el->addCyclicCallback(el, (UA_Callback)MQTTKeepAliveCallback, NULL, bc,
                                (UA_Double)(bc->keepalive * 0.75 * UA_DATETIME_MSEC),
                                NULL, UA_TIMER_HANDLE_CYCLEMISS_WITH_CURRENTTIME,
                                &bc->keepAliveCallbackId);
    if(res != UA_STATUSCODE_GOOD) {
        removeBrokerConnection(bc);
        return NULL;
    }

    UA_LOG_DEBUG(bc->mcm->cm.eventSource.eventLoop->logger,
                 UA_LOGCATEGORY_NETWORK, "MQTT-TCP %u\t| Created broker connection",
                 (unsigned)bc->tcpConnectionId);

    return bc;
}

static MQTTTopicConnection *
createTopicConnection(MQTTConnectionManager *mcm, MQTTBrokerConnection *bc,
                      const UA_KeyValueMap *params,
                      void *application, void *context,
                      UA_ConnectionManager_connectionCallback connectionCallback) {
    UA_Boolean subscribe = true;
    const UA_Boolean *_subscribe= (const UA_Boolean*)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "subscribe"),
                                 &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(_subscribe)
        subscribe = *_subscribe;
    const UA_String *topic = (const UA_String*)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "topic"),
                                 &UA_TYPES[UA_TYPES_STRING]);
    if(topic->length == 0)
        return NULL;

    MQTTTopicConnection *tc = (MQTTTopicConnection*)
        UA_calloc(1, sizeof(MQTTTopicConnection));
    if(!tc)
        return NULL;
    tc->application = application;
    tc->context = context;
    tc->callback = connectionCallback;
    tc->brokerConnection = bc;
    tc->topicConnectionId = (bc->tcpConnectionId * 1000) + (++bc->lastTopicConnectionId);
    tc->subscribe = subscribe;

    
    tc->topic.data = (UA_Byte*)UA_malloc(topic->length + 1);
    if(!tc->topic.data) {
        UA_free(tc);
        return NULL;
    }
    memcpy(tc->topic.data, topic->data, topic->length);
    tc->topic.data[topic->length] = 0;
    tc->topic.length = topic->length;

    if(bc->tcpConnectionState == UA_CONNECTIONSTATE_ESTABLISHED) {
        tc->topicConnectionState = UA_CONNECTIONSTATE_ESTABLISHED;
        if(subscribe) {
            enum MQTTErrors err = mqtt_subscribe(&bc->client, (const char*)topic->data, 0);
            if(err != MQTT_OK) {
                UA_String_clear(&tc->topic);
                UA_free(tc);
                return NULL;
            }
            UA_LOG_INFO(bc->mcm->cm.eventSource.eventLoop->logger,
                        UA_LOGCATEGORY_NETWORK, "MQTT %u\t| Created connection "
                        "subscribed on topic \"%s\"",
                        (unsigned)tc->topicConnectionId, (char*)topic->data);
        } else {
            UA_LOG_INFO(bc->mcm->cm.eventSource.eventLoop->logger,
                        UA_LOGCATEGORY_NETWORK, "MQTT %u\t| Created connection "
                        "publishing on topic \"%s\"",
                        (unsigned)tc->topicConnectionId, (char*)topic->data);
        }
    } else {
        tc->topicConnectionState = UA_CONNECTIONSTATE_OPENING;
    }

    
    LIST_INSERT_HEAD(&bc->topicConnections, tc, next);

    connectionCallback(&mcm->cm, tc->topicConnectionId, application, &tc->context,
                       tc->topicConnectionState, &UA_KEYVALUEMAP_NULL,
                       UA_BYTESTRING_NULL);
    return tc;
}

static UA_StatusCode
MQTT_openConnection(UA_ConnectionManager *cm, const UA_KeyValueMap *params,
                    void *application, void *context,
                    UA_ConnectionManager_connectionCallback connectionCallback) {
    if(cm->eventSource.state != UA_EVENTSOURCESTATE_STARTED)
        return UA_STATUSCODE_BADINTERNALERROR;

    MQTTConnectionManager *mcm = (MQTTConnectionManager*)cm;

    for(size_t i = 0; i < MQTT_PARAMETERSSIZE; i++) {
        const UA_Variant *val =
            UA_KeyValueMap_get(params, MQTTConnectionParameters[i].name);
        if((!val && MQTTConnectionParameters[i].required) ||
           (val && !UA_Variant_hasScalarType(val, MQTTConnectionParameters[i].type)))
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }

    const UA_Boolean *validate = (const UA_Boolean*)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "validate"),
                                 &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(validate && *validate)
        return (createBrokerConnection(mcm, params, true) == 0) ?
            UA_STATUSCODE_BADCONNECTIONREJECTED : UA_STATUSCODE_GOOD;

    MQTTBrokerConnection *bc = findIdenticalBrokerConnection(mcm, params);
    if(!bc && !(bc = createBrokerConnection(mcm, params, false)))
        return UA_STATUSCODE_BADNOTCONNECTED;

    
    MQTTTopicConnection *tc =
        createTopicConnection(mcm, bc, params, application,
                              context, connectionCallback);
    if(!tc) {
        
        if(LIST_EMPTY(&bc->topicConnections))
            shutdownBrokerConnection(bc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
MQTT_sendWithConnection(UA_ConnectionManager *cm, uintptr_t connectionId,
                        const UA_KeyValueMap *params,
                        UA_ByteString *buf) {
    MQTTConnectionManager *mcm = (MQTTConnectionManager*)cm;
    MQTTTopicConnection *tc = findTopicConnection(mcm, connectionId);
    if(!tc) {
        UA_ByteString_clear(buf);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    MQTTBrokerConnection *bc = tc->brokerConnection;
    if(bc->tcpConnectionState != UA_CONNECTIONSTATE_ESTABLISHED) {
        UA_ByteString_clear(buf);
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }

    UA_LOG_DEBUG(bc->mcm->cm.eventSource.eventLoop->logger,
                 UA_LOGCATEGORY_NETWORK, "MQTT %u\t| Publishing on topic \"%s\" "
                 "a message with %u bytes", (unsigned)tc->topicConnectionId,
                 (char*)tc->topic.data, (unsigned)buf->length);

    enum MQTTErrors res = mqtt_publish(&bc->client, (const char*)tc->topic.data,
                                       buf->data, buf->length, 0);
    if(UA_LIKELY(res == MQTT_OK))
        res = (enum MQTTErrors)__mqtt_send(&bc->client);
    UA_ByteString_clear(buf);
    return (res == MQTT_OK) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINTERNALERROR;
}

static UA_StatusCode
MQTT_shutdownConnection(UA_ConnectionManager *cm, uintptr_t connectionId) {
    MQTTConnectionManager *mcm = (MQTTConnectionManager*)cm;
    MQTTTopicConnection *tc = findTopicConnection(mcm, connectionId);
    if(!tc)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(tc->topicConnectionState == UA_CONNECTIONSTATE_CLOSING ||
       tc->topicConnectionState == UA_CONNECTIONSTATE_CLOSED)
        return UA_STATUSCODE_GOOD;


    UA_EventLoop *el = tc->brokerConnection->mcm->cm.eventSource.eventLoop;
    UA_LOG_DEBUG(el->logger, UA_LOGCATEGORY_NETWORK,
                 "MQTT %u\t| Shutdown called", (unsigned)tc->topicConnectionId);

    tc->topicConnectionState = UA_CONNECTIONSTATE_CLOSING;

    
    UA_DelayedCallback *dc = &tc->dc;
    dc->callback = removeTopicConnectionDelayed;
    dc->application = NULL;
    dc->context = tc;
    el->addDelayedCallback(el, dc);

    return UA_STATUSCODE_GOOD;
}

static const char *mqttName = "mqtt";

UA_ConnectionManager *
UA_ConnectionManager_new_MQTT(const UA_String eventSourceName) {
    MQTTConnectionManager *cm = (MQTTConnectionManager*)
        UA_calloc(1, sizeof(MQTTConnectionManager));
    if(!cm)
        return NULL;

    cm->cm.eventSource.eventSourceType = UA_EVENTSOURCETYPE_CONNECTIONMANAGER;
    UA_String_copy(&eventSourceName, &cm->cm.eventSource.name);
    cm->cm.eventSource.start = (UA_StatusCode (*)(UA_EventSource *))MQTT_eventSourceStart;
    cm->cm.eventSource.stop = (void (*)(UA_EventSource *))MQTT_eventSourceStop;
    cm->cm.eventSource.free = (UA_StatusCode (*)(UA_EventSource *))MQTT_eventSourceDelete;
    cm->cm.protocol = UA_STRING((char*)(uintptr_t)mqttName);
    cm->cm.openConnection = MQTT_openConnection;
    cm->cm.allocNetworkBuffer = MQTT_allocNetworkBuffer;
    cm->cm.freeNetworkBuffer = MQTT_freeNetworkBuffer;
    cm->cm.sendWithConnection = MQTT_sendWithConnection;
    cm->cm.closeConnection = MQTT_shutdownConnection;
    return &cm->cm;
}

#endif 
