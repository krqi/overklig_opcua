
#ifndef UA_EVENTLOOP_H_
#define UA_EVENTLOOP_H_

#include <opcua/types.h>
#include <opcua/types_generated.h>
#include <opcua/util.h>
#include <opcua/plugin/log.h>

_UA_BEGIN_DECLS

struct UA_EventLoop;
typedef struct UA_EventLoop UA_EventLoop;

struct UA_EventSource;
typedef struct UA_EventSource UA_EventSource;

struct UA_ConnectionManager;
typedef struct UA_ConnectionManager UA_ConnectionManager;

struct UA_InterruptManager;
typedef struct UA_InterruptManager UA_InterruptManager;


typedef enum {
    UA_TIMER_HANDLE_CYCLEMISS_WITH_CURRENTTIME = 0, 
    UA_TIMER_HANDLE_CYCLEMISS_WITH_BASETIME = 1,    
    UA_TIMERPOLICY_CURRENTTIME = 0,
    UA_TIMERPOLICY_BASETIME = 1,
} UA_TimerPolicy;


typedef void (*UA_Callback)(void *application, void *context);

typedef struct UA_DelayedCallback {
    struct UA_DelayedCallback *next; 
    UA_Callback callback;
    void *application;
    void *context;
} UA_DelayedCallback;

typedef enum {
    UA_EVENTLOOPSTATE_FRESH = 0,
    UA_EVENTLOOPSTATE_STOPPED,
    UA_EVENTLOOPSTATE_STARTED,
} UA_EventLoopState;

struct UA_EventLoop {

    const UA_Logger *logger;

    UA_KeyValueMap params;


    const volatile UA_EventLoopState state; 

    
    UA_StatusCode (*start)(UA_EventLoop *el);

    void (*stop)(UA_EventLoop *el);

    UA_StatusCode (*free)(UA_EventLoop *el);

    UA_StatusCode (*run)(UA_EventLoop *el, UA_UInt32 timeout);

    void (*cancel)(UA_EventLoop *el);


    UA_DateTime (*dateTime_now)(UA_EventLoop *el);
    UA_DateTime (*dateTime_nowMonotonic)(UA_EventLoop *el);
    UA_Int64    (*dateTime_localTimeUtcOffset)(UA_EventLoop *el);


    UA_DateTime (*nextCyclicTime)(UA_EventLoop *el);

    UA_StatusCode
    (*addCyclicCallback)(UA_EventLoop *el, UA_Callback cb, void *application,
                         void *data, UA_Double interval_ms, UA_DateTime *baseTime,
                         UA_TimerPolicy timerPolicy, UA_UInt64 *callbackId);

    UA_StatusCode
    (*modifyCyclicCallback)(UA_EventLoop *el, UA_UInt64 callbackId,
                            UA_Double interval_ms, UA_DateTime *baseTime,
                            UA_TimerPolicy timerPolicy);

    void (*removeCyclicCallback)(UA_EventLoop *el, UA_UInt64 callbackId);

    
    UA_StatusCode
    (*addTimedCallback)(UA_EventLoop *el, UA_Callback cb, void *application,
                        void *data, UA_DateTime date, UA_UInt64 *callbackId);


    void (*addDelayedCallback)(UA_EventLoop *el, UA_DelayedCallback *dc);
    void (*removeDelayedCallback)(UA_EventLoop *el, UA_DelayedCallback *dc);


    
    UA_EventSource *eventSources;

    UA_StatusCode
    (*registerEventSource)(UA_EventLoop *el, UA_EventSource *es);

    
    UA_StatusCode
    (*deregisterEventSource)(UA_EventLoop *el, UA_EventSource *es);
};


typedef enum {
    UA_EVENTSOURCESTATE_FRESH = 0,
    UA_EVENTSOURCESTATE_STOPPED,      
    UA_EVENTSOURCESTATE_STARTING,
    UA_EVENTSOURCESTATE_STARTED,
} UA_EventSourceState;

typedef enum {
    UA_EVENTSOURCETYPE_CONNECTIONMANAGER,
    UA_EVENTSOURCETYPE_INTERRUPTMANAGER
} UA_EventSourceType;

struct UA_EventSource {

    UA_EventSourceType eventSourceType;

    UA_String name;                 
    UA_EventLoop *eventLoop;        
    UA_KeyValueMap params;

    UA_EventSourceState state;
    UA_StatusCode (*start)(UA_EventSource *es);
    UA_StatusCode (*free)(UA_EventSource *es);
};


typedef void
(*UA_ConnectionManager_connectionCallback)
     (UA_ConnectionManager *cm, uintptr_t connectionId,
      void *application, void **connectionContext, UA_ConnectionState state,
      const UA_KeyValueMap *params, UA_ByteString msg);

struct UA_ConnectionManager {
    UA_EventSource eventSource;

    UA_String protocol;

    UA_StatusCode
    (*openConnection)(UA_ConnectionManager *cm, const UA_KeyValueMap *params,
                      void *application, void *context,
                      UA_ConnectionManager_connectionCallback connectionCallback);

    UA_StatusCode
    (*sendWithConnection)(UA_ConnectionManager *cm, uintptr_t connectionId,
                          const UA_KeyValueMap *params, UA_ByteString *buf);

    UA_StatusCode
    (*closeConnection)(UA_ConnectionManager *cm, uintptr_t connectionId);

    UA_StatusCode
    (*allocNetworkBuffer)(UA_ConnectionManager *cm, uintptr_t connectionId,
                          UA_ByteString *buf, size_t bufSize);
    void
    (*freeNetworkBuffer)(UA_ConnectionManager *cm, uintptr_t connectionId,
                         UA_ByteString *buf);
};


typedef void
(*UA_InterruptCallback)(UA_InterruptManager *im,
                        uintptr_t interruptHandle, void *interruptContext,
                        const UA_KeyValueMap *instanceInfos);

struct UA_InterruptManager {
    UA_EventSource eventSource;

    UA_StatusCode
    (*registerInterrupt)(UA_InterruptManager *im, uintptr_t interruptHandle,
                         const UA_KeyValueMap *params,
                         UA_InterruptCallback callback, void *interruptContext);

    void
    (*deregisterInterrupt)(UA_InterruptManager *im, uintptr_t interruptHandle);
};

#if defined(UA_ARCHITECTURE_POSIX) || defined(UA_ARCHITECTURE_WIN32)


UA_EXPORT UA_EventLoop *
UA_EventLoop_new_POSIX(const UA_Logger *logger);

UA_EXPORT UA_ConnectionManager *
UA_ConnectionManager_new_POSIX_TCP(const UA_String eventSourceName);

UA_EXPORT UA_ConnectionManager *
UA_ConnectionManager_new_POSIX_UDP(const UA_String eventSourceName);

UA_EXPORT UA_ConnectionManager *
UA_ConnectionManager_new_POSIX_Ethernet(const UA_String eventSourceName);

UA_EXPORT UA_ConnectionManager *
UA_ConnectionManager_new_MQTT(const UA_String eventSourceName);

UA_EXPORT UA_InterruptManager *
UA_InterruptManager_new_POSIX(const UA_String eventSourceName);

#endif 

_UA_END_DECLS

#endif 
