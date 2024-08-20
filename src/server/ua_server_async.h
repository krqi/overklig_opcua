
#ifndef UA_SERVER_ASYNC_H_
#define UA_SERVER_ASYNC_H_

#include <opcua/server.h>

#include "opcua_queue.h"
#include "util/ua_util_internal.h"

_UA_BEGIN_DECLS

#if UA_MULTITHREADING >= 100

struct UA_AsyncResponse;
typedef struct UA_AsyncResponse UA_AsyncResponse;


typedef struct UA_AsyncOperation {
    TAILQ_ENTRY(UA_AsyncOperation) pointers;
    UA_CallMethodRequest request;
    UA_CallMethodResult	response;
} UA_AsyncOperation;

struct UA_AsyncResponse {
    TAILQ_ENTRY(UA_AsyncResponse) pointers; 
    UA_UInt32 requestId;
    UA_NodeId sessionId;
    UA_UInt32 requestHandle;
    UA_DateTime	timeout;
    UA_AsyncOperationType operationType;
    union {
        UA_CallResponse callResponse;
        UA_ReadResponse readResponse;
        UA_WriteResponse writeResponse;
    } response;
};

typedef TAILQ_HEAD(UA_AsyncOperationQueue, UA_AsyncOperation) UA_AsyncOperationQueue;

typedef struct {
    
    TAILQ_HEAD(, UA_AsyncResponse) asyncResponses;
    size_t asyncResponsesCount;

    UA_AsyncOperationQueue newQueue;        
    UA_AsyncOperationQueue resultQueue;     
    size_t opsCount; 

    UA_UInt64 checkTimeoutCallbackId; 
} UA_AsyncManager;

void UA_AsyncManager_init(UA_AsyncManager *am, UA_Server *server);
void UA_AsyncManager_start(UA_AsyncManager *am, UA_Server *server);
void UA_AsyncManager_stop(UA_AsyncManager *am, UA_Server *server);
void UA_AsyncManager_clear(UA_AsyncManager *am, UA_Server *server);

UA_StatusCode
UA_AsyncManager_createAsyncResponse(UA_AsyncManager *am, UA_Server *server,
                                    const UA_NodeId *sessionId,
                                    const UA_UInt32 requestId,
                                    const UA_UInt32 requestHandle,
                                    const UA_AsyncOperationType operationType,
                                    UA_AsyncResponse **outAr);


void
UA_AsyncManager_removeAsyncResponse(UA_AsyncManager *am, UA_AsyncResponse *ar);

UA_StatusCode
UA_AsyncManager_createAsyncOp(UA_AsyncManager *am, UA_Server *server,
                              UA_AsyncResponse *ar, size_t opIndex,
                              const UA_CallMethodRequest *opRequest);

UA_UInt32
UA_AsyncManager_cancel(UA_Server *server, UA_Session *session, UA_UInt32 requestHandle);

typedef void (*UA_AsyncServiceOperation)(UA_Server *server, UA_Session *session,
                                         UA_UInt32 requestId, UA_UInt32 requestHandle,
                                         size_t opIndex, const void *requestOperation,
                                         void *responseOperation, UA_AsyncResponse **ar);

UA_StatusCode
UA_Server_processServiceOperationsAsync(UA_Server *server, UA_Session *session,
                                        UA_UInt32 requestId, UA_UInt32 requestHandle,
                                        UA_AsyncServiceOperation operationCallback,
                                        const size_t *requestOperations,
                                        const UA_DataType *requestOperationsType,
                                        size_t *responseOperations,
                                        const UA_DataType *responseOperationsType,
                                        UA_AsyncResponse **ar)
UA_FUNC_ATTR_WARN_UNUSED_RESULT;

#endif 

_UA_END_DECLS

#endif 
