
#ifndef UA_PLUGIN_HISTORYDATABASE_H_
#define UA_PLUGIN_HISTORYDATABASE_H_

#include <opcua/util.h>

_UA_BEGIN_DECLS

typedef struct UA_HistoryDatabase UA_HistoryDatabase;

struct UA_HistoryDatabase {
    void *context;

    void (*clear)(UA_HistoryDatabase *hdb);

    void
    (*setValue)(UA_Server *server,
                void *hdbContext,
                const UA_NodeId *sessionId,
                void *sessionContext,
                const UA_NodeId *nodeId,
                UA_Boolean historizing,
                const UA_DataValue *value);

    void
    (*setEvent)(UA_Server *server,
                void *hdbContext,
                const UA_NodeId *originId,
                const UA_NodeId *emitterId,
                const UA_EventFilter *historicalEventFilter,
                UA_EventFieldList *fieldList);

    void
    (*readRaw)(UA_Server *server,
               void *hdbContext,
               const UA_NodeId *sessionId,
               void *sessionContext,
               const UA_RequestHeader *requestHeader,
               const UA_ReadRawModifiedDetails *historyReadDetails,
               UA_TimestampsToReturn timestampsToReturn,
               UA_Boolean releaseContinuationPoints,
               size_t nodesToReadSize,
               const UA_HistoryReadValueId *nodesToRead,
               UA_HistoryReadResponse *response,
               UA_HistoryData * const * const historyData);

    void
    (*readModified)(UA_Server *server,
               void *hdbContext,
               const UA_NodeId *sessionId,
               void *sessionContext,
               const UA_RequestHeader *requestHeader,
               const UA_ReadRawModifiedDetails *historyReadDetails,
               UA_TimestampsToReturn timestampsToReturn,
               UA_Boolean releaseContinuationPoints,
               size_t nodesToReadSize,
               const UA_HistoryReadValueId *nodesToRead,
               UA_HistoryReadResponse *response,
               UA_HistoryModifiedData * const * const historyData);

    void
    (*readEvent)(UA_Server *server,
               void *hdbContext,
               const UA_NodeId *sessionId,
               void *sessionContext,
               const UA_RequestHeader *requestHeader,
               const UA_ReadEventDetails *historyReadDetails,
               UA_TimestampsToReturn timestampsToReturn,
               UA_Boolean releaseContinuationPoints,
               size_t nodesToReadSize,
               const UA_HistoryReadValueId *nodesToRead,
               UA_HistoryReadResponse *response,
               UA_HistoryEvent * const * const historyData);

    void
    (*readProcessed)(UA_Server *server,
               void *hdbContext,
               const UA_NodeId *sessionId,
               void *sessionContext,
               const UA_RequestHeader *requestHeader,
               const UA_ReadProcessedDetails *historyReadDetails,
               UA_TimestampsToReturn timestampsToReturn,
               UA_Boolean releaseContinuationPoints,
               size_t nodesToReadSize,
               const UA_HistoryReadValueId *nodesToRead,
               UA_HistoryReadResponse *response,
               UA_HistoryData * const * const historyData);

    void
    (*readAtTime)(UA_Server *server,
               void *hdbContext,
               const UA_NodeId *sessionId,
               void *sessionContext,
               const UA_RequestHeader *requestHeader,
               const UA_ReadAtTimeDetails *historyReadDetails,
               UA_TimestampsToReturn timestampsToReturn,
               UA_Boolean releaseContinuationPoints,
               size_t nodesToReadSize,
               const UA_HistoryReadValueId *nodesToRead,
               UA_HistoryReadResponse *response,
               UA_HistoryData * const * const historyData);

    void
    (*updateData)(UA_Server *server,
                  void *hdbContext,
                  const UA_NodeId *sessionId,
                  void *sessionContext,
                  const UA_RequestHeader *requestHeader,
                  const UA_UpdateDataDetails *details,
                  UA_HistoryUpdateResult *result);

    void
    (*deleteRawModified)(UA_Server *server,
                         void *hdbContext,
                         const UA_NodeId *sessionId,
                         void *sessionContext,
                         const UA_RequestHeader *requestHeader,
                         const UA_DeleteRawModifiedDetails *details,
                         UA_HistoryUpdateResult *result);

};

_UA_END_DECLS

#endif 
