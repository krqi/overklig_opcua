
#ifndef UA_PLUGIN_HISTORY_DATA_BACKEND_H_
#define UA_PLUGIN_HISTORY_DATA_BACKEND_H_

#include <opcua/server.h>

_UA_BEGIN_DECLS

typedef enum {
    MATCH_EQUAL, 
} MatchStrategy;

typedef struct UA_HistoryDataBackend UA_HistoryDataBackend;

struct UA_HistoryDataBackend {
    void *context;

    void
    (*deleteMembers)(UA_HistoryDataBackend *backend);

    UA_StatusCode
    (*serverSetHistoryData)(UA_Server *server,
                            void *hdbContext,
                            const UA_NodeId *sessionId,
                            void *sessionContext,
                            const UA_NodeId *nodeId,
                            UA_Boolean historizing,
                            const UA_DataValue *value);

    UA_StatusCode
    (*getHistoryData)(UA_Server *server,
                      const UA_NodeId *sessionId,
                      void *sessionContext,
                      const UA_HistoryDataBackend *backend,
                      const UA_DateTime start,
                      const UA_DateTime end,
                      const UA_NodeId *nodeId,
                      size_t maxSizePerResponse,
                      UA_UInt32 numValuesPerNode,
                      UA_Boolean returnBounds,
                      UA_TimestampsToReturn timestampsToReturn,
                      UA_NumericRange range,
                      UA_Boolean releaseContinuationPoints,
                      const UA_ByteString *continuationPoint,
                      UA_ByteString *outContinuationPoint,
                      UA_HistoryData *result);

    size_t
    (*getDateTimeMatch)(UA_Server *server,
                        void *hdbContext,
                        const UA_NodeId *sessionId,
                        void *sessionContext,
                        const UA_NodeId *nodeId,
                        const UA_DateTime timestamp,
                        const MatchStrategy strategy);

    size_t
    (*getEnd)(UA_Server *server,
              void *hdbContext,
              const UA_NodeId *sessionId,
              void *sessionContext,
              const UA_NodeId *nodeId);

    size_t
    (*lastIndex)(UA_Server *server,
                 void *hdbContext,
                 const UA_NodeId *sessionId,
                 void *sessionContext,
                 const UA_NodeId *nodeId);

    size_t
    (*firstIndex)(UA_Server *server,
                  void *hdbContext,
                  const UA_NodeId *sessionId,
                  void *sessionContext,
                  const UA_NodeId *nodeId);

    size_t
    (*resultSize)(UA_Server *server,
                  void *hdbContext,
                  const UA_NodeId *sessionId,
                  void *sessionContext,
                  const UA_NodeId *nodeId,
                  size_t startIndex,
                  size_t endIndex);

    UA_StatusCode
    (*copyDataValues)(UA_Server *server,
                      void *hdbContext,
                      const UA_NodeId *sessionId,
                      void *sessionContext,
                      const UA_NodeId *nodeId,
                      size_t startIndex,
                      size_t endIndex,
                      UA_Boolean reverse,
                      size_t valueSize,
                      UA_NumericRange range,
                      UA_Boolean releaseContinuationPoints,
                      const UA_ByteString *continuationPoint,
                      UA_ByteString *outContinuationPoint,
                      size_t *providedValues,
                      UA_DataValue *values);

    const UA_DataValue*
    (*getDataValue)(UA_Server *server,
                    void *hdbContext,
                    const UA_NodeId *sessionId,
                    void *sessionContext,
                    const UA_NodeId *nodeId,
                    size_t index);

    UA_Boolean
    (*boundSupported)(UA_Server *server,
                      void *hdbContext,
                      const UA_NodeId *sessionId,
                      void *sessionContext,
                      const UA_NodeId *nodeId);

    UA_Boolean
    (*timestampsToReturnSupported)(UA_Server *server,
                                   void *hdbContext,
                                   const UA_NodeId *sessionId,
                                   void *sessionContext,
                                   const UA_NodeId *nodeId,
                                   const UA_TimestampsToReturn timestampsToReturn);

    UA_StatusCode
    (*insertDataValue)(UA_Server *server,
                       void *hdbContext,
                       const UA_NodeId *sessionId,
                       void *sessionContext,
                       const UA_NodeId *nodeId,
                       const UA_DataValue *value);
    UA_StatusCode
    (*replaceDataValue)(UA_Server *server,
                        void *hdbContext,
                        const UA_NodeId *sessionId,
                        void *sessionContext,
                        const UA_NodeId *nodeId,
                        const UA_DataValue *value);
    UA_StatusCode
    (*updateDataValue)(UA_Server *server,
                       void *hdbContext,
                       const UA_NodeId *sessionId,
                       void *sessionContext,
                       const UA_NodeId *nodeId,
                       const UA_DataValue *value);
    UA_StatusCode
    (*removeDataValue)(UA_Server *server,
                       void *hdbContext,
                       const UA_NodeId *sessionId,
                       void *sessionContext,
                       const UA_NodeId *nodeId,
                       UA_DateTime startTimestamp,
                       UA_DateTime endTimestamp);
};

_UA_END_DECLS

#endif 
