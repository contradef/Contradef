#pragma once
#ifndef CALL_CONTEXT_H
#define CALL_CONTEXT_H

#include "pin.H"
#include "EventData.h"
#include "Observer.h"
#include "Notifier.h"

struct CallContextKey {
    UINT32 callId;
    THREADID threadId;
    bool operator<(const CallContextKey& other) const {
        if (callId < other.callId) return true;
        if (callId > other.callId) return false;
        return threadId < other.threadId;
    }
};

struct CallContext {
    ADDRINT rtnAddress;
    std::stringstream stringStream;
    VOID* functionArgs;
    UINT32 maxInst = 0;
    UINT32 callId; // Identificador único para cada chamada
    THREADID threadId; // Identificador da thread

    // Construtor para inicializar o contexto com IDs
    CallContext(UINT32 cid, THREADID tid, ADDRINT rtnAddr, VOID* args) : callId(cid), threadId(tid), rtnAddress(rtnAddr), functionArgs(args) {}
};

STATIC bool instrumentOnlyMain = TRUE;

#endif // CALL_CONTEXT_H
