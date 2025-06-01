#pragma once
#ifndef INST_RTL_ALLOCATE_HEAP_H
#define INST_RTL_ALLOCATE_HEAP_H

#include "pin.H"
#include <iostream>
#include <sstream>
#include <map>
#include "utils.h"
#include "CallContext.h"
#include "Notifier.h"
#include "Observer.h"
#include "Instrumentation.h"
#include "InstrumentationStrategy.h"

// -------- argumentos da função --------
struct RtlAllocateHeapArgs {
    ADDRINT HeapHandle;  // HANDLE
    ADDRINT Flags;       // ULONG
    ADDRINT Size;        // SIZE_T
};

class InstRtlAllocateHeap : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData*, void*) {}
    static VOID HandleTraceEvent(const EventData*, void*) {}

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;

    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT inst, ADDRINT rtn, CONTEXT*,
        ADDRINT retIP,
        ADDRINT HeapHandle, ADDRINT Flags, ADDRINT Size);

    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT inst, ADDRINT rtn, CONTEXT*,
        ADDRINT retIP,
        ADDRINT retValAddr,
        ADDRINT HeapHandle, ADDRINT Flags, ADDRINT Size);
};

#endif
