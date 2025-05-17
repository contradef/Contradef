#pragma once
#ifndef INST_VIRTUAL_ALLOC_H
#define INST_VIRTUAL_ALLOC_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"
#include "CallContext.h"
#include "Notifier.h"
#include "Observer.h"
#include "Instrumentation.h"
#include "InstrumentationStrategy.h"

struct VirtualAllocArgs {
    ADDRINT lpAddress;
    ADDRINT dwSize;
    ADDRINT flAllocationType;
    ADDRINT flProtect;
};

class InstVirtualAlloc : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;
    static VOID CheckPrintConditions(CallContext* callContext);
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT lpAddress, ADDRINT dwSize, ADDRINT flAllocationType, ADDRINT flProtect);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retValAddr,
        ADDRINT lpAddress, ADDRINT dwSize, ADDRINT flAllocationType, ADDRINT flProtect);
};

#endif // INST_VIRTUAL_ALLOC_H
