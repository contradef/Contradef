#pragma once
#ifndef INST_GET_WRITE_WATCH_H
#define INST_GET_WRITE_WATCH_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <deque>
#include <queue>
#include "utils.h"
#include "CallContext.h"
#include "Notifier.h"
#include "Observer.h"
#include "Instrumentation.h"
#include "InstrumentationStrategy.h"
#include "NtStructures.h"


struct GetWriteWatchArgs {
    ADDRINT dwFlags;
    ADDRINT lpBaseAddress;
    ADDRINT dwRegionSize;
    ADDRINT lpAddresses;
    ADDRINT lpdwCount;
};

class InstGetWriteWatch : public InstrumentationStrategy {
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
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT dwFlags, ADDRINT lpBaseAddress, ADDRINT dwRegionSize, ADDRINT lpAddresses, ADDRINT lpdwCount, ADDRINT lpdwGranularity);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT dwFlags, ADDRINT lpBaseAddress, ADDRINT dwRegionSize, ADDRINT lpAddresses, ADDRINT lpdwCount, ADDRINT lpdwGranularity);
};

#endif // INST_GET_WRITE_WATCH_H
