#pragma once
#ifndef INST_NT_QUERY_PERFORMANCE_COUNTER_H
#define INST_NT_QUERY_PERFORMANCE_COUNTER_H

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

struct InstNtQueryPerformanceCounterArgs {
    ADDRINT PerformanceCounter;
    ADDRINT PerformanceFrequency;
};

class InstNtQueryPerformanceCounter : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
        ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency);
};

#endif // INST_NT_QUERY_PERFORMANCE_COUNTER_H
