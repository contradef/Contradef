#pragma once
#pragma once
#ifndef INST_GET_ENVIRONMENT_VARIABLE_W_H
#define INST_GET_ENVIRONMENT_VARIABLE_W_H

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

struct GetEnvironmentVariableWArgs {
    ADDRINT lpName;
    ADDRINT lpBuffer;
    DWORD nSize;
};

class InstGetEnvironmentVariableW : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT lpName, ADDRINT lpBuffer, ADDRINT nSize);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal,
        ADDRINT lpBuffer, ADDRINT nSize);
};

#endif // INST_GET_ENVIRONMENT_VARIABLE_W_H
