#pragma once
#ifndef INST_GET_MODULE_FILE_NAME_W_H
#define INST_GET_MODULE_FILE_NAME_W_H

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

struct GetModuleFileNameWArgs {
    ADDRINT hModule;
    ADDRINT lpFilename;
    ADDRINT nSize;
};

class InstGetModuleFileNameW : public InstrumentationStrategy {
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
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT hModule, ADDRINT lpFilename, ADDRINT nSize);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal, ADDRINT lpFilename, ADDRINT nSize);
};

#endif // INST_GET_MODULE_FILE_NAME_W_H
