#pragma once
#ifndef INST_SHELL_EXECUTE_H
#define INST_SHELL_EXECUTE_H

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

struct InstShellExecuteArgs {
    ADDRINT hwnd;
    ADDRINT lpOperation;
    ADDRINT lpFile;
    ADDRINT lpParameters;
    ADDRINT lpDirectory;
    ADDRINT nShowCmd;
};

class InstShellExecute : public InstrumentationStrategy {
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
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT hwnd, ADDRINT lpOperation, ADDRINT lpFile, ADDRINT lpParameters, ADDRINT lpDirectory, ADDRINT nShowCmd);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
        ADDRINT hwnd, ADDRINT lpOperation, ADDRINT lpFile, ADDRINT lpParameters, ADDRINT lpDirectory, ADDRINT nShowCmd);
};

#endif // INST_SHELL_EXECUTE_H
