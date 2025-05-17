#pragma once
#ifndef INST_CREATE_FILE_W_H
#define INST_CREATE_FILE_W_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <deque>
#include <queue>
#include "utils.h"
#include "CallContext.h"
#include "Notifier.h"
#include "Observer.h"
#include "Instrumentation.h"
#include "InstrumentationStrategy.h"

struct CreateFileWArgs {
    std::wstring lpFileName;
    ADDRINT dwDesiredAccess;
    ADDRINT dwShareMode;
    ADDRINT lpSecurityAttributes;
    ADDRINT dwCreationDisposition;
    ADDRINT dwFlagsAndAttributes;
    ADDRINT hTemplateFile;
};

class InstCreateFileW : public InstrumentationStrategy {
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
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT lpFileName, ADDRINT dwDesiredAccess, ADDRINT dwShareMode, ADDRINT lpSecurityAttributes, ADDRINT dwCreationDisposition, ADDRINT dwFlagsAndAttributes, ADDRINT hTemplateFile);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT lpFileName);
};

#endif // INST_CREATE_FILE_W_H
