#pragma once
#ifndef INST_CREATE_PROCESS_AS_USER_H
#define INST_CREATE_PROCESS_AS_USER_H

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

struct InstCreateProcessAsUserArgs {
    ADDRINT hToken;
    ADDRINT lpApplicationName;
    ADDRINT lpCommandLine;
    ADDRINT lpProcessAttributes;
    ADDRINT lpThreadAttributes;
    ADDRINT bInheritHandles;
    ADDRINT dwCreationFlags;
    ADDRINT lpEnvironment;
    ADDRINT lpCurrentDirectory;
    ADDRINT lpStartupInfo;
    ADDRINT lpProcessInformation;
};

class InstCreateProcessAsUser : public InstrumentationStrategy {
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
        ADDRINT hToken, ADDRINT lpApplicationName, ADDRINT lpCommandLine, ADDRINT lpProcessAttributes,
        ADDRINT lpThreadAttributes, ADDRINT bInheritHandles, ADDRINT dwCreationFlags, ADDRINT lpEnvironment,
        ADDRINT lpCurrentDirectory, ADDRINT lpStartupInfo, ADDRINT lpProcessInformation);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
        ADDRINT hToken, ADDRINT lpApplicationName, ADDRINT lpCommandLine, ADDRINT lpProcessAttributes,
        ADDRINT lpThreadAttributes, ADDRINT bInheritHandles, ADDRINT dwCreationFlags, ADDRINT lpEnvironment,
        ADDRINT lpCurrentDirectory, ADDRINT lpStartupInfo, ADDRINT lpProcessInformation);
};

#endif // INST_CREATE_PROCESS_AS_USER_H
