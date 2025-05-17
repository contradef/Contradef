#pragma once
#ifndef INST_ENUM_PROCESS_MODULES_H
#define INST_ENUM_PROCESS_MODULES_H

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

struct InstEnumProcessModulesArgs {
    ADDRINT hProcess;
    ADDRINT lphModule;
    ADDRINT cb;
    ADDRINT lpcbNeeded;
};

class InstEnumProcessModules : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT hProcess, ADDRINT lphModule, ADDRINT cb, ADDRINT lpcbNeeded);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
        ADDRINT hProcess, ADDRINT lphModule, ADDRINT cb, ADDRINT lpcbNeeded);
};

#endif // INST_ENUM_PROCESS_MODULES_H
