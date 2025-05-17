#pragma once
#ifndef INST_VIRTUAL_QUERY_EX_H
#define INST_VIRTUAL_QUERY_EX_H

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

struct InstVirtualQueryExArgs {
    ADDRINT hProcess;
    ADDRINT lpAddress;
    ADDRINT lpBuffer;
    ADDRINT dwLength;
};

class InstVirtualQueryEx : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;
    static unsigned long InstVirtualQueryEx::show_module(MEMORY_BASIC_INFORMATION info, std::stringstream& stringStream);
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT hProcess, ADDRINT lpAddress, ADDRINT lpBuffer, ADDRINT dwLength);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
        ADDRINT hProcess, ADDRINT lpAddress, ADDRINT lpBuffer, ADDRINT dwLength);
};

#endif // INST_VIRTUAL_QUERY_EX_H
