#pragma once
#ifndef INST_CO_CREATE_INSTANCE_H
#define INST_CO_CREATE_INSTANCE_H

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

struct InstCoCreateInstanceArgs {
    ADDRINT rclsid;
    ADDRINT pUnkOuter;
    ADDRINT dwClsContext;
    ADDRINT riid;
    ADDRINT ppv;
};

class InstCoCreateInstance : public InstrumentationStrategy {
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
        ADDRINT rclsid, ADDRINT pUnkOuter, ADDRINT dwClsContext, ADDRINT riid, ADDRINT ppv);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
        ADDRINT rclsid, ADDRINT pUnkOuter, ADDRINT dwClsContext, ADDRINT riid, ADDRINT ppv);
};

#endif // INST_CO_CREATE_INSTANCE_H
