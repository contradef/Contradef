#pragma once
#ifndef INST_NT_SET_INFORMATION_THREAD_H
#define INST_NT_SET_INFORMATION_THREAD_H

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

struct NtSetInformationThreadArgs {
    ADDRINT ThreadHandle;
    ADDRINT ThreadInformationClass;
    ADDRINT ThreadInformation;
    ADDRINT ThreadInformationLength;
};

class InstNtSetInformationThread : public InstrumentationStrategy {
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
        ADDRINT ThreadHandle, ADDRINT ThreadInformationClass, ADDRINT ThreadInformation, ADDRINT ThreadInformationLength);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal);
};

#endif // INST_NT_SET_INFORMATION_THREAD_H
