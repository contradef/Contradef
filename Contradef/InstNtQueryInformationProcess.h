#pragma once
#ifndef INST_NT_QUERY_INFORMATION_PROCESS_H
#define INST_NT_QUERY_INFORMATION_PROCESS_H

#include "pin.H"
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <vector>
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

struct NtQueryInformationProcessArgs {
    ADDRINT ProcessHandle;
    ADDRINT ProcessInformationClass;
    ADDRINT ProcessInformation;
    ADDRINT ProcessInformationLength;
    ADDRINT ReturnLength;
};

class InstNtQueryInformationProcess : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:

    static ADDRINT TARGET_MEMORY_ADDRESS;
    static LONG retVal;
    static DWORD InstNtQueryInformationProcess::NtGlobalFlag;
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;
    static VOID CheckPrintConditions(CallContext* callContext);
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT ProcessHandle, ADDRINT ProcessInformationClass, ADDRINT ProcessInformation, ADDRINT ProcessInformationLength, ADDRINT ReturnLength);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT ProcessHandle, ADDRINT ProcessInformationClass, ADDRINT ProcessInformation, ADDRINT ProcessInformationLength, ADDRINT ReturnLength);
    static VOID ReadMemoryValue(THREADID tid, CallContext* callContext, CONTEXT* ctxt, INS ins, ADDRINT instAddress, ADDRINT memoryAddress, UINT32 readSize);
    static bool IsRegisterAllowed(const REG& regName);
    static VOID RegContentAnalysisRoutine(CONTEXT* ctxt, REG regToInspect);
    static VOID Instruction(INS ins, VOID* v);
};

#endif // INST_NT_QUERY_INFORMATION_PROCESS_H
