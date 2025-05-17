#pragma once
#ifndef INST_COMPARE_STRING_EX_H
#define INST_COMPARE_STRING_EX_H

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

// Estrutura para armazenar os argumentos da função CompareStringEx
struct CompareStringExArgs {
    ADDRINT lpLocaleName;   // LPCWSTR
    ADDRINT dwCmpFlags;     // DWORD
    ADDRINT lpString1;      // LPCWSTR
    ADDRINT cchCount1;      // int
    ADDRINT lpString2;      // LPCWSTR
    ADDRINT cchCount2;      // int
    ADDRINT lpVersionInformation; // LPNLSVERSIONINFO
    ADDRINT lpReserved;     // LPVOID
    ADDRINT sortHandle;     // LPARAM
};

class InstCompareStringEx : public InstrumentationStrategy {
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
        ADDRINT lpLocaleName, ADDRINT dwCmpFlags, ADDRINT lpString1, ADDRINT cchCount1,
        ADDRINT lpString2, ADDRINT cchCount2, ADDRINT lpVersionInformation, ADDRINT lpReserved, ADDRINT sortHandle);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT lpLocaleName, ADDRINT dwCmpFlags, ADDRINT lpString1, ADDRINT cchCount1,
        ADDRINT lpString2, ADDRINT cchCount2, ADDRINT lpVersionInformation, ADDRINT lpReserved, ADDRINT sortHandle);
};

#endif // INST_COMPARE_STRING_EX_H
