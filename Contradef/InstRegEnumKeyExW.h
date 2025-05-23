#pragma once
#ifndef INST_REG_ENUM_KEY_EX_W_H
#define INST_REG_ENUM_KEY_EX_W_H

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

// Estrutura para armazenar os argumentos da fun��o RegEnumKeyExW
struct RegEnumKeyExWArgs {
    ADDRINT hKey;               // HKEY
    ADDRINT dwIndex;            // DWORD
    ADDRINT lpName;             // LPWSTR
    ADDRINT lpcchName;          // LPDWORD
    ADDRINT lpReserved;         // LPDWORD (deve ser NULL)
    ADDRINT lpClass;            // LPWSTR
    ADDRINT lpcchClass;         // LPDWORD
    ADDRINT lpftLastWriteTime;  // PFILETIME
};

class InstRegEnumKeyExW : public InstrumentationStrategy {
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
        ADDRINT hKey, ADDRINT dwIndex, ADDRINT lpName, ADDRINT lpcchName, ADDRINT lpReserved,
        ADDRINT lpClass, ADDRINT lpcchClass, ADDRINT lpftLastWriteTime);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT hKey, ADDRINT dwIndex, ADDRINT lpName, ADDRINT lpcchName,
        ADDRINT lpReserved, ADDRINT lpClass, ADDRINT lpcchClass, ADDRINT lpftLastWriteTime);
};

#endif // INST_REG_ENUM_KEY_EX_W_H
