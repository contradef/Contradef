#pragma once
#ifndef INST_ENUM_SYSTEM_FIRMWARE_TABLES_H
#define INST_ENUM_SYSTEM_FIRMWARE_TABLES_H

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

// Estrutura com os parâmetros de EnumSystemFirmwareTables
struct EnumSystemFirmwareTablesArgs {
    ADDRINT FirmwareTableProviderSignature;   // DWORD
    ADDRINT pFirmwareTableEnumBuffer;         // PVOID
    ADDRINT BufferSize;                       // DWORD
};

class InstEnumSystemFirmwareTables : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData*, void*) {}
    static VOID HandleTraceEvent(const EventData*, void*) {}

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;

    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT*,
        ADDRINT returnAddress,
        ADDRINT FirmwareTableProviderSignature,
        ADDRINT pFirmwareTableEnumBuffer,
        ADDRINT BufferSize);

    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT*,
        ADDRINT returnAddress,
        ADDRINT retValAddr,
        ADDRINT FirmwareTableProviderSignature,
        ADDRINT pFirmwareTableEnumBuffer,
        ADDRINT BufferSize);
};

#endif // INST_ENUM_SYSTEM_FIRMWARE_TABLES_H
