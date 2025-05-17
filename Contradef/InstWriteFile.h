#pragma once
#ifndef INST_WRITE_FILE_H
#define INST_WRITE_FILE_H

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

// Estrutura para armazenar os argumentos da função WriteFile
struct WriteFileArgs {
    ADDRINT hFile;             // HANDLE
    ADDRINT lpBuffer;          // LPCVOID
    ADDRINT nNumberOfBytesToWrite; // DWORD
    ADDRINT lpNumberOfBytesWritten; // LPDWORD
    ADDRINT lpOverlapped;      // LPOVERLAPPED
};

class InstWriteFile : public InstrumentationStrategy {
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
        ADDRINT hFile, ADDRINT lpBuffer, ADDRINT nNumberOfBytesToWrite, ADDRINT lpNumberOfBytesWritten, ADDRINT lpOverlapped);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT hFile, ADDRINT lpBuffer, ADDRINT nNumberOfBytesToWrite, ADDRINT lpNumberOfBytesWritten, ADDRINT lpOverlapped);
};

#endif // INST_WRITE_FILE_H
