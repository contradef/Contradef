#pragma once
#ifndef INST_GET_COMPUTER_NAME_A_H
#define INST_GET_COMPUTER_NAME_A_H

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

// Estrutura para armazenar os argumentos da função GetComputerNameA
struct GetComputerNameAArgs {
    ADDRINT lpBuffer;   // LPSTR: ponteiro para o buffer do nome do computador
    ADDRINT nSize;      // LPDWORD: ponteiro para o tamanho do buffer
};

class InstGetComputerNameA : public InstrumentationStrategy {
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
        ADDRINT lpBuffer, ADDRINT nSize);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT lpBuffer, ADDRINT nSize);
};

#endif // INST_GET_COMPUTER_NAME_A_H
