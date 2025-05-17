#pragma once
#ifndef INST_GET_COMMAND_LINE_W_H
#define INST_GET_COMMAND_LINE_W_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"                             // Utilitários gerais
#include "CallContext.h"                      // Gerenciamento de contexto de chamadas
#include "Notifier.h"                         // Notificação para observadores
#include "Observer.h"                         // Observadores
#include "Instrumentation.h"                  // Interface de instrumentação
#include "InstrumentationStrategy.h"          // Estratégia de instrumentação

// Não há argumentos para GetCommandLineW, então não precisamos de uma estrutura de argumentos

class InstGetCommandLineW : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;

    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retValAddr);
};

#endif // INST_GET_COMMAND_LINE_W_H
