#pragma once
#ifndef INST_RTL_QUERY_PERFORMANCE_COUNTER_H
#define INST_RTL_QUERY_PERFORMANCE_COUNTER_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"                             // Utilit�rios gerais
#include "CallContext.h"                      // Gerenciamento de contexto de chamadas
#include "Notifier.h"                         // Notifica��o para observadores
#include "Observer.h"                         // Observadores
#include "Instrumentation.h"                  // Interface de instrumenta��o
#include "InstrumentationStrategy.h"          // Estrat�gia de instrumenta��o

// Estrutura para armazenar os argumentos da fun��o RtlQueryPerformanceCounter
struct RtlQueryPerformanceCounterArgs {
    ADDRINT PerformanceCounter;     // PLARGE_INTEGER: Ponteiro para receber o valor do contador de desempenho
    ADDRINT PerformanceFrequency;   // PLARGE_INTEGER: Ponteiro opcional para receber a frequ�ncia do contador
};

// Classe respons�vel pela instrumenta��o da fun��o RtlQueryPerformanceCounter
class InstRtlQueryPerformanceCounter : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;

    // RtlQueryPerformanceCounter � uma fun��o VOID, portanto n�o h� valor de retorno significativo
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency);
};

#endif // INST_RTL_QUERY_PERFORMANCE_COUNTER_H
