#pragma once
#ifndef INST_RTL_QUERY_PERFORMANCE_COUNTER_H
#define INST_RTL_QUERY_PERFORMANCE_COUNTER_H

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

// Estrutura para armazenar os argumentos da função RtlQueryPerformanceCounter
struct RtlQueryPerformanceCounterArgs {
    ADDRINT PerformanceCounter;     // PLARGE_INTEGER: Ponteiro para receber o valor do contador de desempenho
    ADDRINT PerformanceFrequency;   // PLARGE_INTEGER: Ponteiro opcional para receber a frequência do contador
};

// Classe responsável pela instrumentação da função RtlQueryPerformanceCounter
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

    // RtlQueryPerformanceCounter é uma função VOID, portanto não há valor de retorno significativo
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency);
};

#endif // INST_RTL_QUERY_PERFORMANCE_COUNTER_H
