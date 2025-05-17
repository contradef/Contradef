#pragma once
#ifndef INST_QUERY_DOS_DEVICE_W_H
#define INST_QUERY_DOS_DEVICE_W_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"                     // Utilitários gerais
#include "CallContext.h"              // Gerenciamento de contexto de chamadas
#include "Notifier.h"                 // Notificação para observadores
#include "Observer.h"                 // Observadores
#include "Instrumentation.h"          // Interface de instrumentação
#include "InstrumentationStrategy.h"  // Estratégia de instrumentação

// Estrutura para armazenar os argumentos da função QueryDosDeviceW
struct QueryDosDeviceWArgs {
    ADDRINT lpDeviceName;
    ADDRINT lpTargetPath;
    ADDRINT ucchMax;
};

// Classe responsável pela instrumentação da função QueryDosDeviceW
class InstQueryDosDeviceW : public InstrumentationStrategy {
public:
    // Métodos públicos
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:
    // Mapa para armazenar o contexto das chamadas
    static std::map<CallContextKey, CallContext*> callContextMap;
    // Identificadores únicos para chamadas
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    // Ponteiro para o notificador global
    static Notifier* globalNotifierPtr;

    // Callbacks para antes e depois da chamada da função
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT lpDeviceName, ADDRINT lpTargetPath, ADDRINT ucchMax);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT lpDeviceName, ADDRINT lpTargetPath, ADDRINT ucchMax);
};

#endif // INST_QUERY_DOS_DEVICE_W_H
