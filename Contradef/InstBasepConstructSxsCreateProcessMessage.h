#pragma once
#ifndef INST_BASEP_CONSTRUCT_SXS_CREATE_PROCESS_MESSAGE_H
#define INST_BASEP_CONSTRUCT_SXS_CREATE_PROCESS_MESSAGE_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"                           // Utilitários gerais
#include "CallContext.h"                    // Gerenciamento de contexto de chamadas
#include "Notifier.h"                       // Notificação para observadores
#include "Observer.h"                       // Observadores
#include "Instrumentation.h"                // Interface de instrumentação
#include "InstrumentationStrategy.h"        // Estratégia de instrumentação

// Estrutura para armazenar os argumentos da função BasepConstructSxsCreateProcessMessage
struct BasepConstructSxsCreateProcessMessageArgs {
    ADDRINT param1; // Substitua com o tipo e nome reais
    ADDRINT param2; // Substitua com o tipo e nome reais
    ADDRINT param3; // Substitua com o tipo e nome reais
    // Adicione mais parâmetros conforme necessário
};

// Classe responsável pela instrumentação da função BasepConstructSxsCreateProcessMessage
class InstBasepConstructSxsCreateProcessMessage : public InstrumentationStrategy {
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
        ADDRINT param1, ADDRINT param2, ADDRINT param3);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT param1, ADDRINT param2, ADDRINT param3);
};

#endif // INST_BASEP_CONSTRUCT_SXS_CREATE_PROCESS_MESSAGE_H
