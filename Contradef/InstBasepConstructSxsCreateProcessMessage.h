#pragma once
#ifndef INST_BASEP_CONSTRUCT_SXS_CREATE_PROCESS_MESSAGE_H
#define INST_BASEP_CONSTRUCT_SXS_CREATE_PROCESS_MESSAGE_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"                           // Utilit�rios gerais
#include "CallContext.h"                    // Gerenciamento de contexto de chamadas
#include "Notifier.h"                       // Notifica��o para observadores
#include "Observer.h"                       // Observadores
#include "Instrumentation.h"                // Interface de instrumenta��o
#include "InstrumentationStrategy.h"        // Estrat�gia de instrumenta��o

// Estrutura para armazenar os argumentos da fun��o BasepConstructSxsCreateProcessMessage
struct BasepConstructSxsCreateProcessMessageArgs {
    ADDRINT param1; // Substitua com o tipo e nome reais
    ADDRINT param2; // Substitua com o tipo e nome reais
    ADDRINT param3; // Substitua com o tipo e nome reais
    // Adicione mais par�metros conforme necess�rio
};

// Classe respons�vel pela instrumenta��o da fun��o BasepConstructSxsCreateProcessMessage
class InstBasepConstructSxsCreateProcessMessage : public InstrumentationStrategy {
public:
    // M�todos p�blicos
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:
    // Mapa para armazenar o contexto das chamadas
    static std::map<CallContextKey, CallContext*> callContextMap;
    // Identificadores �nicos para chamadas
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    // Ponteiro para o notificador global
    static Notifier* globalNotifierPtr;

    // Callbacks para antes e depois da chamada da fun��o
    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT param1, ADDRINT param2, ADDRINT param3);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT param1, ADDRINT param2, ADDRINT param3);
};

#endif // INST_BASEP_CONSTRUCT_SXS_CREATE_PROCESS_MESSAGE_H
