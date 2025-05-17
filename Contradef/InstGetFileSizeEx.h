#pragma once
#ifndef INST_GET_FILE_SIZE_EX_H
#define INST_GET_FILE_SIZE_EX_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"                 // Utilit�rios gerais
#include "CallContext.h"          // Gerenciamento de contexto de chamadas
#include "Notifier.h"             // Notifica��o para observadores
#include "Observer.h"             // Observadores
#include "Instrumentation.h"      // Interface de instrumenta��o
#include "InstrumentationStrategy.h" // Estrat�gia de instrumenta��o

// Estrutura para armazenar os argumentos da fun��o GetFileSizeEx
struct GetFileSizeExArgs {
    ADDRINT hFile;
    ADDRINT lpFileSize;
};

// Classe respons�vel pela instrumenta��o da fun��o GetFileSizeEx
class InstGetFileSizeEx : public InstrumentationStrategy {
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
        ADDRINT hFile, ADDRINT lpFileSize);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT hFile, ADDRINT lpFileSize);
};

#endif // INST_GET_FILE_SIZE_EX_H
