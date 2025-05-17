#pragma once
#ifndef INST_GET_VOLUME_PATH_NAME_W_H
#define INST_GET_VOLUME_PATH_NAME_W_H

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

// Estrutura para armazenar os argumentos da fun��o GetVolumePathNameW
struct GetVolumePathNameWArgs {
    ADDRINT lpszFileName;        // LPCWSTR: Ponteiro para a string de entrada
    ADDRINT lpszVolumePathName;  // LPWSTR: Ponteiro para o buffer de sa�da
    ADDRINT cchBufferLength;     // DWORD: Tamanho do buffer de sa�da
};

// Classe respons�vel pela instrumenta��o da fun��o GetVolumePathNameW
class InstGetVolumePathNameW : public InstrumentationStrategy {
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
        ADDRINT lpszFileName, ADDRINT lpszVolumePathName, ADDRINT cchBufferLength);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT lpszFileName, ADDRINT lpszVolumePathName, ADDRINT cchBufferLength);
};

#endif // INST_GET_VOLUME_PATH_NAME_W_H
