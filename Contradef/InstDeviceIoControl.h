#pragma once
#ifndef INST_DEVICE_IO_CONTROL_H
#define INST_DEVICE_IO_CONTROL_H

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

// Estrutura para armazenar os argumentos da fun��o DeviceIoControl
struct DeviceIoControlArgs {
    ADDRINT hDevice;           // HANDLE: Identificador do dispositivo
    ADDRINT dwIoControlCode;   // DWORD: C�digo de controle de E/S
    ADDRINT lpInBuffer;        // LPVOID: Ponteiro para o buffer de entrada
    ADDRINT nInBufferSize;     // DWORD: Tamanho do buffer de entrada
    ADDRINT lpOutBuffer;       // LPVOID: Ponteiro para o buffer de sa�da
    ADDRINT nOutBufferSize;    // DWORD: Tamanho do buffer de sa�da
    ADDRINT lpBytesReturned;   // LPDWORD: Ponteiro para o n�mero de bytes retornados
    ADDRINT lpOverlapped;      // LPOVERLAPPED: Ponteiro para a estrutura OVERLAPPED
};

// Classe respons�vel pela instrumenta��o da fun��o DeviceIoControl
class InstDeviceIoControl : public InstrumentationStrategy {
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
        ADDRINT hDevice, ADDRINT dwIoControlCode, ADDRINT lpInBuffer, ADDRINT nInBufferSize,
        ADDRINT lpOutBuffer, ADDRINT nOutBufferSize, ADDRINT lpBytesReturned, ADDRINT lpOverlapped);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT hDevice, ADDRINT dwIoControlCode, ADDRINT lpInBuffer, ADDRINT nInBufferSize,
        ADDRINT lpOutBuffer, ADDRINT nOutBufferSize, ADDRINT lpBytesReturned, ADDRINT lpOverlapped);
};

#endif // INST_DEVICE_IO_CONTROL_H
