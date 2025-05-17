#pragma once
#ifndef INST_DEVICE_IO_CONTROL_H
#define INST_DEVICE_IO_CONTROL_H

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

// Estrutura para armazenar os argumentos da função DeviceIoControl
struct DeviceIoControlArgs {
    ADDRINT hDevice;           // HANDLE: Identificador do dispositivo
    ADDRINT dwIoControlCode;   // DWORD: Código de controle de E/S
    ADDRINT lpInBuffer;        // LPVOID: Ponteiro para o buffer de entrada
    ADDRINT nInBufferSize;     // DWORD: Tamanho do buffer de entrada
    ADDRINT lpOutBuffer;       // LPVOID: Ponteiro para o buffer de saída
    ADDRINT nOutBufferSize;    // DWORD: Tamanho do buffer de saída
    ADDRINT lpBytesReturned;   // LPDWORD: Ponteiro para o número de bytes retornados
    ADDRINT lpOverlapped;      // LPOVERLAPPED: Ponteiro para a estrutura OVERLAPPED
};

// Classe responsável pela instrumentação da função DeviceIoControl
class InstDeviceIoControl : public InstrumentationStrategy {
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
        ADDRINT hDevice, ADDRINT dwIoControlCode, ADDRINT lpInBuffer, ADDRINT nInBufferSize,
        ADDRINT lpOutBuffer, ADDRINT nOutBufferSize, ADDRINT lpBytesReturned, ADDRINT lpOverlapped);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT hDevice, ADDRINT dwIoControlCode, ADDRINT lpInBuffer, ADDRINT nInBufferSize,
        ADDRINT lpOutBuffer, ADDRINT nOutBufferSize, ADDRINT lpBytesReturned, ADDRINT lpOverlapped);
};

#endif // INST_DEVICE_IO_CONTROL_H
