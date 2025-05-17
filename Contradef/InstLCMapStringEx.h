#pragma once
#ifndef INST_LC_MAP_STRING_EX_H
#define INST_LC_MAP_STRING_EX_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "utils.h"
#include "CallContext.h"
#include "Notifier.h"
#include "Observer.h"
#include "Instrumentation.h"
#include "InstrumentationStrategy.h"

// Estrutura para armazenar os argumentos da função LCMapStringEx
struct LCMapStringExArgs {
    ADDRINT lpLocaleName;           // LPCWSTR: Nome da localidade
    ADDRINT dwMapFlags;             // DWORD: Flags de mapeamento
    ADDRINT lpSrcStr;               // LPCWSTR: String de entrada
    ADDRINT cchSrc;                 // int: Número de caracteres na string de entrada
    ADDRINT lpDestStr;              // LPWSTR: String de saída
    ADDRINT cchDest;                // int: Tamanho do buffer de saída (em chars)
    ADDRINT lpVersionInformation;   // LPNLSVERSIONINFO: Info de versão opcional
    ADDRINT lpReserved;             // LPVOID: Reservado, deve ser NULL
    ADDRINT lParam;                 // LPARAM: Reservado, deve ser NULL
};

class InstLCMapStringEx : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, Notifier& globalNotifier);
    static VOID HandleInstructionEvent(const EventData* data, void* context);
    static VOID HandleTraceEvent(const EventData* data, void* context);

private:
    static std::map<CallContextKey, CallContext*> callContextMap;
    static UINT32 imgCallId;
    static UINT32 fcnCallId;
    static Notifier* globalNotifierPtr;

    static VOID CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT lpLocaleName, ADDRINT dwMapFlags, ADDRINT lpSrcStr, ADDRINT cchSrc,
        ADDRINT lpDestStr, ADDRINT cchDest, ADDRINT lpVersionInformation,
        ADDRINT lpReserved, ADDRINT lParam);
    static VOID CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT retValAddr, ADDRINT lpLocaleName, ADDRINT dwMapFlags, ADDRINT lpSrcStr, ADDRINT cchSrc,
        ADDRINT lpDestStr, ADDRINT cchDest, ADDRINT lpVersionInformation,
        ADDRINT lpReserved, ADDRINT lParam);
};

#endif // INST_LC_MAP_STRING_EX_H
