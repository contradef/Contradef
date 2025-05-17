#include "InstVirtualProtectEx.h"

std::map<CallContextKey, CallContext*> InstVirtualProtectEx::callContextMap;
UINT32 InstVirtualProtectEx::imgCallId = 0;
UINT32 InstVirtualProtectEx::fcnCallId = 0;
Notifier* InstVirtualProtectEx::globalNotifierPtr;


VOID InstVirtualProtectEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hProcess, ADDRINT lpAddress, ADDRINT dwSize, ADDRINT flNewProtect, ADDRINT lpflOldProtect) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstVirtualProtectExArgs args;
    args.hProcess = hProcess;
    args.lpAddress = lpAddress;
    args.dwSize = dwSize;
    args.flNewProtect = flNewProtect;
    args.lpflOldProtect = lpflOldProtect;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;
}

VOID InstVirtualProtectEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT hProcess, ADDRINT lpAddress, ADDRINT dwSize, ADDRINT flNewProtect, ADDRINT lpflOldProtect) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar função
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar parâmetros
        const InstVirtualProtectExArgs* args = reinterpret_cast<InstVirtualProtectExArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        // Obter a RTN da instrução atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parâmetros: " << std::endl;
        stringStream << "        hProcess: " << args->hProcess << std::endl;
        stringStream << "        lpAddress: " << args->lpAddress << std::endl;
        stringStream << "        dwSize: " << args->dwSize << std::endl;
        stringStream << "        flNewProtect: " << args->flNewProtect << std::endl;
        stringStream << "        lpflOldProtect: " << args->lpflOldProtect << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        // Cria evento
        ExecutionEventData executionEvent(executionCompletedInfo);
        // Notifica os observers
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstVirtualProtectEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "VirtualProtectEx") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hProcess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // flNewProtect
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpflOldProtect
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hProcess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // flNewProtect
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpflOldProtect
            IARG_END);

        RTN_Close(rtn);
    }
}
