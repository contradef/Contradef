#include "InstVirtualAlloc.h"

std::map<CallContextKey, CallContext*> InstVirtualAlloc::callContextMap;
UINT32 InstVirtualAlloc::imgCallId = 0;
UINT32 InstVirtualAlloc::fcnCallId = 0;
Notifier* InstVirtualAlloc::globalNotifierPtr;

VOID InstVirtualAlloc::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpAddress, ADDRINT dwSize, ADDRINT flAllocationType, ADDRINT flProtect) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    VirtualAllocArgs args;
    args.lpAddress = lpAddress;
    args.dwSize = dwSize;
    args.flAllocationType = flAllocationType;
    args.flProtect = flProtect;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando parâmetros
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] VirtualAlloc..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        lpAddress: 0x" << std::hex << lpAddress << std::dec << std::endl;
    stringStream << "        dwSize: " << dwSize << " bytes" << std::endl;
    stringStream << "        flAllocationType: 0x" << std::hex << flAllocationType << std::dec << std::endl;
    stringStream << "        flProtect: 0x" << std::hex << flProtect << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada VirtualAlloc" << std::endl;

}

VOID InstVirtualAlloc::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retValAddr,
    ADDRINT lpAddress, ADDRINT dwSize, ADDRINT flAllocationType, ADDRINT flProtect) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        stringStream << "    Retorno VirtualAlloc: 0x" << std::hex << retValAddr << std::dec << std::endl;

        if (retValAddr != 0) {
            stringStream << "    Alocação de memória bem-sucedida." << std::endl;
        }
        else {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha na alocação de memória. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada VirtualAlloc concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstVirtualAlloc::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "VirtualAlloc") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // flAllocationType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // flProtect
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE, // Valor de retorno (endereço da memória alocada ou NULL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // flAllocationType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // flProtect
            IARG_END);

        RTN_Close(rtn);
    }
}
