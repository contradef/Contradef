#include "InstVirtualFree.h"

std::map<CallContextKey, CallContext*> InstVirtualFree::callContextMap;
UINT32 InstVirtualFree::imgCallId = 0;
UINT32 InstVirtualFree::fcnCallId = 0;
Notifier* InstVirtualFree::globalNotifierPtr;

VOID InstVirtualFree::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpAddress, ADDRINT dwSize, ADDRINT dwFreeType) {
    PIN_LockClient();
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    VirtualFreeArgs args;
    args.lpAddress = lpAddress;
    args.dwSize = dwSize;
    args.dwFreeType = dwFreeType;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] VirtualFree..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        lpAddress: 0x" << std::hex << lpAddress << std::dec << std::endl;
    stringStream << "        dwSize: " << dwSize << " bytes" << std::endl;
    stringStream << "        dwFreeType: 0x" << std::hex << dwFreeType << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada VirtualFree" << std::endl;

}

VOID InstVirtualFree::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT lpAddress, ADDRINT dwSize, ADDRINT dwFreeType) {

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

        BOOL result = static_cast<BOOL>(retValAddr);
        stringStream << "    Retorno VirtualFree: " << result << std::endl;

        if (result != 0) {
            stringStream << "    Liberação de memória bem-sucedida." << std::endl;
        }
        else {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha na liberação de memória. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada VirtualFree concluída" << std::endl;
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

VOID InstVirtualFree::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "VirtualFree") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwFreeType
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwFreeType
            IARG_END);

        RTN_Close(rtn);
    }
}
