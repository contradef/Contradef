#include "InstGetProcAddress.h"

std::map<CallContextKey, CallContext*> InstGetProcAddress::callContextMap;
UINT32 InstGetProcAddress::imgCallId = 0;
UINT32 InstGetProcAddress::fcnCallId = 0;
Notifier* InstGetProcAddress::globalNotifierPtr;

VOID InstGetProcAddress::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hModule, ADDRINT lpProcName) {
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        //return;
    }

    GetProcAddressArgs args;
    args.hModule = hModule;
    args.lpProcName = lpProcName;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetProcAddress..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        hModule: 0x" << std::hex << hModule << std::dec << std::endl;

    // Recuperar o nome da função (lpProcName)
    std::string procName;
    if (lpProcName != 0) {
        CHAR buffer[256] = { 0 };
        PIN_SafeCopy(buffer, reinterpret_cast<CHAR*>(lpProcName), sizeof(buffer) - 1);
        procName = buffer;
    }

    stringStream << "        lpProcName: 0x" << std::hex << lpProcName << std::dec << " (" << procName << ")" << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada GetProcAddress" << std::endl;

}

VOID InstGetProcAddress::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT hModule, ADDRINT lpProcName) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        //return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        {
            using namespace WindowsAPI;
            FARPROC result = reinterpret_cast<FARPROC>(retValAddr);
            stringStream << "    Retorno GetProcAddress: 0x" << std::hex << retValAddr << std::dec << std::endl;

            if (result != NULL) {
                stringStream << "    Função obtida com sucesso." << std::endl;
            }
            else {
                DWORD error = GetLastError();
                stringStream << "    Falha ao obter o endereço da função. Código de erro: " << error << std::endl;
            }
        }

        stringStream << "  [-] Chamada GetProcAddress concluída" << std::endl;
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

VOID InstGetProcAddress::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetProcAddress") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura de GetProcAddress:
        // FARPROC GetProcAddress(
        //   HMODULE hModule,
        //   LPCSTR  lpProcName
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hModule
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpProcName
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE, // Valor de retorno (FARPROC)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hModule
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpProcName
            IARG_END);

        RTN_Close(rtn);
    }
}
