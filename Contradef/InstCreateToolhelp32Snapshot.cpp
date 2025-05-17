#include "InstCreateToolhelp32Snapshot.h"

std::map<CallContextKey, CallContext*> InstCreateToolhelp32Snapshot::callContextMap;
UINT32 InstCreateToolhelp32Snapshot::imgCallId = 0;
UINT32 InstCreateToolhelp32Snapshot::fcnCallId = 0;
Notifier* InstCreateToolhelp32Snapshot::globalNotifierPtr;

VOID InstCreateToolhelp32Snapshot::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT dwFlags, ADDRINT th32ProcessID) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    CreateToolhelp32SnapshotArgs args;
    args.dwFlags = dwFlags;
    args.th32ProcessID = th32ProcessID;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] CreateToolhelp32Snapshot..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        dwFlags: 0x" << std::hex << dwFlags << std::dec << std::endl;
    stringStream << "        th32ProcessID: " << th32ProcessID << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada CreateToolhelp32Snapshot" << std::endl;

}

VOID InstCreateToolhelp32Snapshot::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT dwFlags, ADDRINT th32ProcessID) {

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

        HANDLE result = reinterpret_cast<HANDLE>(retValAddr);
        stringStream << "    Retorno CreateToolhelp32Snapshot: 0x" << std::hex << retValAddr << std::dec << std::endl;

        if (result != INVALID_HANDLE_VALUE) {
            stringStream << "    Snapshot criado com sucesso." << std::endl;
        }
        else {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao criar o snapshot. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada CreateToolhelp32Snapshot concluída" << std::endl;
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

VOID InstCreateToolhelp32Snapshot::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "CreateToolhelp32Snapshot") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // HANDLE CreateToolhelp32Snapshot(
        //   DWORD dwFlags,
        //   DWORD th32ProcessID
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dwFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // th32ProcessID
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (HANDLE)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dwFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // th32ProcessID
            IARG_END);

        RTN_Close(rtn);
    }
}
