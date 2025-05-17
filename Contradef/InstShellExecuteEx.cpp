#include "InstShellExecuteEx.h"

std::map<CallContextKey, CallContext*> InstShellExecuteEx::callContextMap;
UINT32 InstShellExecuteEx::imgCallId = 0;
UINT32 InstShellExecuteEx::fcnCallId = 0;
Notifier* InstShellExecuteEx::globalNotifierPtr;


VOID InstShellExecuteEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpExecInfo) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstShellExecuteExArgs args;
    args.lpExecInfo = lpExecInfo;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstShellExecuteEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT lpExecInfo) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar fun��o
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar Parámetros
        const InstShellExecuteExArgs* args = reinterpret_cast<InstShellExecuteExArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        SHELLEXECUTEINFO* execInfo = reinterpret_cast<SHELLEXECUTEINFO*>(args->lpExecInfo);

        std::string operation = execInfo->lpVerb ? ConvertAddrToAnsiString(reinterpret_cast<ADDRINT>(execInfo->lpVerb)) : "NULL";
        std::string file = execInfo->lpFile ? ConvertAddrToAnsiString(reinterpret_cast<ADDRINT>(execInfo->lpFile)) : "NULL";
        std::string parameters = execInfo->lpParameters ? ConvertAddrToAnsiString(reinterpret_cast<ADDRINT>(execInfo->lpParameters)) : "NULL";
        std::string directory = execInfo->lpDirectory ? ConvertAddrToAnsiString(reinterpret_cast<ADDRINT>(execInfo->lpDirectory)) : "NULL";

        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        hwnd: " << execInfo->hwnd << std::endl;
        stringStream << "        lpVerb: " << operation << std::endl;
        stringStream << "        lpFile: " << file << std::endl;
        stringStream << "        lpParameters: " << parameters << std::endl;
        stringStream << "        lpDirectory: " << directory << std::endl;
        stringStream << "        nShow: " << execInfo->nShow << std::endl;
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

VOID InstShellExecuteEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (RTN_Name(rtn) == "ShellExecuteExA" || RTN_Name(rtn) == "ShellExecuteExW") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpExecInfo
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpExecInfo
            IARG_END);

        RTN_Close(rtn);
    }
}
