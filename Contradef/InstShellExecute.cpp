#include "InstShellExecute.h"

std::map<CallContextKey, CallContext*> InstShellExecute::callContextMap;
UINT32 InstShellExecute::imgCallId = 0;
UINT32 InstShellExecute::fcnCallId = 0;
Notifier* InstShellExecute::globalNotifierPtr;


VOID InstShellExecute::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hwnd, ADDRINT lpOperation, ADDRINT lpFile, ADDRINT lpParameters, ADDRINT lpDirectory, ADDRINT nShowCmd) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstShellExecuteArgs args;
    args.hwnd = hwnd;
    args.lpOperation = lpOperation;
    args.lpFile = lpFile;
    args.lpParameters = lpParameters;
    args.lpDirectory = lpDirectory;
    args.nShowCmd = nShowCmd;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstShellExecute::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT hwnd, ADDRINT lpOperation, ADDRINT lpFile, ADDRINT lpParameters, ADDRINT lpDirectory, ADDRINT nShowCmd) {

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
        const InstShellExecuteArgs* args = reinterpret_cast<InstShellExecuteArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        std::string operation = args->lpOperation ? ConvertAddrToAnsiString(args->lpOperation) : "NULL";
        std::string file = args->lpFile ? ConvertAddrToAnsiString(args->lpFile) : "NULL";
        std::string parameters = args->lpParameters ? ConvertAddrToAnsiString(args->lpParameters) : "NULL";
        std::string directory = args->lpDirectory ? ConvertAddrToAnsiString(args->lpDirectory) : "NULL";

        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        hwnd: " << args->hwnd << std::endl;
        stringStream << "        lpOperation: " << operation << std::endl;
        stringStream << "        lpFile: " << file << std::endl;
        stringStream << "        lpParameters: " << parameters << std::endl;
        stringStream << "        lpDirectory: " << directory << std::endl;
        stringStream << "        nShowCmd: " << args->nShowCmd << std::endl;
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

VOID InstShellExecute::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (RTN_Name(rtn) == "ShellExecuteA" || RTN_Name(rtn) == "ShellExecuteW") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hwnd
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpOperation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpParameters
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpDirectory
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // nShowCmd
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hwnd
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpOperation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpParameters
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpDirectory
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // nShowCmd
            IARG_END);

        RTN_Close(rtn);
    }
}
