#include "InstLoadLibraryEx.h"

std::map<CallContextKey, CallContext*> InstLoadLibraryEx::callContextMap;
UINT32 InstLoadLibraryEx::imgCallId = 0;
UINT32 InstLoadLibraryEx::fcnCallId = 0;
Notifier* InstLoadLibraryEx::globalNotifierPtr;
BOOL InstLoadLibraryEx::wideVersion = false;

VOID InstLoadLibraryEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpLibFileName, ADDRINT hFile, ADDRINT dwFlags) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstLoadLibraryExArgs args;
    args.lpLibFileName = lpLibFileName;
    args.hFile = hFile;
    args.dwFlags = dwFlags;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstLoadLibraryEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT lpLibFileName, ADDRINT hFile, ADDRINT dwFlags) {

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
        const InstLoadLibraryExArgs* args = reinterpret_cast<InstLoadLibraryExArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        std::string libFileName;
        if (wideVersion) {
            std::wstring libFileNameW;
            libFileNameW = args->lpLibFileName ? ConvertAddrToWideString(args->lpLibFileName) : L"NULL";
            libFileName = WStringToString(libFileNameW);
        }
        else {
            libFileName = args->lpLibFileName ? ConvertAddrToAnsiString(args->lpLibFileName) : "NULL";
        }
        
        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        lpLibFileName: " << libFileName << std::endl;
        stringStream << "        hFile: " << args->hFile << std::endl;
        stringStream << "        dwFlags: " << args->dwFlags << std::endl;
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

VOID InstLoadLibraryEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (rtnName == "LoadLibraryEx" || rtnName == "LoadLibraryExA" || rtnName == "LoadLibraryExW") {
        if (rtnName == "LoadLibraryExW") {
            wideVersion = true;
        }

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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpLibFileName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // hFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwFlags
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpLibFileName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // hFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwFlags
            IARG_END);

        RTN_Close(rtn);
    }
}
