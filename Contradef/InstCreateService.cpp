#include "InstCreateService.h"

std::map<CallContextKey, CallContext*> InstCreateService::callContextMap;
UINT32 InstCreateService::imgCallId = 0;
UINT32 InstCreateService::fcnCallId = 0;
Notifier* InstCreateService::globalNotifierPtr;


VOID InstCreateService::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hSCManager, ADDRINT lpServiceName, ADDRINT lpDisplayName, ADDRINT dwDesiredAccess,
    ADDRINT dwServiceType, ADDRINT dwStartType, ADDRINT dwErrorControl, ADDRINT lpBinaryPathName,
    ADDRINT lpLoadOrderGroup, ADDRINT lpdwTagId, ADDRINT lpDependencies, ADDRINT lpServiceStartName,
    ADDRINT lpPassword) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstCreateServiceArgs args;
    args.hSCManager = hSCManager;
    args.lpServiceName = lpServiceName;
    args.lpDisplayName = lpDisplayName;
    args.dwDesiredAccess = dwDesiredAccess;
    args.dwServiceType = dwServiceType;
    args.dwStartType = dwStartType;
    args.dwErrorControl = dwErrorControl;
    args.lpBinaryPathName = lpBinaryPathName;
    args.lpLoadOrderGroup = lpLoadOrderGroup;
    args.lpdwTagId = lpdwTagId;
    args.lpDependencies = lpDependencies;
    args.lpServiceStartName = lpServiceStartName;
    args.lpPassword = lpPassword;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstCreateService::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT hSCManager, ADDRINT lpServiceName, ADDRINT lpDisplayName, ADDRINT dwDesiredAccess,
    ADDRINT dwServiceType, ADDRINT dwStartType, ADDRINT dwErrorControl, ADDRINT lpBinaryPathName,
    ADDRINT lpLoadOrderGroup, ADDRINT lpdwTagId, ADDRINT lpDependencies, ADDRINT lpServiceStartName,
    ADDRINT lpPassword) {

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
        const InstCreateServiceArgs* args = reinterpret_cast<InstCreateServiceArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        std::string serviceName = args->lpServiceName ? ConvertAddrToAnsiString(args->lpServiceName) : "NULL";
        std::string displayName = args->lpDisplayName ? ConvertAddrToAnsiString(args->lpDisplayName) : "NULL";
        std::string binaryPathName = args->lpBinaryPathName ? ConvertAddrToAnsiString(args->lpBinaryPathName) : "NULL";
        std::string serviceStartName = args->lpServiceStartName ? ConvertAddrToAnsiString(args->lpServiceStartName) : "NULL";

        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        hSCManager: " << args->hSCManager << std::endl;
        stringStream << "        lpServiceName: " << serviceName << std::endl;
        stringStream << "        lpDisplayName: " << displayName << std::endl;
        stringStream << "        dwDesiredAccess: " << args->dwDesiredAccess << std::endl;
        stringStream << "        dwServiceType: " << args->dwServiceType << std::endl;
        stringStream << "        dwStartType: " << args->dwStartType << std::endl;
        stringStream << "        dwErrorControl: " << args->dwErrorControl << std::endl;
        stringStream << "        lpBinaryPathName: " << binaryPathName << std::endl;
        stringStream << "        lpLoadOrderGroup: " << args->lpLoadOrderGroup << std::endl;
        stringStream << "        lpdwTagId: " << args->lpdwTagId << std::endl;
        stringStream << "        lpDependencies: " << args->lpDependencies << std::endl;
        stringStream << "        lpServiceStartName: " << serviceStartName << std::endl;
        stringStream << "        lpPassword: " << args->lpPassword << std::endl;
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

VOID InstCreateService::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (rtnName == "CreateServiceA" || rtnName == "CreateServiceW") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hSCManager
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpServiceName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpDisplayName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // dwDesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // dwServiceType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // dwStartType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // dwErrorControl
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // lpBinaryPathName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 8, // lpLoadOrderGroup
            IARG_FUNCARG_ENTRYPOINT_VALUE, 9, // lpdwTagId
            IARG_FUNCARG_ENTRYPOINT_VALUE, 10, // lpDependencies
            IARG_FUNCARG_ENTRYPOINT_VALUE, 11, // lpServiceStartName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 12, // lpPassword
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hSCManager
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpServiceName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpDisplayName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // dwDesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // dwServiceType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // dwStartType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // dwErrorControl
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // lpBinaryPathName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 8, // lpLoadOrderGroup
            IARG_FUNCARG_ENTRYPOINT_VALUE, 9, // lpdwTagId
            IARG_FUNCARG_ENTRYPOINT_VALUE, 10, // lpDependencies
            IARG_FUNCARG_ENTRYPOINT_VALUE, 11, // lpServiceStartName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 12, // lpPassword
            IARG_END);

        RTN_Close(rtn);
    }
}
