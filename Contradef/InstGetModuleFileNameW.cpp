#include "InstGetModuleFileNameW.h"

std::map<CallContextKey, CallContext*> InstGetModuleFileNameW::callContextMap;
UINT32 InstGetModuleFileNameW::imgCallId = 0;
UINT32 InstGetModuleFileNameW::fcnCallId = 0;
Notifier* InstGetModuleFileNameW::globalNotifierPtr;

VOID InstGetModuleFileNameW::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT hModule, ADDRINT lpFilename, ADDRINT nSize) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    GetModuleFileNameWArgs args;
    args.hModule = hModule;
    args.lpFilename = lpFilename;
    args.nSize = nSize;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros de GetModuleFileNameW e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
   
    stringStream << std::endl << "[+] GetModuleFileNameW..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        hModule: " << std::hex << hModule << std::dec << std::endl;
    stringStream << "        lpFilename (Endereço do Buffer): " << std::hex << lpFilename << std::dec << std::endl;
    stringStream << "        nSize (Tamanho do Buffer): " << nSize << " caracteres" << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da obtenção do caminho do módulo" << std::endl;

}

VOID InstGetModuleFileNameW::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal, ADDRINT lpFilename, ADDRINT nSize) {

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

        std::wstring wsFilename = ConvertAddrToWideString(lpFilename);
        stringStream << "    Caminho do Módulo Retornado: " << WStringToString(wsFilename) << std::endl;
        stringStream << "    Número de caracteres copiados: " << retVal << std::endl;
        stringStream << "  [-] Operação concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstGetModuleFileNameW::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    SEC sec = RTN_Sec(rtn);
    IMG img = SEC_Img(sec);
    if (IMG_Valid(img)) {
        std::string imageName = IMG_Name(img);
        std::string moduleName = ExtractModuleName(IMG_Name(img));
        if (toUpperCase(moduleName) != "KERNELBASE.DLL") {
            return;
        }
    }
    else {
        return;
    }

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetModuleFileNameW") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // hModule
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // lpFilename
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // nSize
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,           // Valor de retorno
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // lpFilename
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // nSize
            IARG_END);

        RTN_Close(rtn);
    }
}
