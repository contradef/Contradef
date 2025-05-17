#include "InstCreateFileW.h"

std::map<CallContextKey, CallContext*> InstCreateFileW::callContextMap;
UINT32 InstCreateFileW::imgCallId = 0;
UINT32 InstCreateFileW::fcnCallId = 0;
Notifier* InstCreateFileW::globalNotifierPtr;

VOID InstCreateFileW::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT lpFileName, ADDRINT dwDesiredAccess, ADDRINT dwShareMode, ADDRINT lpSecurityAttributes, ADDRINT dwCreationDisposition, ADDRINT dwFlagsAndAttributes, ADDRINT hTemplateFile) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    CreateFileWArgs* args = new CreateFileWArgs;
    args->lpFileName = ConvertAddrToWideStringSafe(lpFileName);
    args->dwDesiredAccess = dwDesiredAccess;
    args->dwShareMode = dwShareMode;
    args->lpSecurityAttributes = lpSecurityAttributes;
    args->dwCreationDisposition = dwCreationDisposition;
    args->dwFlagsAndAttributes = dwFlagsAndAttributes;
    args->hTemplateFile = hTemplateFile;
    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto* callContext = new CallContext(callCtxId, tid, instAddress, args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os par�metros de CreateFileW e o endere�o da fun��o chamante
    std::stringstream& stringStream = callContext->stringStream;
    std::wstring wsFileName = ConvertAddrToWideString(lpFileName);
    stringStream << std::endl << "[+] CreateFileW..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereçoo da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        lpFileName: " << WStringToString(wsFileName) << std::endl;
    stringStream << "        dwDesiredAccess: " << dwDesiredAccess << std::endl;
    stringStream << "        dwShareMode: " << dwShareMode << std::endl;
    stringStream << "        dwCreationDisposition: " << dwCreationDisposition << std::endl;
    stringStream << "        dwFlagsAndAttributes: " << dwFlagsAndAttributes << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início do acesso ao arquivo" << std::endl;

}

VOID InstCreateFileW::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT lpFileName) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }


    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* callContext = it->second;
        const CreateFileWArgs* args = reinterpret_cast<CreateFileWArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        stringStream << "    Handle retornado: " << std::hex << *retValAddr << std::dec << std::endl;
        stringStream << "  [-] Acesso ao arquivo conclu�do" << std::endl;
        stringStream << "[*] Conclu�do" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        // CONTRAMEDIDA
        if (args->lpFileName == L"\\\\.\\TitanHide") {
            if (retValAddr != nullptr) {
                HANDLE* returnValue = reinterpret_cast<HANDLE*>(retValAddr);
                if (*returnValue != INVALID_HANDLE_VALUE) {
                    std::cout << "[CONTRADEF] Aplicando Contramedida TitanHideDetect\n";
                    *returnValue = INVALID_HANDLE_VALUE; // INVALID_HANDLE_VALUE -> -1
                }
            }
        }

        delete reinterpret_cast<CreateFileWArgs*>(callContext->functionArgs);
        delete callContext;
        PIN_UnlockClient();
    }



    fcnCallId++;
}

VOID InstCreateFileW::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

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
    if (rtnName == "CreateFileW") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endere�o da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // lpFileName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // dwDesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // dwShareMode
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // lpSecurityAttributes
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,      // dwCreationDisposition
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,      // dwFlagsAndAttributes
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6,      // hTemplateFile
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,           // Handle retornado
            IARG_RETURN_IP,                        // Endere�o da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // lpFileName
            IARG_END);

        RTN_Close(rtn);
    }
}
