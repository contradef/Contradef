#include "InstNtOpenKey.h"

std::map<CallContextKey, CallContext*> InstNtOpenKey::callContextMap;
UINT32 InstNtOpenKey::imgCallId = 0;
UINT32 InstNtOpenKey::fcnCallId = 0;
Notifier* InstNtOpenKey::globalNotifierPtr;

static std::string strc = "";
VOID InstNtOpenKey::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT KeyHandle, ADDRINT DesiredAccess, ADDRINT ObjectAttributes) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    NtOpenKeyArgs args;
    args.KeyHandle = KeyHandle;
    args.DesiredAccess = DesiredAccess;
    args.ObjectAttributes = ObjectAttributes;

    // Acessando a estrutura OBJECT_ATTRIBUTES
    OBJECT_ATTRIBUTES* objAttr = reinterpret_cast<OBJECT_ATTRIBUTES*>(ObjectAttributes);
    if (objAttr != nullptr && objAttr->ObjectName != nullptr) {
        UNICODE_STRING* unicodeStr = objAttr->ObjectName;
        std::wstring keyPath(unicodeStr->Buffer, unicodeStr->Length / sizeof(WCHAR));
        args.keyPathStr = std::string(WStringToString(keyPath));
        strc = std::string(WStringToString(keyPath));
    }
    else {
        args.keyPathStr = "";
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstNtOpenKey::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT KeyHandle, ADDRINT DesiredAccess, ADDRINT ObjectAttributes) {
    
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar fun�ao
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar Parámetros
        const NtOpenKeyArgs* args = reinterpret_cast<NtOpenKeyArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        KeyHandle: " << args->KeyHandle << std::endl;
        // Verificar erro de memoria e usar args->keyPathStr
        stringStream << "        keyPath: " << strc << std::endl; // args->keyPathStr << std::endl;
        stringStream << "        DesiredAccess: " << args->DesiredAccess << std::endl;
        stringStream << "        ObjectAttributes: " << args->ObjectAttributes << std::endl;
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

VOID InstNtOpenKey::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    
   std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtOpenKey" || rtnName == "ZwOpenKey") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(CallbackBefore),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // KeyHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // DesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ObjectAttributes
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // KeyHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // DesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ObjectAttributes
            IARG_END);
        RTN_Close(rtn);
    }

}