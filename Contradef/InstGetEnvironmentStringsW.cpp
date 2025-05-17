#include "InstGetEnvironmentStringsW.h"

std::map<CallContextKey, CallContext*> InstGetEnvironmentStringsW::callContextMap;
UINT32 InstGetEnvironmentStringsW::imgCallId = 0;
UINT32 InstGetEnvironmentStringsW::fcnCallId = 0;
Notifier* InstGetEnvironmentStringsW::globalNotifierPtr;

VOID InstGetEnvironmentStringsW::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, nullptr);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetEnvironmentStringsW..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada GetEnvironmentStringsW" << std::endl;

}

VOID InstGetEnvironmentStringsW::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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

        if (retVal != 0) {
            using namespace WindowsAPI;
            // Converte o bloco de strings de ambiente para uma representação legível
            LPWSTR envStrings = reinterpret_cast<LPWSTR>(retVal);
            std::wstring allEnvStrings;
            LPWSTR current = envStrings;

            while (*current) {
                std::wstring envVar(current);
                allEnvStrings += envVar + L"\n";
                current += envVar.length() + 1;
            }

            // Converter std::wstring para std::string (considerando possível perda de informação)
            std::string envStringsStr(allEnvStrings.begin(), allEnvStrings.end());

            stringStream << "    Strings de ambiente obtidas com sucesso." << std::endl;
            stringStream << "    Ambiente:" << std::endl << envStringsStr << std::endl;
        }
        else {
            stringStream << "    Falha ao obter as strings de ambiente." << std::endl;
        }

        stringStream << "  [-] Chamada GetEnvironmentStringsW concluída" << std::endl;
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

VOID InstGetEnvironmentStringsW::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetEnvironmentStringsW") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno
            IARG_END);

        RTN_Close(rtn);
    }
}
