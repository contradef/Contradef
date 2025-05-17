#include "InstGetEnvironmentVariableA.h"

std::map<CallContextKey, CallContext*> InstGetEnvironmentVariableA::callContextMap;
UINT32 InstGetEnvironmentVariableA::imgCallId = 0;
UINT32 InstGetEnvironmentVariableA::fcnCallId = 0;
Notifier* InstGetEnvironmentVariableA::globalNotifierPtr;

VOID InstGetEnvironmentVariableA::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpName, ADDRINT lpBuffer, ADDRINT nSize) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    GetEnvironmentVariableAArgs args;
    args.lpName = lpName;
    args.lpBuffer = lpBuffer;
    args.nSize = static_cast<DWORD>(nSize);

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;

    stringStream << std::endl << "[+] GetEnvironmentVariableA..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;

    // Recuperar o nome da variável de ambiente
    std::string envVarName;
    if (lpName != 0) {
        CHAR buffer[4096] = { 0 };
        PIN_SafeCopy(buffer, reinterpret_cast<CHAR*>(lpName), sizeof(buffer) - 1);
        envVarName = buffer;
    }

    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        lpName: " << std::hex << lpName << std::dec << " (" << envVarName << ")" << std::endl;
    stringStream << "        lpBuffer: " << std::hex << lpBuffer << std::dec << std::endl;
    stringStream << "        nSize: " << args.nSize << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada GetEnvironmentVariableA" << std::endl;

}

VOID InstGetEnvironmentVariableA::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal,
    ADDRINT lpBuffer, ADDRINT nSize) {

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

        DWORD result = static_cast<DWORD>(retVal);
        stringStream << "    Valor de retorno: " << result << std::endl;

        if (result > 0 && lpBuffer != 0) {
            // Recuperar o valor da variável de ambiente
            size_t bufferSize = result * sizeof(CHAR);
            CHAR* buffer = new CHAR[result + 1];
            memset(buffer, 0, result + 1);
            PIN_SafeCopy(buffer, reinterpret_cast<CHAR*>(lpBuffer), bufferSize);
            std::string envVarValue(buffer);
            delete[] buffer;

            stringStream << "    Valor da variável de ambiente: " << envVarValue << std::endl;
        }
        else if (result == 0) {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao obter a variável de ambiente. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada GetEnvironmentVariableA concluída" << std::endl;
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

VOID InstGetEnvironmentVariableA::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetEnvironmentVariableA") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // lpName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // nSize
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // nSize
            IARG_END);

        RTN_Close(rtn);
    }
}
