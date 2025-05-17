#include "InstNtQuerySystemInformation.h"
#include "NtStructures.h"

std::map<CallContextKey, CallContext*> InstNtQuerySystemInformation::callContextMap;
UINT32 InstNtQuerySystemInformation::imgCallId = 0;
UINT32 InstNtQuerySystemInformation::fcnCallId = 0;
Notifier* InstNtQuerySystemInformation::globalNotifierPtr;

VOID InstNtQuerySystemInformation::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT SystemInformationClass, ADDRINT SystemInformation, ADDRINT SystemInformationLength, ADDRINT ReturnLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstNtQuerySystemInformationArgs args;
    args.SystemInformationClass = SystemInformationClass;
    args.SystemInformation = SystemInformation;
    args.SystemInformationLength = SystemInformationLength;
    args.ReturnLength = ReturnLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;
}

VOID InstNtQuerySystemInformation::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT SystemInformationClass, ADDRINT SystemInformation, ADDRINT SystemInformationLength, ADDRINT ReturnLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar função
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar parâmetros
        const InstNtQuerySystemInformationArgs* args = reinterpret_cast<InstNtQuerySystemInformationArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        // Obter a RTN da instrução atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parâmetros: " << std::endl;
        stringStream << "        SystemInformationClass: " << args->SystemInformationClass << std::endl; // -> SystemKernelDebuggerInformation do SYSTEM_INFORMATION_CLASS em NtStructures
        stringStream << "        SystemInformation: " << args->SystemInformation << std::endl;
        stringStream << "        SystemInformationLength: " << args->SystemInformationLength << std::endl;
        stringStream << "        ReturnLength: " << args->ReturnLength << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        // CONTRAMEDIDA
        if (args->SystemInformationClass == 5) {
            using namespace WindowsAPI;
            DWORD currentProcessId = GetCurrentProcessId();

            PSYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(args->SystemInformation);
            while (processInfo) {
                if (reinterpret_cast<DWORD>(processInfo->UniqueProcessId) == currentProcessId) {
                    stringStream << "  [-] Aplicando contramedida" << std::endl;

                    DWORD* parentProcessId = reinterpret_cast<DWORD*>(&(processInfo->Reserved2));
                    DWORD fakePID = GetProcessIdByName("explorer.exe");
                    stringStream << "    Substituindo o PID do processo pai (pin.exe - " << *parentProcessId << ") pelo do explorer.exe (" << fakePID << ")" << std::endl;
                    *parentProcessId = fakePID;
                    stringStream << "  [-] Contramedida aplicada" << std::endl;

                    break;
                }

                // Avançar para o próximo processo
                if (processInfo->NextEntryOffset == 0) {
                    break;
                }
                processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<BYTE*>(processInfo) + processInfo->NextEntryOffset
                    );
            }
        }
        /////

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

VOID InstNtQuerySystemInformation::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtQuerySystemInformation" || rtnName == "ZwQuerySystemInformation") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // SystemInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // SystemInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // SystemInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // ReturnLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // SystemInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // SystemInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // SystemInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // ReturnLength
            IARG_END);

        RTN_Close(rtn);
    }
}
