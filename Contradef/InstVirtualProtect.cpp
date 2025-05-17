#include "InstVirtualProtect.h"
#include "NtStructures.h"

std::map<CallContextKey, CallContext*> InstVirtualProtect::callContextMap;
UINT32 InstVirtualProtect::imgCallId = 0;
UINT32 InstVirtualProtect::fcnCallId = 0;
Notifier* InstVirtualProtect::globalNotifierPtr;

VOID InstVirtualProtect::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT lpAddress, ADDRINT dwSize, ADDRINT flNewProtect, ADDRINT lpflOldProtect) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    VirtualProtectArgs args;
    args.lpAddress = lpAddress;
    args.dwSize = dwSize;
    args.flNewProtect = flNewProtect;
    args.lpflOldProtect = lpflOldProtect;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros de VirtualProtect e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] VirtualProtect..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        lpAddress: " << std::hex << lpAddress << std::dec << std::endl;
    stringStream << "        dwSize: " << dwSize << " bytes" << std::endl;
    stringStream << "        flNewProtect: " << flNewProtect << std::endl;
    stringStream << "        lpflOldProtect (Endereço): " << std::hex << lpflOldProtect << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Alteração de proteção de memória iniciada" << std::endl;

}

VOID InstVirtualProtect::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal, ADDRINT lpflOldProtect) {

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
        const VirtualProtectArgs* args = reinterpret_cast<const VirtualProtectArgs*>(callContext->functionArgs);

        DWORD oldProtect = 0;
        PIN_SafeCopy(&oldProtect, reinterpret_cast<DWORD*>(args->lpflOldProtect), sizeof(DWORD));

        ///// TESTE
        //DWORD* oProtect = reinterpret_cast<DWORD*>(args->lpflOldProtect);
        //if (args->dwSize == 137472) {
        //    *oProtect = 0x02;
        //}
        //else if (args->dwSize == 71574) {
        //    *oProtect = 0x02;
        //}
        //else if (args->dwSize == 10568) {
        //    *oProtect = 0x04;
        //}
        //else if (args->dwSize == 348) {
        //    *oProtect = 0x02;
        //}
        /////

        stringStream << "    Valor de retorno: " << returnAddress << std::endl;
        stringStream << "    Proteção antiga: " << oldProtect << std::endl;
        stringStream << "  [-] Alteração de proteção de memória concluída" << std::endl;
        stringStream << "[*] ConcluídO" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstVirtualProtect::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    
    //SEC sec = RTN_Sec(rtn);
    //IMG img = SEC_Img(sec);
    //if (IMG_Valid(img)) {
    //    std::string imageName = IMG_Name(img);
    //    std::string moduleName = ExtractModuleName(IMG_Name(img));
    //    if (toUpperCase(moduleName) != "KERNELBASE.DLL") {
    //        return;
    //    }
    //}
    //else {
    //    return;
    //}

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "VirtualProtect") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // dwSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // flNewProtect
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // lpflOldProtect
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,           // Valor de retorno
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // lpflOldProtect
            IARG_END);

        RTN_Close(rtn);
    }
}
