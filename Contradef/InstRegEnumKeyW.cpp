#include "InstRegEnumKeyW.h"

std::map<CallContextKey, CallContext*> InstRegEnumKeyW::callContextMap;
UINT32 InstRegEnumKeyW::imgCallId = 0;
UINT32 InstRegEnumKeyW::fcnCallId = 0;
Notifier* InstRegEnumKeyW::globalNotifierPtr;


VOID InstRegEnumKeyW::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT hKey, ADDRINT dwIndex, ADDRINT lpName, ADDRINT lpcName) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstRegEnumKeyWArgs args;
    args.hKey = hKey;
    args.dwIndex = dwIndex;
    args.lpName = lpName;
    args.lpcName = lpcName;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstRegEnumKeyW::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT hKey, ADDRINT dwIndex, ADDRINT lpName, ADDRINT lpcName) {

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
        const InstRegEnumKeyWArgs* args = reinterpret_cast<InstRegEnumKeyWArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        std::wstring wideStringLpName = ConvertAddrToWideString(args->lpName);
        std::string ansiStringLpName(wideStringLpName.begin(), wideStringLpName.end());

        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        hKey: " << args->hKey << std::endl;
        stringStream << "        dwIndex: " << args->dwIndex << std::endl;
        stringStream << "        lpName: " << ansiStringLpName << std::endl;
        stringStream << "        lpcName: " << args->lpcName << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        if (isRegistryKeyPartInList(ansiStringLpName)) {
            std::cout << "A chave de registro est� na lista." << std::endl;
            // Contramedida pode ser alterando o valor de retorno para algumas chaves
            //*retValAddr = 0;
            //alterar o valor de retorno
            //verificar a necessidade de chamar RegCloseKey para encerrar o handle
            //se poss�vel, alterar o valor da chave de registro antes da chamada, colocar uma chave que n�o existe
        }
        else {
            std::cout << "A chave de registro n�o est� na lista." << std::endl;
        }

        PIN_UnlockClient();
    }

    fcnCallId++;

}

VOID InstRegEnumKeyW::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (rtnName == "RegEnumKeyW") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hKey
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwIndex
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpcName
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hKey
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwIndex
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpcName
            IARG_END);

        RTN_Close(rtn);
    }
}
