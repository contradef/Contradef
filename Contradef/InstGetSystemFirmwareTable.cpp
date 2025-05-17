#include "InstGetSystemFirmwareTable.h"

// Inicializa��o das vari�veis est�ticas
std::map<CallContextKey, CallContext*> InstGetSystemFirmwareTable::callContextMap;
UINT32 InstGetSystemFirmwareTable::imgCallId = 0;
UINT32 InstGetSystemFirmwareTable::fcnCallId = 0;
Notifier* InstGetSystemFirmwareTable::globalNotifierPtr;

// Callback executado antes da chamada da fun��o GetSystemFirmwareTable
VOID InstGetSystemFirmwareTable::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT FirmwareTableProviderSignature, ADDRINT FirmwareTableID, ADDRINT pFirmwareTableBuffer, ADDRINT BufferSize) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Estrutura para armazenar os argumentos
    GetSystemFirmwareTableArgs args;
    args.FirmwareTableProviderSignature = FirmwareTableProviderSignature;
    args.FirmwareTableID = FirmwareTableID;
    args.pFirmwareTableBuffer = pFirmwareTableBuffer;
    args.BufferSize = BufferSize;

    // Cria��o de um ID �nico para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Cria��o e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Constru��o da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetSystemFirmwareTable..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endere�o da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Par�metros: " << std::endl;
    stringStream << "        FirmwareTableProviderSignature: 0x" << std::hex << FirmwareTableProviderSignature << std::dec << std::endl;
    stringStream << "        FirmwareTableID: 0x" << std::hex << FirmwareTableID << std::dec << std::endl;
    stringStream << "        pFirmwareTableBuffer: 0x" << std::hex << pFirmwareTableBuffer << std::dec << std::endl;
    stringStream << "        BufferSize: " << BufferSize << " bytes" << std::endl;
    stringStream << "    Endere�o da fun��o chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] In�cio da chamada GetSystemFirmwareTable" << std::endl;

}

// Callback executado ap�s a chamada da fun��o GetSystemFirmwareTable
VOID InstGetSystemFirmwareTable::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT FirmwareTableProviderSignature, ADDRINT FirmwareTableID, ADDRINT pFirmwareTableBuffer, ADDRINT BufferSize) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Cria��o do ID �nico para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };

    // Busca do contexto da chamada no mapa
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient(); // Prote��o para acesso seguro ao contexto

        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        // Convers�o do valor de retorno para DWORD
        DWORD bytesCopied = static_cast<DWORD>(retValAddr);
        stringStream << "    Retorno GetSystemFirmwareTable: " << bytesCopied << " bytes" << std::endl;

        if (bytesCopied != 0) {
            // Sucesso: tenta ler os dados retornados em pFirmwareTableBuffer
            if (pFirmwareTableBuffer != 0 && BufferSize > 0) {
                // Para evitar logs excessivos, limitamos a quantidade de bytes a serem exibidos
                DWORD bytesToDisplay = (BufferSize < 64) ? BufferSize : 64;
                std::vector<BYTE> firmwareTableData(bytesToDisplay);
                PIN_SafeCopy(firmwareTableData.begin(), reinterpret_cast<BYTE*>(pFirmwareTableBuffer), bytesToDisplay);

                stringStream << "    Dados do FirmwareTableBuffer (" << bytesToDisplay << " bytes): ";
                for (DWORD i = 0; i < bytesToDisplay; ++i) {
                    stringStream << std::hex << static_cast<int>(firmwareTableData[i]) << " ";
                }
                stringStream << std::dec << std::endl;
            }
            else {
                stringStream << "    pFirmwareTableBuffer � NULL ou BufferSize � inv�lido. N�o foi poss�vel ler os dados." << std::endl;
            }
            stringStream << "    Opera��o conclu�da com sucesso." << std::endl;
        }
        else {
            // Falha: obt�m o c�digo de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao obter a tabela de firmware. C�digo de erro: " << error << std::endl;
        }

        // Finaliza��o das mensagens de log
        stringStream << "  [-] Chamada GetSystemFirmwareTable conclu�da" << std::endl;
        stringStream << "[*] Conclu�do" << std::endl << std::endl;

        // Notifica��o aos observadores ap�s capturar o resultado
        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        // Limpeza: remove e deleta o contexto da chamada
        delete callContext;
        callContextMap.erase(it);

        PIN_UnlockClient(); // Desprotege o contexto
    }
}

// M�todo respons�vel por inserir os callbacks na fun��o GetSystemFirmwareTable
VOID InstGetSystemFirmwareTable::InstrumentFunction(RTN rtn, Notifier & globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetSystemFirmwareTable") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // DWORD GetSystemFirmwareTable(
        //   DWORD FirmwareTableProviderSignature,
        //   DWORD FirmwareTableID,
        //   PVOID pFirmwareTableBuffer,
        //   DWORD BufferSize
        // );

        // Inser��o do CallbackBefore antes da chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // FirmwareTableProviderSignature
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // FirmwareTableID
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // pFirmwareTableBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // BufferSize
            IARG_END);

        // Inser��o do CallbackAfter ap�s a chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (DWORD)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // FirmwareTableProviderSignature
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // FirmwareTableID
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // pFirmwareTableBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // BufferSize
            IARG_END);

        RTN_Close(rtn);
    }
}
