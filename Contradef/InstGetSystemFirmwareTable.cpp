#include "InstGetSystemFirmwareTable.h"

// Inicialização das variáveis estáticas
std::map<CallContextKey, CallContext*> InstGetSystemFirmwareTable::callContextMap;
UINT32 InstGetSystemFirmwareTable::imgCallId = 0;
UINT32 InstGetSystemFirmwareTable::fcnCallId = 0;
Notifier* InstGetSystemFirmwareTable::globalNotifierPtr;

// Callback executado antes da chamada da função GetSystemFirmwareTable
VOID InstGetSystemFirmwareTable::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT FirmwareTableProviderSignature, ADDRINT FirmwareTableID, ADDRINT pFirmwareTableBuffer, ADDRINT BufferSize) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Estrutura para armazenar os argumentos
    GetSystemFirmwareTableArgs args;
    args.FirmwareTableProviderSignature = FirmwareTableProviderSignature;
    args.FirmwareTableID = FirmwareTableID;
    args.pFirmwareTableBuffer = pFirmwareTableBuffer;
    args.BufferSize = BufferSize;

    // Criação de um ID único para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Criação e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Construção da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetSystemFirmwareTable..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        FirmwareTableProviderSignature: 0x" << std::hex << FirmwareTableProviderSignature << std::dec << std::endl;
    stringStream << "        FirmwareTableID: 0x" << std::hex << FirmwareTableID << std::dec << std::endl;
    stringStream << "        pFirmwareTableBuffer: 0x" << std::hex << pFirmwareTableBuffer << std::dec << std::endl;
    stringStream << "        BufferSize: " << BufferSize << " bytes" << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada GetSystemFirmwareTable" << std::endl;

}

// Callback executado após a chamada da função GetSystemFirmwareTable
VOID InstGetSystemFirmwareTable::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT FirmwareTableProviderSignature, ADDRINT FirmwareTableID, ADDRINT pFirmwareTableBuffer, ADDRINT BufferSize) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Criação do ID único para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };

    // Busca do contexto da chamada no mapa
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient(); // Proteção para acesso seguro ao contexto

        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        // Conversão do valor de retorno para DWORD
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
                stringStream << "    pFirmwareTableBuffer é NULL ou BufferSize é inválido. Não foi possível ler os dados." << std::endl;
            }
            stringStream << "    Operação concluída com sucesso." << std::endl;
        }
        else {
            // Falha: obtém o código de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao obter a tabela de firmware. Código de erro: " << error << std::endl;
        }

        // Finalização das mensagens de log
        stringStream << "  [-] Chamada GetSystemFirmwareTable concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        // Notificação aos observadores após capturar o resultado
        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        // Limpeza: remove e deleta o contexto da chamada
        delete callContext;
        callContextMap.erase(it);

        PIN_UnlockClient(); // Desprotege o contexto
    }
}

// Método responsável por inserir os callbacks na função GetSystemFirmwareTable
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

        // Inserção do CallbackBefore antes da chamada da função
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

        // Inserção do CallbackAfter após a chamada da função
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
