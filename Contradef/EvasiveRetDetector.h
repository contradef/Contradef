#pragma once
#ifndef EVASIVE_RET_DETECTOR_H
#define EVASIVE_RET_DETECTOR_H

#include "pin.H"
#include <map>
#include <deque>
#include <iostream>

namespace EvasiveRetDetector {
    /**
     * Estrutura que guarda informa��es sobre a escrita na pilha:
     * - value: endere�o que foi escrito (p. ex., endere�o de API)
     * - mov_ins: endere�o da instru��o MOV respons�vel por escrever esse valor
     */
    struct StackWriteInfo {
        ADDRINT value;
        ADDRINT mov_ins;
    };

    // Mapeia endere�o de mem�ria (na pilha) -> informa��es sobre escrita suspeita
    extern std::map<ADDRINT, StackWriteInfo> suspicious_stack;

    /**
     * Usamos um deque para armazenar as �ltimas instru��es POP e o valor desempilhado.
     * Assim podemos correlacionar caso queira monitorar encadeamentos usando POP antes do RET.
     */
    extern std::deque<std::pair<ADDRINT, ADDRINT>> last_pops;

    /**
     * Fun��o chamada antes de gravar (por MOV) um valor no endere�o da mem�ria.
     * Se esse valor for heuristicamente reconhecido como endere�o de API, armazenamos no `suspicious_stack`.
     */
    VOID RecordStackPointerWrite(ADDRINT addr, ADDRINT value, ADDRINT ins_addr);

    /**
     * Fun��o para registrar o POP, guardando (ins_addr, valor_popado).
     */
    VOID RecordPopInstruction(ADDRINT value, ADDRINT ins_addr);

    /**
     * Detecta, no momento do RET, se o valor em RSP corresponde a algo suspeito armazenado anteriormente.
     */
    VOID DetectRetBasedCall(ADDRINT rsp, ADDRINT ret_ins);

    /**
     * Heur�stica simples para saber se o endere�o � de alguma API do sistema (Ex.: acima de 0x7FF...).
     * Em um projeto real, poder�amos integrar verifica��o contra m�dulos carregados, etc.
     */
    bool IsLikelyApiAddress(ADDRINT addr);

    /**
     * Fun��o de instrumenta��o de instru��es do PIN (chamada em cada INS).
     */
    VOID InstrumentInstructions(INS ins, VOID* v);

    int InitEvasiveRetDetector();
}
#endif // EVASIVE_RET_DETECTOR_H
