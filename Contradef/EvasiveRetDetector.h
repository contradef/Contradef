#pragma once
#ifndef EVASIVE_RET_DETECTOR_H
#define EVASIVE_RET_DETECTOR_H

#include "pin.H"
#include <map>
#include <deque>
#include <iostream>

namespace EvasiveRetDetector {
    /**
     * Estrutura que guarda informações sobre a escrita na pilha:
     * - value: endereço que foi escrito (p. ex., endereço de API)
     * - mov_ins: endereço da instrução MOV responsável por escrever esse valor
     */
    struct StackWriteInfo {
        ADDRINT value;
        ADDRINT mov_ins;
    };

    // Mapeia endereço de memória (na pilha) -> informações sobre escrita suspeita
    extern std::map<ADDRINT, StackWriteInfo> suspicious_stack;

    /**
     * Usamos um deque para armazenar as últimas instruções POP e o valor desempilhado.
     * Assim podemos correlacionar caso queira monitorar encadeamentos usando POP antes do RET.
     */
    extern std::deque<std::pair<ADDRINT, ADDRINT>> last_pops;

    /**
     * Função chamada antes de gravar (por MOV) um valor no endereço da memória.
     * Se esse valor for heuristicamente reconhecido como endereço de API, armazenamos no `suspicious_stack`.
     */
    VOID RecordStackPointerWrite(ADDRINT addr, ADDRINT value, ADDRINT ins_addr);

    /**
     * Função para registrar o POP, guardando (ins_addr, valor_popado).
     */
    VOID RecordPopInstruction(ADDRINT value, ADDRINT ins_addr);

    /**
     * Detecta, no momento do RET, se o valor em RSP corresponde a algo suspeito armazenado anteriormente.
     */
    VOID DetectRetBasedCall(ADDRINT rsp, ADDRINT ret_ins);

    /**
     * Heurística simples para saber se o endereço é de alguma API do sistema (Ex.: acima de 0x7FF...).
     * Em um projeto real, poderíamos integrar verificação contra módulos carregados, etc.
     */
    bool IsLikelyApiAddress(ADDRINT addr);

    /**
     * Função de instrumentação de instruções do PIN (chamada em cada INS).
     */
    VOID InstrumentInstructions(INS ins, VOID* v);

    int InitEvasiveRetDetector();
}
#endif // EVASIVE_RET_DETECTOR_H
