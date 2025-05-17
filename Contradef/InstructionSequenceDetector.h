#pragma once
#ifndef INSTRUCTION_SEQUENCE_DETECTOR_H
#define INSTRUCTION_SEQUENCE_DETECTOR_H

#include "pin.H"
#include <iostream>
#include <vector>
#include <deque>
#include <algorithm>
#include <unordered_map>
#include <cctype> // Para std::toupper

#define CreateInstVector(...) CreateVectorFromArgs(__VA_ARGS__, NULL)

std::vector<std::string> CreateVectorFromArgs(const char* first, ...);

std::string CaptureAndConvertToUpper(const std::string& input);
void NormalizeInstructionText(std::string& instr);

// Forward declaration
struct SequenceInstructions;

// Definição do tipo de callback usando a declaração antecipada de SequenceInstruction
using SeqMatchCallbackFunc = VOID(*)(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);

struct InstrumentedInstruction {
    ADDRINT instAddr;
    std::string instructionStr;
    std::string normalizedInstructionStr;
    bool insHasWildcard;
    size_t strSize;
    OPCODE insClass;

    InstrumentedInstruction(OPCODE insCl, std::string instructionStr)
        : instAddr(0), instructionStr(instructionStr), normalizedInstructionStr(instructionStr), insHasWildcard(false), strSize(0), insClass(insCl)
    {
        NormalizeInstructionText(normalizedInstructionStr);
        strSize = strlen(normalizedInstructionStr.c_str());
    }
};

struct InstructionToMatch {
    ADDRINT matchAddr;
    std::string instructionStr;
    std::string normalizedInstructionStr;
    bool isAnyInst;
    bool hasWildcard;
    size_t size;
    OPCODE insClass;

    // Construtor para inicializar o contexto com IDs
    InstructionToMatch(std::string instructionStr)
        : matchAddr(0), instructionStr(instructionStr), normalizedInstructionStr(instructionStr), isAnyInst(false), hasWildcard(false), size(0), insClass(XED_ICLASS_INVALID)
    {
        NormalizeInstructionText(normalizedInstructionStr);
        const char* insChar = normalizedInstructionStr.c_str();
        size = strlen(insChar);
        if (size == 3 && normalizedInstructionStr[0] == '?' && normalizedInstructionStr[1] == '?' && normalizedInstructionStr[2] == '?')
        {
            isAnyInst = true;
        }
        else if (normalizedInstructionStr.find("?") != std::wstring::npos)
        {
            hasWildcard = true;
        }

        std::string mnemonic = CaptureAndConvertToUpper(instructionStr);
        if (mnemonic.find("?") != std::wstring::npos)
        {
            std::cout << "Wildcards não são permitidos nas instruções, use somente nos operandos." << std::endl;
            exit(1);
        }
        // Quando insHasWildcard == true -> insClass será inválida
        insClass = str2xed_iclass_enum_t(mnemonic.c_str());
    }
};

struct SequenceInstructions {
    // Armazena as sequências de instruções normalizadas
    std::vector<std::vector<InstructionToMatch*>> instruction_sequences;
    int matchOcurrenceIndex;
    int matchOcurrenceIndexEnd;
    int matchCount;

    // Callback a ser chamado quando uma sequência for encontrada
    SeqMatchCallbackFunc match_callback;

    // Pointeiro para um valor ou estrutura a ser passado para o callback
    VOID* v;

    // Construtor para inicializar o contexto com IDs
    SequenceInstructions(const std::vector<std::vector<std::string>>& instruction_seq, SeqMatchCallbackFunc callback, VOID* v, int matchOcurrenceIndex = -1, int matchOcurrenceIndexEnd = -1)
        : instruction_sequences(), matchOcurrenceIndex(matchOcurrenceIndex), matchOcurrenceIndexEnd(matchOcurrenceIndexEnd), matchCount(0), match_callback(callback), v(v)
    {
        for (const auto& instructionArr : instruction_seq)
        {
            std::vector<InstructionToMatch*> orLst;
            for (const auto& inst: instructionArr) {
                orLst.push_back(new InstructionToMatch(inst));
            }
            instruction_sequences.push_back(orLst);
        }
    }
};


struct InstructionKey {
    ADDRINT address;
    std::string disassembledInstruction;

    // Construtor
    InstructionKey(ADDRINT addr, const std::string& instr)
        : address(addr), disassembledInstruction(instr) {
    }

    // Operador de igualdade para comparação no unordered_map
    bool operator==(const InstructionKey& other) const {
        return address == other.address &&
            disassembledInstruction == other.disassembledInstruction;
    }
};

// Função de hash personalizada
struct InstructionKeyHash {
    size_t operator()(const InstructionKey& key) const {
        // Combinar o hash do endereço e da string
        size_t hash1 = std::hash<ADDRINT>()(key.address);
        size_t hash2 = std::hash<std::string>()(key.disassembledInstruction);
        return hash1 ^ (hash2 << 1); // Combinação simples
    }
};

enum CaptureMode
{
    onCall,
    onDisassembly
};

class InstructionSequenceDetector
{
public:
    InstructionSequenceDetector();
    ~InstructionSequenceDetector();

    // Adiciona uma nova sequência de instruções para detecção
    void AddInstructionSequence(const std::vector<std::vector<std::string>>& sequence, SeqMatchCallbackFunc matchCallBack = nullptr, VOID* v = nullptr, int matchOcurrenceIndex = -1, int matchOcurrenceIndexEnd = -1);

    // Inicializa a estrutura necessária (deve ser chamado após adicionar todas as sequências)
    void Initialize();

    // Função de instrumentação que deve ser chamada para cada instrução
    VOID InstructionTrace(INS ins, VOID* v, CaptureMode captureMode = onCall);
    VOID seqInstCB(ADDRINT ip, CONTEXT* ctxt, InstrumentedInstruction* ins_instr);
    static VOID seqInstCBWrapper(ADDRINT ip, CONTEXT* ctxt, InstrumentedInstruction* ins_instr, InstructionSequenceDetector* self);

    static VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v);
    static VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v);

    // Implementações não estáticas
    VOID ThreadStartImpl(THREADID tid, CONTEXT* ctxt, INT32 flags);
    VOID ThreadFiniImpl(THREADID tid, const CONTEXT* ctxt, INT32 code);
    std::deque<InstrumentedInstruction*> InstructionSequenceDetector::GetInstructionQueue();
    std::deque<InstrumentedInstruction*> InstructionSequenceDetector::GetDisassembledInstructionQueue();

private:
    // Estrutura para armazenar dados específicos da thread
    struct ThreadData
    {
        std::deque<InstrumentedInstruction*> instruction_queue;
        std::deque<InstrumentedInstruction*> disassembled_instruction_queue;
    };

    // Key para o Thread-Local Storage
    TLS_KEY tls_key;

    // Armazena as sequências de instruções normalizadas
    std::vector<SequenceInstructions*> instruction_sequences;

    std::tr1::unordered_map<InstructionKey, InstrumentedInstruction*, InstructionKeyHash> instructionCache;

    // Tamanho máximo das sequências (para a fila)
    size_t max_sequence_length;

    // Métodos auxiliares
    ThreadData* GetThreadData();

    VOID Instruction(ADDRINT ip, CONTEXT* ctxt, InstrumentedInstruction* ins_text);
    VOID DisassembledInstruction(ADDRINT ip, InstrumentedInstruction* ins_instr);
};

#endif // INSTRUCTION_SEQUENCE_DETECTOR_H
