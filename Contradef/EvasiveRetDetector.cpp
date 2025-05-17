#include "EvasiveRetDetector.h"
#include "InstrumentationUtils.h"

namespace EvasiveRetDetector {
    // Mapa global que relaciona endere�o na pilha -> (valor escrito, onde foi escrito)
    std::map<ADDRINT, StackWriteInfo> suspicious_stack;
    // Hist�rico das �ltimas instru��es POP
    std::deque<std::pair<ADDRINT, ADDRINT>> last_pops;

    /**
     * Se um MOV [endereco_pilha], reg = valor_api for detectado,
     * e considerarmos esse valor como prov�vel endere�o de API,
     * armazenamos no suspicious_stack.
     */
    VOID RecordStackPointerWrite(ADDRINT addr, ADDRINT value, ADDRINT ins_addr)
    {
        // Se for �provavelmente� um endere�o de API (heur�stica simples),
        // guarda no mapa para verificar depois.
        if (IsLikelyApiAddress(value))
        {
            StackWriteInfo info;
            info.value = value;
            info.mov_ins = ins_addr;
            suspicious_stack[addr] = info;

            // Podemos imprimir debug:
            std::cout << "[Debug] MOV suspeito -> Pilha: 0x" << std::hex << addr
                << ", Valor: 0x" << value
                << ", Instru��o MOV em: 0x" << ins_addr << std::endl;
        }
    }

    /**
     * Armazena informa��es de instru��es POP:
     *  - ins_addr: endere�o da instru��o POP
     *  - value: qual valor foi lido da pilha
     */
    VOID RecordPopInstruction(ADDRINT value, ADDRINT ins_addr)
    {
        last_pops.push_back(std::make_pair(ins_addr, value));

        // Mant�m o hist�rico curto (at� 5)
        if (last_pops.size() > 5)
            last_pops.pop_front();
    }

    /**
     * Chamado no momento de um RET (NEAR/FAR).
     * Verifica se RSP aponta para algo registrado no suspicious_stack.
     */
    VOID DetectRetBasedCall(ADDRINT rsp, ADDRINT ret_ins)
    {
        auto it = suspicious_stack.find(rsp);
        if (it != suspicious_stack.end())
        {
            // Achamos um valor suspeito na pilha (MOV c/ endere�o de API).
            const StackWriteInfo& info = it->second;
            ADDRINT func_addr = info.value;
            ADDRINT mov_ins = info.mov_ins;

            std::cout << "[ALERTA - RET Encadeado] RET em 0x" << std::hex << ret_ins
                << " desvia para suposta API 0x" << func_addr
                << " (empilhada por MOV em 0x" << mov_ins << ")" << std::endl;

            // Se quiser remover do mapa (para n�o repetir alertas):
            // suspicious_stack.erase(rsp);
        }
    }

    /**
     * Heur�stica simples: API addresses �tendem� a ser altos (por ex.: 0x7FFF...).
     * Pode integrar t�cnicas para ver se est� em alguma DLL.
     */
    bool IsLikelyApiAddress(ADDRINT addr)
    {
        //if (!PIN_CheckReadAccess(reinterpret_cast<VOID*>(addr))) return false;
        //PIN_LockClient(); 
        //RTN rtnTgt = RTN_FindByAddress(addr);
        //if (RTN_Valid(rtnTgt))
        //{
        //    IMG img = SEC_Img(RTN_Sec(rtnTgt));
        //    if (IMG_Valid(img)) {
        //        PIN_UnlockClient();
        //        
        //        // � necess�rio verificar se a imagam � va�lida pois para o c�digo descompactado ou desencriptado n�o � retornado um nome de imagem
        //        return !IsMainExecutable(addr);
        //    }
        //}
        //PIN_UnlockClient();
        //return false;

        // Alternativa mais eficiente
        return (addr > 0x7FF000000000ULL); // Ajustar conforme a necessidade
    }

    /**
     * Instrumenta instru��es:
     *  1) Detecta MOV [mem], reg � se mem==[pilha] e reg for valor em API range
     *  2) Detecta POP � registra info
     *  3) Detecta RET � verifica se top stack guarda um valor suspeito
     */
    VOID InstrumentInstructions(INS ins, VOID* v)
    {
        // 1) Se for MOV [mem], reg
        if (INS_Opcode(ins) == XED_ICLASS_MOV &&
            INS_OperandIsMemory(ins, 0) &&
            INS_OperandIsReg(ins, 1) &&
            INS_IsMemoryWrite(ins))
        {
            // Precisamos interceptar o endere�o de escrita e o valor do reg
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordStackPointerWrite,
                IARG_MEMORYWRITE_EA,
                IARG_REG_VALUE, INS_OperandReg(ins, 1),
                IARG_INST_PTR,
                IARG_END);
        }

        // 2) Se for POP
        if (INS_Opcode(ins) == XED_ICLASS_POP)
        {
            // Intercepta valor popado do topo
            //   No PIN 3.x: para POP reg => INS_RegW(ins,0)
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordPopInstruction,
                IARG_REG_VALUE, INS_RegW(ins, 0),
                IARG_INST_PTR,
                IARG_END);
        }

        // 3) Se for RET
        if (INS_Opcode(ins) == XED_ICLASS_RET_NEAR || INS_Opcode(ins) == XED_ICLASS_RET_FAR)
        {
            // Precisamos do RSP e do endere�o do RET
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DetectRetBasedCall,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_INST_PTR,
                IARG_END);
        }
    }


    int InitEvasiveRetDetector()
    {

        INS_AddInstrumentFunction(InstrumentInstructions, 0);

        return 0;
    }
}