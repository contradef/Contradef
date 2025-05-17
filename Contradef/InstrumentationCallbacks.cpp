#include "InstrumentationCallbacks.h"

// #include "xed-interface.h"
//
//VOID InstructionX(INS ins, VOID* v)
//{
//    // Obter o endereço da instrução
//    ADDRINT addr = INS_Address(ins);
//
//    // Obter o tamanho da instrução
//    UINT32 len = INS_Size(ins);
//
//    // Obter o código binário da instrução
//    UINT8* code = new UINT8[len];
//    PIN_SafeCopy(code, (VOID*)addr, len);
//
//    // Inicializar o estado do XED
//    xed_state_t dstate;
//    xed_state_zero(&dstate);
//    dstate.stack_addr_width = XED_ADDRESS_WIDTH_64b;
//    dstate.mmode = XED_MACHINE_MODE_LONG_64;
//
//    // Decodificar a instrução original
//    xed_decoded_inst_t xedd;
//    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
//
//    xed_error_enum_t xed_error = xed_decode(&xedd, code, len);
//    if (xed_error == XED_ERROR_NONE)
//    {
//        // Modificar a instrução conforme necessário
//        // Exemplo: alterar o opcode para NOP
//        xed_encoder_instruction_t enc_instr;
//        xed_inst1(&enc_instr, dstate, XED_ICLASS_NOP, 0);
//
//        // Codificar a nova instrução
//        UINT8 enc_buf[XED_MAX_INSTRUCTION_BYTES];
//        UINT32 enc_len = 0;
//
//        xed_encoder_request_t enc_req;
//        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
//
//        xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
//        if (convert_ok)
//        {
//            xed_error_enum_t xed_err = xed_encode(&enc_req, enc_buf, XED_MAX_INSTRUCTION_BYTES, &enc_len);
//            if (xed_err == XED_ERROR_NONE)
//            {
//                // Substituir a instrução no cache de código do PIN
//                // Use INS_Rewrite para substituir a instrução (Note que INS_Rewrite não existe, mas veja a seção abaixo)
//
//                // Infelizmente, o PIN não fornece uma API direta para substituir instruções individuais
//                // Alternativamente, você pode remover a instrução original e inserir a nova instrução
//
//                // Remover a instrução original
//                INS_Delete(ins);
//
//                // Inserir a nova instrução codificada
//                INS_InsertDirectJump(ins, IPOINT_BEFORE, (ADDRINT)enc_buf);
//                // Note que INS_InsertDirectJump é usado para inserir um salto, não uma instrução arbitrária
//                // Inserir instruções arbitrárias requer técnicas avançadas
//
//                // Outra opção é usar um código de substituição personalizado
//            }
//        }
//    }
//
//    delete[] code;
//}



VOID SequenceMatchCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    // Obtém as últimas 2 chamadas
    //auto lastCalls = callTracker.getLastNCalls(100);
    //std::cout << "Últimas 100 chamadas:\n";
    //for (const auto& call : lastCalls) {
    //    std::cout << "[" << call.threadId << "] " << std::hex << call.address << " - " << std::dec << "DLL: " << call.dllName << ", Função: " << call.functionName << "\n";
    //}


    // Obter os flags atuais
    ADDRINT flags = PIN_GetContextReg(ctxt, REG_RFLAGS);

    // Verificar o valor atual do ZF
    BOOL zf_before = (flags & (1 << 6)) != 0;
    //std::cout << "1 - ZF ->" << zf_before << std::endl;

    if (zf_before == 0) {

        // Para setar o ZF para 1:
        flags |= (1 << 6); // Seta o bit 6 (ZF) para 1
        std::cout << "[CONTRADEF] APLICANDO CONTRAMEDIDA NO INDICE " << sequence.matchCount << std::endl;

        // Para setar o ZF para 0:
        //flags &= ~(1 << 6); // Limpa o bit 6 (ZF) para 0

        // Atualizar os flags
        PIN_SetContextReg(ctxt, REG_RFLAGS, flags);

        // Obter os flags atualizados
        flags = PIN_GetContextReg(ctxt, REG_RFLAGS);
        BOOL zf_after = (flags & (1 << 6)) != 0;
        //std::cout << "ZF depois da modificação: " << zf_after << std::endl;

        PIN_ExecuteAt(ctxt);
    }


    //    wchar_t* CharStr2 = reinterpret_cast<wchar_t*>(rax);
    //    fflush(stdout);
    //    wprintf(L" ** RETURN WString2 --> %ls <-\n", CharStr2);
    //    fflush(stdout);
    //}

}


VOID SequenceMatchCallFcnCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    // Obter os flags atuais
    ADDRINT targetAddr = PIN_GetContextReg(ctxt, REG_R10);



    //////

    if (IsMainExecutable(ip)) {
        PIN_LockClient();
        RTN rtnTgt = RTN_FindByAddress(targetAddr);
        std::string s;
        bool print = true;
        if (RTN_Valid(rtnTgt))
        {
            IMG img = SEC_Img(RTN_Sec(rtnTgt));
            std::string imgName = "";
            if (IMG_Valid(img))
            {
                imgName = IMG_Name(img);
                s += imgName;
                if (imgName == IMG_Name(IMG_FindImgById(1))) {
                    print = false;
                }
            }
            std::string rtnName = RTN_Name(rtnTgt);
            s += ":" + rtnName;
            if (rtnName.empty() || imgName.empty()) {
                print = false;
            }
        }
        else {
            print = false;
        }
        if (print) {
            std::cout << "----> " << ip << " -> " << targetAddr << s << std::endl;
        }

        PIN_UnlockClient();

    }
    return;

    //////



    //PIN_LockClient();

    //ADDRINT targetAddr = PIN_GetContextReg(ctxt, REG_R10);

    //IMG img = IMG_FindByAddress(targetAddr);


    //if (IMG_Valid(img)) {
    //    std::cout << "Chamada -> " << IMG_Name(img) << ":";

    //}
    //RTN rtn = RTN_FindByAddress(targetAddr);
    //if (RTN_Valid(rtn)) {
    //    std::cout << RTN_Name(rtn);
    //}
    //std::cout << std::endl;

    //PIN_UnlockClient();
}


VOID SequenceMatchReadStringFcnCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    std::cout << "xxxxx: " << ip << std::endl;
    //return;
    ADDRINT regRcx = PIN_GetContextReg(ctxt, REG_RAX);

    if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(regRcx)))
    {
        wprintf(L" ** RETURN WStringX --> %ls <-\n", ConvertAddrToWideString(regRcx));

        char* CharStr = reinterpret_cast<char*>(regRcx);
        std::cout << "Nome da função --> " << CharStr << std::endl;
    }
}


VOID SequenceMatchReadStringEnvsCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    //lea rax, ptr [rip+0x25e]
    ADDRINT rax_value = PIN_GetContextReg(ctxt, REG_RAX);
    ADDRINT rbp_value = PIN_GetContextReg(ctxt, REG_RBP);

    //ADDRINT rdx_value = PIN_GetContextReg(ctxt, REG_RCX);

    ADDRINT result = rbp_value + rax_value * 2;


    if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(result)))
    {
        //wchar_t* CharStr = reinterpret_cast<wchar_t*>(result);


        //std::wstring wstr(CharStr);
        //wprintf(L" ** RETURN WString --> %ls <-\n", CharStr);
        wprintf(L" ** RETURN WStringX --> %ls <-\n", ConvertAddrToWideString(result));


        char* CharStr2 = reinterpret_cast<char*>(result);
        std::cout << " ** RETURN StringArg --> " << CharStr2 << std::endl;
    }


}


VOID SequenceMatchReadStringForCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    std::cout << " ** --> " << std::endl;

    //lea rax, ptr [rip+0x25e]
    ADDRINT rax_value = PIN_GetContextReg(ctxt, REG_RAX);
    ADDRINT r8_value = PIN_GetContextReg(ctxt, REG_R9);

    //ADDRINT rdx_value = PIN_GetContextReg(ctxt, REG_RCX);

    ADDRINT result = rax_value;

    for (size_t i = 0; i < 15; i++)
    {

        if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(result)))
        {
            wchar_t* CharStr = reinterpret_cast<wchar_t*>(result);


            std::wstring wstr(CharStr);
            wprintf(L" ** RETURN WString --> %ls <-\n", CharStr);
            /*std::wstring wstr = ConvertAddrToWideString(result);
            if (IsValidWideString(wstr)) {
                wprintf(L" ** RETURN WStringX --> %ls <-\n", wstr);

            }*/
            //wprintf(L" ** RETURN WStringX --> %ls <-\n", ConvertAddrToWideString(result));



            //char* CharStr2 = reinterpret_cast<char*>(result);
            //if (IsValidString(std::string(CharStr2))) {
            //    std::cout << " ** RETURN StringArg --> " << CharStr2 << std::endl;
            //}

            //char* CharStr2 = reinterpret_cast<char*>(result);
            //std::cout << " ** RETURN StringArg --> " << CharStr2 << std::endl;

        }
        result = result - 0x4a;
    }


}


VOID SequenceMatchReadStringCmpCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    // Obter o valor completo de RSI
    ADDRINT rsi_value = PIN_GetContextReg(ctxt, REG_RSI);

    // Extrair os 16 bits menos significativos (SI)
    UINT16 six_value = static_cast<UINT16>(rsi_value);

    // Imprimir o valor do registrador SI
    std::cout << "Valor de SI: 0x" << std::hex << six_value << std::endl;
    std::cout << "Valor de RSI: 0x" << std::hex << rsi_value << std::endl;

    //ADDRINT six_value = PIN_GetContextReg(ctxt, REG_SI);
    //ADDRINT rbp_value = PIN_GetContextReg(ctxt, REG_RBP);
    //ADDRINT rax_value = PIN_GetContextReg(ctxt, REG_RAX);

    //for (size_t i = 0; i < 15; i++)
    //{
    //    ADDRINT result = rbp_value + rax_value * 2;

    //    if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(result)))
    //    {
    //        wchar_t* CharStr = reinterpret_cast<wchar_t*>(result);
    //        std::wstring wstr(CharStr);
    //        wprintf(L" ** RETURN WString --> %ls <-\n", CharStr);

    //    }
    //    result = result + 0x1;
    //}


}


VOID SequenceMatchReadStringCmp2Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    ADDRINT rbp_value = PIN_GetContextReg(ctxt, REG_RBP);
    wchar_t* CharStr = reinterpret_cast<wchar_t*>(rbp_value);
    std::wstring wstr(CharStr);
    wprintf(L" ** RETURN WString --> %ls <-\n", CharStr);
}

VOID SequenceMatchReadStringCmp3Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    ADDRINT rdi_value = PIN_GetContextReg(ctxt, REG_RCX);
    wchar_t* CharStr = reinterpret_cast<wchar_t*>(rdi_value);
    std::wstring wstr(CharStr);
    wprintf(L" ** RETURN WString --> %ls <-\n", CharStr);

    char* CharStr2 = reinterpret_cast<char*>(rdi_value);
    std::cout << " ** RETURN StringArg --> " << CharStr2 << std::endl;
}


// Leitura de depuradores
VOID SequenceMatchReadStringCmp40Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    ADDRINT r_value = PIN_GetContextReg(ctxt, REG_R10) + PIN_GetContextReg(ctxt, REG_RCX) * 1 + 0x1;

    for (size_t i = 0; i < 1; i++)
    {
        std::cout << "ADDR: " << std::hex << r_value << std::dec << std::endl;

        if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(r_value))) {
            wchar_t* CharStr = reinterpret_cast<wchar_t*>(r_value);
            std::wstring wstr(CharStr);
            wprintf(L" ** RETURN WString --> %ls <-\n", CharStr);

            char* CharStr2 = reinterpret_cast<char*>(r_value);
            std::cout << " ** RETURN StringArg --> " << CharStr2 << std::endl;
            r_value = r_value + 0x1;
        }

    }


}


// IMPORTANTE - Contem os valores a serem comparados com os nomes de alguns depuradores
VOID SequenceMatchReadStringCmp41Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    ADDRINT r_value = PIN_GetContextReg(ctxt, REG_RBP) + PIN_GetContextReg(ctxt, REG_RCX) * 2 + 0x0;

    for (size_t i = 0; i < 1; i++)
    {
        std::cout << "ADDR: " << std::hex << r_value << std::dec << " T[" << tid << "]" << std::endl;
        std::cout << "TXT: " << r_value << std::endl;

        if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(r_value))) {
            wchar_t* CharStr = reinterpret_cast<wchar_t*>(r_value);
            std::wstring wstr(CharStr);
            wprintf(L" ** RETURN WString --> %ls <-\n", CharStr);

            char* CharStr2 = reinterpret_cast<char*>(r_value);
            std::cout << " ** RETURN StringArg --> " << CharStr2 << std::endl;
            r_value = r_value + 0x1;
        }

    }


}



VOID SequenceMatchAntiDebugSameTarget(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    InstructionSequenceDetector* disassembly_seq_detector = reinterpret_cast<InstructionSequenceDetector*>(v);
    std::deque<InstrumentedInstruction*> instruction_queue = disassembly_seq_detector->GetDisassembledInstructionQueue();

    InstrumentedInstruction* inst = instruction_queue[instruction_queue.size() - 2];
    InstrumentedInstruction* inst2 = instruction_queue[instruction_queue.size() - 1];

    std::string inststr = inst->instructionStr;
    std::string inststr2 = inst2->instructionStr;

    std::string subinst = inststr.substr(2, 15);
    std::string subinst2 = inststr2.substr(3, 15);

    if (subinst == subinst2 && (inst->instAddr + 2) == inst2->instAddr) {  // 2 = tamanho da instrução jz (SHORT JUMP)
        std::cout << "\n[CONTRADEF][ANTIDEBUG] Instruções de Salto com o Mesmo Alvo:" << std::endl;
        std::cout << "    " << std::hex << inst->instAddr << " | " << inststr << std::dec << std::endl;
        std::cout << "    " << std::hex << inst2->instAddr << " | " << inststr2 << std::dec << std::endl;
    }
}


VOID SequenceMatchAntiDebugConstCondition(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    InstructionSequenceDetector* disassembly_seq_detector = reinterpret_cast<InstructionSequenceDetector*>(v);
    std::deque<InstrumentedInstruction*> instruction_queue = disassembly_seq_detector->GetDisassembledInstructionQueue();

    InstrumentedInstruction* inst = instruction_queue[instruction_queue.size() - 2];
    InstrumentedInstruction* inst2 = instruction_queue[instruction_queue.size() - 1];

    std::string inststr = inst->instructionStr;
    std::string inststr2 = inst2->instructionStr;

    if ((inst->instAddr + 2) == inst2->instAddr) { // 2 = tamanho da instrução xor
        std::cout << "\n[CONTRADEF][ANTIDEBUG] Instruções com Condição Constante:" << std::endl;
        std::cout << "    " << std::hex << inst->instAddr << " | " << inststr << std::dec << std::endl;
        std::cout << "    " << std::hex << inst2->instAddr << " | " << inststr2 << std::dec << std::endl;
    }
}


VOID SequenceMatchPauseCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    OS_PROCESS_ID pid = PIN_GetPid();
    std::cout << "Sequencia de instrucoes identificada, endereco de instrucao " << std::hex << ip << std::dec << ", corresponde a funcao: " << GetFunctionFromAddress(ip, pid).functionName << std::endl;
    PauseAtAddress(ip);
}
