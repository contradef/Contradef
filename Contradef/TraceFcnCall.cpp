#include "TraceFcnCall.h"

namespace TraceFcnCall {
    // Arquivo de saída para rastreamento de chamadas externas
    std::ofstream ExternalCallTraceOutFile;
    std::ofstream ExternalCallTraceOutFileM2;
    
    PIN_MUTEX traceFcnMutex;
    std::map<THREADID, CallStackManager> callStacks;
    DllFunctionTracker callTracker(100000); // Máximo de 100000 funções rastreadas
    bool saveAtFini = false;

    VOID EmitFuncCall(THREADID threadid, ADDRINT instAddress, ADDRINT targetRtnAddr, BOOL isCall, BOOL isDirect, INT32 tailCall, ADDRINT returnAddress, ADDRINT rspValue, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
    {
        if (targetRtnAddr == 0) {
            return;
        }
        if (IsMainExecutable(instAddress)) {
            PIN_LockClient();
            RTN rtnTgt = RTN_FindByAddress(targetRtnAddr);
            std::string s;
            bool print = true;
            std::string rtnName = "";
            std::string imgName = "";

            if (RTN_Valid(rtnTgt))
            {
                IMG img = SEC_Img(RTN_Sec(rtnTgt));
                if (IMG_Valid(img))
                {
                    imgName = IMG_Name(img);
                    s += imgName;
                    if (imgName == IMG_Name(IMG_FindImgById(1))) {
                        print = false;
                    }
                }
                rtnName = RTN_Name(rtnTgt);

                s += ":" + rtnName;
                if (rtnName.empty() || imgName.empty()) {
                    print = false;
                }
            }
            else {
                print = false;

            }

            ///// Desativando call stack. Ainda em testes
            // UINT64 stackValue = *reinterpret_cast<UINT64*>(rspValue);
            // callStacks[threadid].pushFunction(instAddress, returnAddress, stackValue, tailCall, rtnName);
            /////

            if (print) {
                //std::cout << "----> " << instAddress << " -> " << targetRtn << s << std::endl;
            }

            PIN_UnlockClient();

        }

        PIN_LockClient();

        if (IsMainExecutable(instAddress) && !IsMainExecutable(targetRtnAddr)) {
            std::string tgtRtnName = "";
            std::string imgName = "";
            ADDRINT tgtRtnAddr = 0;
            RTN tgtRtn = RTN_FindByAddress(targetRtnAddr);
            if (RTN_Valid(tgtRtn))
            {
                tgtRtnName = RTN_Name(tgtRtn);
                tgtRtnAddr = RTN_Address(tgtRtn);
                IMG tgtImg = SEC_Img(RTN_Sec(tgtRtn));
                if (IMG_Valid(tgtImg))
                {
                    imgName = IMG_Name(tgtImg);
                }
            }
            if (tgtRtnName.empty()) {
                OS_PROCESS_ID pid = PIN_GetPid();
                FunctionData fcnData = GetFunctionFromAddress(targetRtnAddr, pid);
                tgtRtnName = fcnData.functionName;
                tgtRtnAddr = targetRtnAddr;
                imgName = "[forced] " + fcnData.fullModuleName;
            }
            callTracker.addFunctionCall(threadid, imgName, tgtRtnName, tgtRtnAddr);
            if (KnobTraceExternalCallTrace && !saveAtFini) {
                saveLastExternalCall(ExternalCallTraceOutFile);
            }

            std::string retRtnName = "INVALID_RTN";
            RTN rtnt = RTN_FindByAddress(returnAddress);
            if (RTN_Valid(rtnt)) {
                retRtnName = RTN_Name(rtnt);
            }

        }
        PIN_UnlockClient();
    }


    VOID EmitFuncReturn(THREADID threadid, ADDRINT instAddress, ADDRINT retAddr, ADDRINT ret0, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
    {
        ///// Desativando call stack. Ainda em testes
        //if (IsMainExecutable(retAddr)) {
        //    callStacks[threadid].popUntilAddress(retAddr);
        //    
        //    //callStacks[threadid].popFunction();
        //    //callStackManager.peekTopFunction();
        //}
    }

    VOID InstrumentFuncCall(TRACE trace, INS ins)
    {
        if (INS_IsCall(ins) && !INS_IsDirectControlFlow(ins))
        {
            BOOL isCall = INS_IsCall(ins);
            // Indirect call
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitFuncCall),
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_BRANCH_TARGET_ADDR,
                IARG_BOOL, isCall, // isCall
                IARG_BOOL, FALSE, // isDirect
                IARG_BOOL, FALSE, // tailCall
                IARG_ADDRINT, INS_NextAddress(ins), // Endereço da próxima instrução
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_FUNCARG_CALLSITE_VALUE, 0,
                IARG_FUNCARG_CALLSITE_VALUE, 1,
                IARG_FUNCARG_CALLSITE_VALUE, 2,
                IARG_FUNCARG_CALLSITE_VALUE, 3,
                IARG_FUNCARG_CALLSITE_VALUE, 4,
                IARG_FUNCARG_CALLSITE_VALUE, 5,
                IARG_FUNCARG_CALLSITE_VALUE, 6,
                IARG_END);
        }
        else if (!INS_IsRet(ins) && INS_IsIndirectControlFlow(ins))
        {
            BOOL isCall = INS_IsCall(ins);

            // Indirect call
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitFuncCall),
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_BRANCH_TARGET_ADDR,
                IARG_BOOL, isCall, // isCall
                IARG_BOOL, FALSE, // isDirect
                IARG_BOOL, FALSE, // tailCall
                IARG_ADDRINT, INS_NextAddress(ins), // Endereço da próxima instrução
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_FUNCARG_CALLSITE_VALUE, 0,
                IARG_FUNCARG_CALLSITE_VALUE, 1,
                IARG_FUNCARG_CALLSITE_VALUE, 2,
                IARG_FUNCARG_CALLSITE_VALUE, 3,
                IARG_FUNCARG_CALLSITE_VALUE, 4,
                IARG_FUNCARG_CALLSITE_VALUE, 5,
                IARG_FUNCARG_CALLSITE_VALUE, 6,
                IARG_END);
        }
        else if (INS_IsDirectControlFlow(ins))
        {
            // Is this a tail call?
            PIN_LockClient();
            RTN sourceRtn = TRACE_Rtn(trace);
            RTN destRtn = RTN_FindByAddress(INS_DirectControlFlowTargetAddress(ins));
            PIN_UnlockClient();

            //std::cout << INS_Disassemble(ins) << std::endl;

            if (INS_IsCall(ins)         // conventional call
                || sourceRtn != destRtn // tail call
                )
            {
                BOOL isCall = INS_IsCall(ins);
                BOOL tailcall = !isCall;
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitFuncCall),
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_ADDRINT, RTN_Address(destRtn),
                    IARG_BOOL, isCall, // isCall
                    IARG_BOOL, TRUE, // isDirect
                    IARG_BOOL, tailcall,
                    IARG_ADDRINT, INS_NextAddress(ins), // Endereço da próxima instrução
                    IARG_REG_VALUE, REG_STACK_PTR,
                    IARG_FUNCARG_CALLSITE_VALUE, 0,
                    IARG_FUNCARG_CALLSITE_VALUE, 1,
                    IARG_FUNCARG_CALLSITE_VALUE, 2,
                    IARG_FUNCARG_CALLSITE_VALUE, 3,
                    IARG_FUNCARG_CALLSITE_VALUE, 4,
                    IARG_FUNCARG_CALLSITE_VALUE, 5,
                    IARG_FUNCARG_CALLSITE_VALUE, 6,
                    IARG_END);
            }
        }
        else if (INS_IsRet(ins))
        {
            RTN rtn = TRACE_Rtn(trace);

#if defined(TARGET_LINUX) && defined(TARGET_IA32)
            //        if( RTN_Name(rtn) ==  "_dl_debug_state") return;
            if (RTN_Valid(rtn) && RTN_Name(rtn) == "_dl_runtime_resolve") return;
#endif
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitFuncReturn),
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_RETURN_IP,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_FUNCARG_CALLSITE_VALUE, 0,
                IARG_FUNCARG_CALLSITE_VALUE, 1,
                IARG_FUNCARG_CALLSITE_VALUE, 2,
                IARG_FUNCARG_CALLSITE_VALUE, 3,
                IARG_FUNCARG_CALLSITE_VALUE, 4,
                IARG_FUNCARG_CALLSITE_VALUE, 5,
                IARG_FUNCARG_CALLSITE_VALUE, 6,
                IARG_END);

        }
        else {
            if (INS_IsDirectControlFlow(ins)) {

                std::cout << INS_Disassemble(ins) << "\n";
            }
        }
    }

    VOID TraceFunc(TRACE trace, VOID* v)
    {
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
            for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
            {
                InstrumentFuncCall(trace, ins);
            }
        }
    }

    VOID saveAllExternalCalls(std::ofstream& ExternalCallTraceOutFile)
    {
        callTracker.saveAllExternalCalls(ExternalCallTraceOutFile);
    }

    VOID saveLastExternalCall(std::ofstream& ExternalCallTraceOutFile)
    {
        callTracker.saveLastExternalCall(ExternalCallTraceOutFile);
    }


    ///////Método 2
    static bool inited = true;
    static bool tracing = false;
    VOID CallbackBefore(THREADID tid, ADDRINT instAddress, CONTEXT* ctx, ADDRINT returnAddress) {

        PIN_MutexLock(&traceFcnMutex);

		if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(returnAddress)))
		{
            if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) 
            {
                PIN_MutexUnlock(&traceFcnMutex);
                return;
            }
            //
            PIN_LockClient();
            RTN rtnTgt = RTN_FindByAddress(instAddress);
            std::string rtnName = RTN_Name(rtnTgt);
            if (RTN_Valid(rtnTgt))
            {
                IMG img = SEC_Img(RTN_Sec(rtnTgt));
                if (IMG_Valid(img)) {
                    std::string imgName = IMG_Name(img);
                    ExternalCallTraceOutFileM2 << std::hex << instAddress << std::dec << "   T[" << tid << "]  " << imgName << ":" << rtnName << std::endl << std::flush;
                }
            }

            if ("IsBadReadPtr" == rtnName) {
                inited = false;
                string ipid = decstr(WindowsAPI::getpid());
                TraceInstructions::disable();
            }
            if ("VirtualFree" == rtnName && !inited) {
                inited = true;
                TraceInstructions::enable();
            }

            if ("MapViewOfFile" == rtnName) {
                inited = false;
                TraceInstructions::disable();
            }
            if ("UnmapViewOfFile" == rtnName && !inited) {
                inited = true;
                TraceInstructions::enable();
            }

            //if ("RegQueryValueExA" == rtnName && !inited) {
            //    inited = true;
            //    string ipid = decstr(WindowsAPI::getpid()); // CHAMAR ESTA FUNÇÃO EVITA O ERRO DE INSTRUMENTAÇÃO, VERIFICAR O MOTIVO
            //    std::cout << "Hook inserido" << std::endl;
            //    TraceInstructions::InitTrace(ipid, "RegQueryValueExA");
            //}
            PIN_UnlockClient();
		}
        PIN_MutexUnlock(&traceFcnMutex);

    }

    VOID InstrumentFcn(RTN rtn) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_CONTEXT,
            IARG_RETURN_IP,          // Endereço da função chamante
            IARG_END);

        RTN_Close(rtn);
    }

    void TraceFuncM2(IMG img, VOID* v) {
        for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
            RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
            if (RTN_Valid(rtn)) {
                InstrumentFcn(rtn);
            }
        }
    }
    ///////FIM Método 2


    VOID Fini(int, VOID* v) {
        if (KnobTraceExternalCallTrace && saveAtFini) {
            saveAllExternalCalls(ExternalCallTraceOutFile);
        }
        ExternalCallTraceOutFile.close();
        ExternalCallTraceOutFileM2.close();
    }

    int InitFcnCallTrace(std::string pid, std::string filename)
    {

        if (KnobTraceExternalCallTrace)
        {
            std::string logfilename = filename + "." + pid + ".externalcalltraceM1.cdf";
            ExternalCallTraceOutFile.open(logfilename.c_str(), std::ios::binary);

            std::string logfilenameM2 = filename + "." + pid + ".externalcalltraceM2.cdf";
            ExternalCallTraceOutFileM2.open(logfilenameM2.c_str(), std::ios::binary);
        }

        PIN_AddFiniFunction(Fini, 0);
        TRACE_AddInstrumentFunction(TraceFunc, 0);
        IMG_AddInstrumentFunction(TraceFuncM2, 0); // Método 2

        return 0;
    }
}