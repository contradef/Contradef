#pragma once
#ifndef TRACE_FCN_CALL_H
#define TRACE_FCN_CALL_H

#include <vector>
#include <iostream>
#include <fstream>
#include "utils.h"
#include <unistd.h>
#include "pin.H"
#include "InstrumentationUtils.h"
#include "CallStackManager.h"
#include "DllFunctionTracker.h"
#include "DllFunctionMapper.h"
#include "TraceInstructions.h"

namespace TraceFcnCall {

    // Arquivo de saída para rastreamento de chamadas externas
    extern std::ofstream ExternalCallTraceOutFile;
    VOID EmitFuncCall(THREADID threadid, ADDRINT instAddress, ADDRINT targetRtnAddr, BOOL isCall, BOOL isDirect, INT32 tailCall, ADDRINT returnAddress, ADDRINT rspValue, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6);
    VOID EmitFuncReturn(THREADID threadid, ADDRINT instAddress, ADDRINT retAddr, ADDRINT ret0, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6);
    VOID InstrumentFuncCall(TRACE trace, INS ins);
    VOID TraceFunc(TRACE trace, VOID* v);
    VOID saveAllExternalCalls(std::ofstream& ExternalCallTraceOutFile);
    VOID saveLastExternalCall(std::ofstream& ExternalCallTraceOutFile);
    VOID CallbackBefore(THREADID tid, ADDRINT instAddress, CONTEXT* ctx, ADDRINT returnAddress);
    VOID InstrumentFcn(RTN rtn);
    void TraceFuncM2(IMG img, VOID* v);
    VOID Fini(int, VOID* v);
    int InitFcnCallTrace(std::string pid, std::string filename);

}

#endif // TRACE_FCN_CALL_H
