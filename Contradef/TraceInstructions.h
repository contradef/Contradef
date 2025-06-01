#pragma once
/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

 /*! @file
  *  This file contains declarations for a tool that generates instruction traces with values.
  *  It is designed to help debugging.
  */

#ifndef TRACE_INSTRUCTIONS_H
#define TRACE_INSTRUCTIONS_H

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <stack>
#include "utils.h"
#include <unistd.h>
#include "pin.H"
#include "instlib.H"
#include "control_manager.H"
#include "regvalue_utils.h"
#include "Instrumentation.h"
#include "InitParams.h"

namespace TraceInstructions {
	using namespace CONTROLLER;
	using namespace INSTLIB;

	/* ===================================================================== */
	/* Global Variables */
	/* ===================================================================== */

	extern PIN_MUTEX fileOutMutex;
	extern const std::size_t bufferSize;
	extern std::vector<char> buffer;
	extern std::ofstream out;
	extern INT32 enabled;
	extern FILTER filter;
	extern ICOUNT icount;
	extern const UINT32 MaxEmitArgs;
	extern AFUNPTR emitFuns[];
	extern std::stack<ADDRINT> callStack;

	/* ===================================================================== */
	/* Function Declarations */
	/* ===================================================================== */

	BOOL Emit(THREADID threadid);
	VOID Flush();
	VOID Handler(EVENT_TYPE ev, VOID*, CONTEXT* ctxt, VOID*, THREADID, bool bcast);
	VOID EmitNoValues(THREADID threadid, std::string* str);
	VOID Emit1Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val);
	VOID Emit2Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val, std::string* reg2str, ADDRINT reg2val);
	VOID Emit3Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val, std::string* reg2str, ADDRINT reg2val, std::string* reg3str, ADDRINT reg3val);
	VOID Emit4Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val, std::string* reg2str, ADDRINT reg2val, std::string* reg3str, ADDRINT reg3val, std::string* reg4str, ADDRINT reg4val);
	VOID EmitXMM(THREADID threadid, UINT32 regno, PINTOOL_REGISTER* xmm);
	VOID AddXMMEmit(INS ins, IPOINT point, REG xmm_dst);
	VOID EmitCmpValues(ADDRINT addr, THREADID threadid, std::string* str, std::string* reg1str, INT32 reg1ismem, UINT32 reg1size, VOID* reg1val, std::string* reg2str, INT32 reg2ismem, UINT32 reg2size, VOID* reg2val, std::string* reg3str, UINT64 reg3val);
	VOID AddEmitCmp(INS ins, IPOINT point, std::string& traceString, REG reg3val);
	VOID EmitMovValue(ADDRINT addr, THREADID threadid, std::string* str, REG dstReg, ADDRINT value, UINT32 movSize);
	VOID AddEmitMov(INS ins, IPOINT point, std::string& traceString);
	VOID AddEmit(INS ins, IPOINT point, std::string& traceString, UINT32 regCount, REG regs[]);
	VOID CaptureWriteEa(THREADID threadid, VOID* addr);
	VOID ShowN(UINT32 n, VOID* ea);
	VOID EmitWrite(ADDRINT addr, THREADID threadid, std::string* str, UINT32 size);
	VOID EmitRead(ADDRINT addr, THREADID threadid, std::string* str, VOID* ea, UINT32 size);
	VOID Indent();
	VOID EmitICount();
	VOID EmitDirectCall(THREADID threadid, ADDRINT instAddress, std::string* str, INT32 tailCall, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6);
	VOID EmitIndirectCall(THREADID threadid, ADDRINT instAddress, std::string* str, ADDRINT target, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6);
	VOID EmitReturn(THREADID threadid, ADDRINT instAddress, string* str, ADDRINT retAddr, ADDRINT ret0);
	VOID CallTrace(TRACE trace, INS ins);
	VOID InstructionTrace(TRACE trace, INS ins);
	VOID Trace(TRACE trace, VOID* v);
	VOID OnSig(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom, CONTEXT* ctxtTo, INT32 sig, VOID* v);
	void enable();
	void disable();
	int InitTrace(std::string pid, std::string filename);
}

#endif // TRACE_INSTRUCTIONS_H
