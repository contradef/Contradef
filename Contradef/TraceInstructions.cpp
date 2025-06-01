// Este módulo foi implementado usando como base a Pintool InstLib, disponível no SDK do Pin. 

#include "TraceInstructions.h"
#include "InstrumentationUtils.h"

using namespace CONTROLLER;
using namespace INSTLIB;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

PIN_MUTEX TraceInstructions::fileOutMutex;

std::ofstream TraceInstructions::out;
// Buffer de 512 KB para out
const std::size_t TraceInstructions::bufferSize = 512 * 1024;
std::vector<char> TraceInstructions::buffer(bufferSize);  // o buffer precisa durar enquanto o ofstream estiver aberto

INT32 TraceInstructions::enabled = 0;
FILTER TraceInstructions::filter;
ICOUNT TraceInstructions::icount;
const UINT32 TraceInstructions::MaxEmitArgs = 4;
AFUNPTR TraceInstructions::emitFuns[] = { AFUNPTR(TraceInstructions::EmitNoValues), AFUNPTR(TraceInstructions::Emit1Values), AFUNPTR(TraceInstructions::Emit2Values), AFUNPTR(TraceInstructions::Emit3Values), AFUNPTR(TraceInstructions::Emit4Values) };
std::stack<ADDRINT> TraceInstructions::callStack;

/* ===================================================================== */
/* Function Implementations */
/* ===================================================================== */

BOOL TraceInstructions::Emit(THREADID threadid) {
    if (!enabled || KnobSilent || (KnobWatchThread != static_cast<THREADID>(-1) && KnobWatchThread != threadid)) return false;
    return true;
}

VOID TraceInstructions::Flush() {
    if (KnobFlush) out << std::flush;
}

VOID TraceInstructions::Handler(EVENT_TYPE ev, VOID*, CONTEXT* ctxt, VOID*, THREADID, bool bcast) {
    switch (ev) {
    case EVENT_START:
        enabled = 1;
        PIN_RemoveInstrumentation();
#if defined(TARGET_IA32) || defined(TARGET_IA32E)
        if (ctxt) PIN_ExecuteAt(ctxt);
#endif
        break;
    case EVENT_STOP:
        enabled = 0;
        PIN_RemoveInstrumentation();
        if (KnobEarlyOut) {
            std::cerr << "Exiting due to -early_out" << std::endl;
            exit(0);
        }
#if defined(TARGET_IA32) || defined(TARGET_IA32E)
        if (ctxt) PIN_ExecuteAt(ctxt);
#endif
        break;
    default:
        ASSERTX(false);
    }
}

VOID TraceInstructions::EmitNoValues(THREADID threadid, std::string* str) {
    if (!Emit(threadid)) return;
    PIN_MutexLock(&fileOutMutex);
    out << *str << " | [T" << std::dec << threadid << std::hex << "]" << std::endl;
    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::Emit1Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val) {
    if (!Emit(threadid)) return;
    PIN_MutexLock(&fileOutMutex);
    out << *str << " | [T" << std::dec << threadid << std::hex << "] " << *reg1str << " = " << reg1val << std::endl;
    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::Emit2Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val, std::string* reg2str, ADDRINT reg2val) {
    if (!Emit(threadid)) return;
    PIN_MutexLock(&fileOutMutex);
    out << *str << " | [T" << std::dec << threadid << std::hex << "] " << *reg1str << " = " << reg1val << ", " << *reg2str << " = " << reg2val << std::endl;
    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::Emit3Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val, std::string* reg2str, ADDRINT reg2val, std::string* reg3str, ADDRINT reg3val) {
    if (!Emit(threadid)) return;
    PIN_MutexLock(&fileOutMutex);
    out << *str << " | [T" << std::dec << threadid << std::hex << "] " << *reg1str << " = " << reg1val << ", " << *reg2str << " = " << reg2val << ", " << *reg3str << " = " << reg3val << std::endl;
    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::Emit4Values(THREADID threadid, std::string* str, std::string* reg1str, ADDRINT reg1val, std::string* reg2str, ADDRINT reg2val, std::string* reg3str, ADDRINT reg3val, std::string* reg4str, ADDRINT reg4val) {
    if (!Emit(threadid)) return;
    PIN_MutexLock(&fileOutMutex);
    out << *str << " | [T" << std::dec << threadid << std::hex << "] " << *reg1str << " = " << reg1val << ", " << *reg2str << " = " << reg2val << ", " << *reg3str << " = " << reg3val << ", " << *reg4str << " = " << reg4val << std::endl;
    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::EmitXMM(THREADID threadid, UINT32 regno, PINTOOL_REGISTER* xmm) {
    if (!Emit(threadid)) return;
    PIN_MutexLock(&fileOutMutex);
    out << "\t\t\tXMM" << std::dec << regno << " := " << std::setfill('0') << std::hex;
    out.unsetf(std::ios::showbase);
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 8 || i == 12) out << "_";
        out << std::setw(2) << static_cast<int>(xmm->byte[15 - i]);
    }
    out << std::setfill(' ') << std::endl;
    out.setf(std::ios::showbase);
    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::AddXMMEmit(INS ins, IPOINT point, REG xmm_dst) {
    INS_InsertCall(ins, point, AFUNPTR(EmitXMM), IARG_THREAD_ID, IARG_UINT32, xmm_dst - REG_XMM0, IARG_REG_CONST_REFERENCE, xmm_dst, IARG_END);
}

VOID TraceInstructions::EmitCmpValues(ADDRINT addr, THREADID threadid, std::string* str, std::string* reg1str, INT32 reg1ismem, UINT32 reg1size, VOID* reg1val, std::string* reg2str, INT32 reg2ismem, UINT32 reg2size, VOID* reg2val, std::string* reg3str, UINT64 reg3val) {
    if (!Emit(threadid)) return;

    std::string valnum1 = "";
    std::stringstream val1;
    if (reg1ismem) {
        val1 << " [" << GetNumericHexValue((UINT64)reg1val, 8) << "]";

        if (IsStringPointer((ADDRINT)reg1val)) {
            valnum1 = " -> " + GetNumericValueFromRef(reg1val, reg1size) + " = \"" + std::string(reinterpret_cast<const char*>(reg1val)) + "\"";
        }
        else {
            std::stringstream ss;
            valnum1 = " -> " + GetNumericValueFromRef(reg1val, reg1size);
        }
    }
    else {
        val1 << " [" << GetNumericHexValue((UINT64)reg1val, reg1size) << "]";
        std::string reg1str = GetStringValueFromRegister((UINT64)reg1val, reg1size);
        if (!reg1str.empty()) {
            valnum1 = " -> " + GetNumericValue((UINT64)reg1val, reg1size) + " = \"" + reg1str + "\"";
        }
        else
        {
            valnum1 = " -> " + GetNumericValue((UINT64)reg1val, reg1size);
        }
    }

    std::string valnum2 = "";
    std::stringstream val2;
    if (reg2ismem) {
        val2 << " [" << GetNumericHexValue((UINT64)reg2val, 8) << "]";

        if (IsStringPointer((ADDRINT)reg2val)) {
            valnum2 = " -> " + GetNumericValueFromRef(reg2val, reg2size) + " = \"" + std::string(reinterpret_cast<const char*>(reg2val)) + "\"";
        }
        else {
            std::stringstream ss;
            valnum2 = " -> " + GetNumericValueFromRef(reg2val, reg2size);
        }
    }
    else {
        val2 << " [" << GetNumericHexValue((UINT64)reg2val, reg2size) << "]";
        std::string reg2str = GetStringValueFromRegister((UINT64)reg2val, reg2size);
        if (!reg2str.empty()) {
            valnum2 = " -> " + GetNumericValue((UINT64)reg2val, reg2size) + " = \"" + reg2str + "\"";
        }
        else 
        {
            valnum2 = " -> " + GetNumericValue((UINT64)reg2val, reg2size);
        }
    }

    PIN_MutexLock(&fileOutMutex);
    out << *str << " | [T" << std::dec << threadid << std::hex << "] "
        << *reg1str << val1.str() << valnum1 << ", "
        << *reg2str << val2.str() << valnum2 << ", "
        << *reg3str << " = " << reg3val << std::endl;

    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::AddEmitCmp(INS ins, IPOINT point, std::string& traceString, REG reg3val) {
    // Instrumenta a instrução CMP
    if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
        // CMP com dois registradores
        REG reg1 = INS_OperandReg(ins, 0);
        REG reg2 = INS_OperandReg(ins, 1);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitCmpValues,
            IARG_ADDRINT, INS_Address(ins),
            IARG_THREAD_ID, 
            IARG_PTR, new std::string(traceString),
            IARG_PTR, new std::string(REG_StringShort(reg1)),
            IARG_BOOL, false,
            IARG_ADDRINT, REG_Size(reg1),
            IARG_REG_VALUE, reg1,
            IARG_PTR, new std::string(REG_StringShort(reg2)),
            IARG_BOOL, false,
            IARG_ADDRINT, REG_Size(reg2),
            IARG_REG_VALUE, reg2,
            IARG_PTR, new std::string(REG_StringShort(reg3val)),
            IARG_REG_VALUE, reg3val,
            IARG_END);
    }
    else if (INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1)) {
        // CMP entre registrador e memória
        REG reg1 = INS_OperandReg(ins, 0);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitCmpValues,
            IARG_ADDRINT, INS_Address(ins),
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_PTR, new std::string(REG_StringShort(reg1)),
            IARG_BOOL, false,
            IARG_ADDRINT, REG_Size(reg1),
            IARG_REG_VALUE, reg1,
            IARG_PTR, new std::string("memval"),
            IARG_BOOL, true,
            IARG_MEMORYREAD_SIZE,
            IARG_MEMORYREAD_EA,
            IARG_PTR, new std::string(REG_StringShort(reg3val)),
            IARG_REG_VALUE, reg3val,
            IARG_END);
    }
    else if (INS_OperandIsMemory(ins, 0) && INS_OperandIsReg(ins, 1)) {
        // CMP entre memória e registrador
        REG reg2 = INS_OperandReg(ins, 1);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitCmpValues,
            IARG_ADDRINT, INS_Address(ins),
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_PTR, new std::string("memval"),
            IARG_BOOL, true,
            IARG_MEMORYREAD_SIZE,
            IARG_MEMORYREAD_EA,
            IARG_PTR, new std::string(REG_StringShort(reg2)),
            IARG_BOOL, false,
            IARG_ADDRINT, REG_Size(reg2),
            IARG_REG_VALUE, reg2,
            IARG_PTR, new std::string(REG_StringShort(reg3val)),
            IARG_REG_VALUE, reg3val,
            IARG_END);
    }
    else if (INS_OperandIsImmediate(ins, 1)) {
        // CMP entre registrador/memória e imediato
        if (INS_OperandIsReg(ins, 0)) {
            REG reg1 = INS_OperandReg(ins, 0);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitCmpValues,
                IARG_ADDRINT, INS_Address(ins),
                IARG_THREAD_ID,
                IARG_PTR, new std::string(traceString),
                IARG_PTR, new std::string(REG_StringShort(reg1)),
                IARG_BOOL, false,
                IARG_ADDRINT, REG_Size(reg1),
                IARG_REG_VALUE, reg1,
                IARG_PTR, new std::string("immval"),
                IARG_BOOL, false,
                IARG_ADDRINT, (INS_OperandWidth(ins, 1) / 8),
                IARG_ADDRINT, INS_OperandImmediate(ins, 1),
                IARG_PTR, new std::string(REG_StringShort(reg3val)),
                IARG_REG_VALUE, reg3val,
                IARG_END);
        }
        else if (INS_OperandIsMemory(ins, 0)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitCmpValues,
                IARG_ADDRINT, INS_Address(ins),
                IARG_THREAD_ID,
                IARG_PTR, new std::string(traceString),
                IARG_PTR, new std::string("memval"),
                IARG_BOOL, true,
                IARG_MEMORYREAD_SIZE,
                IARG_MEMORYREAD_EA,
                IARG_PTR, new std::string("immval"),
                IARG_BOOL, false,
                IARG_ADDRINT, (INS_OperandWidth(ins, 1) / 8),
                IARG_ADDRINT, INS_OperandImmediate(ins, 1),
                IARG_PTR, new std::string(REG_StringShort(reg3val)),
                IARG_REG_VALUE, reg3val,
                IARG_END);
        }
    }
}

VOID TraceInstructions::EmitMovValue(ADDRINT addr, THREADID threadid, std::string* str, REG dstReg, ADDRINT value, UINT32 movSize) {
    if (!Emit(threadid)) return;
    PIN_MutexLock(&fileOutMutex);
    std::string strVal = GetStringValueFromRegister(value, movSize);
    std::string strValOut;
    if (!strVal.empty()) {
        strValOut = " -> \"" + strVal + "\"";
    }
    out << *str << " | [T" << std::dec << threadid << std::hex << "] "
        << REG_StringShort(dstReg) << " = " << std::hex << value 
        << " (" << std::dec << value << ")" << strValOut << "\n";
    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}


VOID TraceInstructions::AddEmitMov(INS ins, IPOINT point, std::string& traceString) {
    UINT32 movSize = 0;

    if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
        // Caso 1: mov reg, reg
        REG dst = INS_OperandReg(ins, 0);
        REG src = INS_OperandReg(ins, 1);
        movSize = REG_Size(dst);

        INS_InsertCall(ins, point, (AFUNPTR)EmitMovValue,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_UINT32, dst,
            IARG_REG_VALUE, src,
            IARG_UINT32, movSize,
            IARG_END);
    }
    else if (INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
        // Caso 2: mov reg, imediato
        REG dst = INS_OperandReg(ins, 0);
        ADDRINT imm = INS_OperandImmediate(ins, 1);
        movSize = REG_Size(dst);

        INS_InsertCall(ins, point, (AFUNPTR)EmitMovValue,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_UINT32, dst,
            IARG_ADDRINT, imm,
            IARG_UINT32, movSize,
            IARG_END);
    }
    else if (INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1)) {
        // Caso 3: mov reg, [mem]
        REG dst = INS_OperandReg(ins, 0);
        movSize = INS_MemoryReadSize(ins);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitMovValue,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_UINT32, dst,
            IARG_MEMORYREAD_EA,
            IARG_UINT32, movSize,
            IARG_END);
    }
    else if (INS_OperandIsMemory(ins, 0) && INS_OperandIsReg(ins, 1)) {
        // Caso 4: mov [mem], reg
        REG src = INS_OperandReg(ins, 1);
        movSize = INS_MemoryWriteSize(ins);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitMovValue,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_MEMORYWRITE_EA,
            IARG_UINT32, src,
            IARG_UINT32, movSize,
            IARG_END);
    }
    else if (INS_OperandIsMemory(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
        // Caso 5: mov [mem], imediato
        ADDRINT imm = INS_OperandImmediate(ins, 1);
        movSize = INS_MemoryWriteSize(ins);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitMovValue,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_MEMORYWRITE_EA,
            IARG_ADDRINT, imm,
            IARG_UINT32, movSize,
            IARG_END);
    }
}

VOID TraceInstructions::AddEmit(INS ins, IPOINT point, std::string& traceString, UINT32 regCount, REG regs[]) {
    if (regCount > MaxEmitArgs) regCount = MaxEmitArgs;
    IARGLIST args = IARGLIST_Alloc();
    for (UINT32 i = 0; i < regCount; i++) {
        IARGLIST_AddArguments(args, IARG_PTR, new std::string(REG_StringShort(regs[i])), IARG_REG_VALUE, regs[i], IARG_END);
    }
    
    std::string mnemonic = INS_Mnemonic(ins);
    if (INS_Opcode(ins) == XED_ICLASS_CMP || mnemonic.rfind("CMOV", 0) == 0) {
        AddEmitCmp(ins, point, traceString, regs[0]);
    }
    else if (INS_Opcode(ins) == XED_ICLASS_MOV ||
        INS_Opcode(ins) == XED_ICLASS_MOVZX ||
        INS_Opcode(ins) == XED_ICLASS_MOVSX) 
    {
        AddEmitMov(ins, point, traceString);
    }
    else {
        INS_InsertCall(ins, point, emitFuns[regCount], IARG_THREAD_ID, IARG_PTR, new std::string(traceString), IARG_IARGLIST, args, IARG_END);
    }
    IARGLIST_Free(args);
}

static VOID* WriteEa[PIN_MAX_THREADS];

VOID TraceInstructions::CaptureWriteEa(THREADID threadid, VOID* addr) {
    WriteEa[threadid] = addr;
}

VOID TraceInstructions::ShowN(UINT32 n, VOID* ea)
{
    out.unsetf(ios::showbase);
    // Print out the bytes in "big endian even though they are in memory little endian.
    // This is most natural for 8B and 16B quantities that show up most frequently.
    // The address pointed to
    out << std::setfill('0');
    UINT8 b[512];
    UINT8* x;
    if (n > 512)
        x = new UINT8[n];
    else
        x = b;
    PIN_SafeCopy(x, static_cast<UINT8*>(ea), n);
    for (UINT32 i = 0; i < n; i++)
    {
        out << std::setw(2) << static_cast<UINT32>(x[n - i - 1]);
        if (((reinterpret_cast<ADDRINT>(ea) + n - i - 1) & 0x3) == 0 && i < n - 1) out << "_";
    }
    out << std::setfill(' ');
    out.setf(ios::showbase);
    if (n > 512) delete[] x;
}



VOID TraceInstructions::EmitWrite(ADDRINT addr, THREADID threadid, std::string * str, UINT32 size)
{
    if (!Emit(threadid)) return;


    VOID* ea = WriteEa[threadid];

    if (!KnobTraceMemoryInstructions) return;

    PIN_MutexLock(&fileOutMutex);

    out << "                                 Write ";

    switch (size)
    {
    case 0:
        out << "0 repeat count" << endl;
        break;

    case 1:
    {
        UINT8 x;
        PIN_SafeCopy(&x, static_cast<UINT8*>(ea), 1);
        out << "*(UINT8*)" << ea << " = " << static_cast<UINT32>(x) << endl;
    }
    break;

    case 2:
    {
        UINT16 x;
        PIN_SafeCopy(&x, static_cast<UINT16*>(ea), 2);
        out << "*(UINT16*)" << ea << " = " << x << endl;
    }
    break;

    case 4:
    {
        UINT32 x;
        PIN_SafeCopy(&x, static_cast<UINT32*>(ea), 4);
        out << "*(UINT32*)" << ea << " = " << x << endl;
    }
    break;

    case 8:
    {
        UINT64 x;
        PIN_SafeCopy(&x, static_cast<UINT64*>(ea), 8);
        out << "*(UINT64*)" << ea << " = " << x << endl;
    }
    break;

    default:
        out << "*(UINT" << dec << size * 8 << hex << ")" << ea << " = ";
        ShowN(size, ea);
        out << endl;
        break;
    }

    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::EmitRead(ADDRINT addr, THREADID threadid, std::string* str, VOID* ea, UINT32 size)
{
    if (!Emit(threadid)) return;

    if (!KnobTraceMemoryInstructions) return;

    PIN_MutexLock(&fileOutMutex);

    out << "                                 Read ";

    switch (size)
    {
    case 0:
        out << "0 repeat count" << endl;
        break;

    case 1:
    {
        UINT8 x;
        PIN_SafeCopy(&x, static_cast<UINT8*>(ea), 1);
        out << static_cast<UINT32>(x) << " = *(UINT8*)" << ea << endl;
    }
    break;

    case 2:
    {
        UINT16 x;
        PIN_SafeCopy(&x, static_cast<UINT16*>(ea), 2);
        out << x << " = *(UINT16*)" << ea << endl;
    }
    break;

    case 4:
    {
        UINT32 x;
        PIN_SafeCopy(&x, static_cast<UINT32*>(ea), 4);
        out << x << " = *(UINT32*)" << ea << endl;
    }
    break;

    case 8:
    {
        UINT64 x;
        PIN_SafeCopy(&x, static_cast<UINT64*>(ea), 8);
        out << x << " = *(UINT64*)" << ea << endl;
    }
    break;

    default:
        ShowN(size, ea);
        out << " = *(UINT" << dec << size * 8 << hex << ")" << ea << endl;
        break;
    }

    Flush();
    PIN_MutexUnlock(&fileOutMutex);

}

static INT32 indent = 0;

VOID TraceInstructions::Indent()
{
    for (INT32 i = 0; i < indent; i++)
    {
        out << "| ";
    }
}

VOID TraceInstructions::EmitICount()
{ 
    out << setw(10) << dec << icount.Count() << hex << " "; 
}

VOID TraceInstructions::EmitDirectCall(THREADID threadid, ADDRINT instAddress, string* str, INT32 tailCall, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
    if (!Emit(threadid)) return;

    EmitICount();

    if (tailCall)
    {
        // A tail call is like an implicit return followed by an immediate call
        indent--;
    }
    else
    {
        callStack.push(instAddress);
    }

    PIN_MutexLock(&fileOutMutex);
    Indent();

    out << *str << " [T" << threadid << "] (" << arg0 << ", " << arg1 << ", " << arg2 << ", " << arg3 << ", " << arg4 << ", " << arg5 << ", " << arg6 << ", ...)" << endl;

    indent++;

    Flush();
    PIN_MutexUnlock(&fileOutMutex);

}

VOID TraceInstructions::EmitIndirectCall(THREADID threadid, ADDRINT instAddress, string* str, ADDRINT target, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
    if (!Emit(threadid)) return;

    if (target == 0) return;

    callStack.push(instAddress);

    PIN_MutexLock(&fileOutMutex);
    EmitICount();
    Indent();
    out << *str;

    PIN_LockClient();

    string s = FormatAddress(target, RTN_FindByAddress(target), KnobSymbols, KnobFullImgName, KnobLines);

    PIN_UnlockClient();
    
    out << s << " [T" << threadid << "] (" << arg0 << ", " << arg1 << ", " << arg2 << ", " << arg3 << ", " << arg4 << ", " << arg5 << ", " << arg6 << ", ...)" << endl;
    indent++;

    Flush();
    PIN_MutexUnlock(&fileOutMutex);
}

VOID TraceInstructions::EmitReturn(THREADID threadid, ADDRINT instAddress, string* str, ADDRINT retAddr, ADDRINT ret0)
{
    if (!Emit(threadid)) return;

    if (retAddr == 0) return;

    PIN_MutexLock(&fileOutMutex);

    EmitICount();
    indent--;
    if (indent < 0)
    {
        out << "@@@ return underflow\n";
        indent = 0;
    }

    Indent();

    ADDRINT callAddr = 0;
    if (!callStack.empty()) {
        callAddr = callStack.top();
        callStack.pop(); 
    }

    out << *str << " [T" << threadid << "] returns: " << ret0 << ", ret addr: " << retAddr << ", call addr: " << callAddr << endl;

    Flush();
    PIN_MutexUnlock(&fileOutMutex);

}

VOID TraceInstructions::CallTrace(TRACE trace, INS ins)
{
    if (!KnobTraceCalls) return;

    if (KnobTraceOnlyMain && !IsMainExecutable(INS_Address(ins))) return;

    if (INS_IsCall(ins) && !INS_IsDirectControlFlow(ins))
    {
        // Indirect call
        string s = "Call " + FormatAddress(INS_Address(ins), RTN_FindByAddress(INS_Address(ins)), KnobSymbols, KnobFullImgName, KnobLines);
        s += " -> ";

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitIndirectCall), IARG_THREAD_ID, IARG_INST_PTR, IARG_PTR, new string(s),
            IARG_BRANCH_TARGET_ADDR, IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_FUNCARG_CALLSITE_VALUE, 1, IARG_FUNCARG_CALLSITE_VALUE, 2, IARG_FUNCARG_CALLSITE_VALUE, 3, IARG_FUNCARG_CALLSITE_VALUE, 4, IARG_FUNCARG_CALLSITE_VALUE, 5, IARG_FUNCARG_CALLSITE_VALUE, 6, IARG_END);
    }
    else if (INS_IsDirectControlFlow(ins))
    {
        PIN_LockClient();
        // Is this a tail call?
        RTN sourceRtn = TRACE_Rtn(trace);
        RTN destRtn = RTN_FindByAddress(INS_DirectControlFlowTargetAddress(ins));
        PIN_UnlockClient();

        if (INS_IsCall(ins)         // conventional call
            || sourceRtn != destRtn // tail call
            )
        {
            BOOL tailcall = !INS_IsCall(ins);

            string s = "";
            if (tailcall)
            {
                s += "Tailcall ";
            }
            else
            {
                if (INS_IsProcedureCall(ins))
                    s += "Call ";
                else
                {
                    s += "PcMaterialization ";
                    tailcall = 1;
                }
            }

            //s += INS_Mnemonic(ins) + " ";

            s += FormatAddress(INS_Address(ins), RTN_FindByAddress(INS_Address(ins)), KnobSymbols, KnobFullImgName, KnobLines);
            s += " -> ";

            ADDRINT target = INS_DirectControlFlowTargetAddress(ins);

            PIN_LockClient();
            s += FormatAddress(target, RTN_FindByAddress(target), KnobSymbols, KnobFullImgName, KnobLines);
            PIN_UnlockClient();

            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitDirectCall), IARG_THREAD_ID, IARG_INST_PTR, IARG_PTR, new string(s), IARG_BOOL,
                tailcall, IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_FUNCARG_CALLSITE_VALUE, 1, IARG_FUNCARG_CALLSITE_VALUE, 2, IARG_FUNCARG_CALLSITE_VALUE, 3, IARG_FUNCARG_CALLSITE_VALUE, 4, IARG_FUNCARG_CALLSITE_VALUE, 5, IARG_FUNCARG_CALLSITE_VALUE, 6, IARG_END);
        }
    }
    else if (INS_IsRet(ins))
    {
        RTN rtn = TRACE_Rtn(trace);

#if defined(TARGET_LINUX) && defined(TARGET_IA32)
        //        if( RTN_Name(rtn) ==  "_dl_debug_state") return;
        if (RTN_Valid(rtn) && RTN_Name(rtn) == "_dl_runtime_resolve") return;
#endif
        string tracestring = "Return " + FormatAddress(INS_Address(ins), rtn, KnobSymbols, KnobFullImgName, KnobLines);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitReturn), IARG_THREAD_ID, IARG_INST_PTR, IARG_PTR, new string(tracestring),
            IARG_RETURN_IP, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }
}

VOID TraceInstructions::InstructionTrace(TRACE trace, INS ins)
{
    ADDRINT addr = INS_Address(ins);
    ASSERTX(addr);

    // Format the string at instrumentation time
    string traceString = "";
    string astring = FormatAddress(INS_Address(ins), RTN_FindByAddress(INS_Address(ins)), KnobSymbols, KnobFullImgName, KnobLines);
    for (INT32 length = astring.length(); length < 95; length++)
    {
        traceString += " ";
    }
    traceString = astring + traceString;

    traceString += " " + INS_Disassemble(ins);

    for (INT32 length = traceString.length(); length < 140; length++)
    {
        traceString += " ";
    }

    INT32 regCount = 0;
    REG regs[20];
    REG xmm_dst = REG_INVALID();

    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++)
    {
        REG x = REG_FullRegName(INS_RegW(ins, i));

        if (REG_is_gr(x)
#if defined(TARGET_IA32)
            || x == REG_EFLAGS
#elif defined(TARGET_IA32E)
            || x == REG_RFLAGS
#endif
            )
        {
            regs[regCount] = x;
            regCount++;
        }

        if (REG_is_xmm(x)) xmm_dst = x;
    }

    if (INS_IsValidForIpointAfter(ins))
    {
        AddEmit(ins, IPOINT_AFTER, traceString, regCount, regs);
    }
    if (INS_IsValidForIpointTakenBranch(ins))
    {
        AddEmit(ins, IPOINT_TAKEN_BRANCH, traceString, regCount, regs);
    }

    if (xmm_dst != REG_INVALID())
    {
        if (INS_IsValidForIpointAfter(ins)) AddXMMEmit(ins, IPOINT_AFTER, xmm_dst);
        if (INS_IsValidForIpointTakenBranch(ins)) AddXMMEmit(ins, IPOINT_TAKEN_BRANCH, xmm_dst);
    }
}


VOID TraceInstructions::Trace(TRACE trace, VOID* v)
{
    if (!filter.SelectTrace(trace)) return;

    if (enabled)
    {
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
            for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
            {

                InstructionTrace(trace, ins);

                CallTrace(trace, ins);

            }
        }
    }
}


static void TraceInstructions::OnSig(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom, CONTEXT* ctxtTo, INT32 sig, VOID* v)
{
    PIN_MutexLock(&fileOutMutex);

    if (ctxtFrom != 0)
    {
        ADDRINT address = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
        out << "SIG signal=" << sig << " on thread " << threadIndex << " at address " << hex << address << dec << " ";
    }

    switch (reason)
    {
    case CONTEXT_CHANGE_REASON_FATALSIGNAL:
        out << "FATALSIG" << sig;
        break;
    case CONTEXT_CHANGE_REASON_SIGNAL:
        out << "SIGNAL " << sig;
        break;
    case CONTEXT_CHANGE_REASON_SIGRETURN:
        out << "SIGRET";
        break;

    case CONTEXT_CHANGE_REASON_APC:
        out << "APC";
        break;

    case CONTEXT_CHANGE_REASON_EXCEPTION:
        out << "EXCEPTION";
        break;

    case CONTEXT_CHANGE_REASON_CALLBACK:
        out << "CALLBACK";
        break;

    default:
        break;
    }
    out << std::endl;
    PIN_MutexUnlock(&fileOutMutex);

}

static CONTROL_MANAGER control;
static SKIPPER skipper;

void TraceInstructions::enable() {
    TraceInstructions::enabled = 1;
}
void TraceInstructions::disable() {
    TraceInstructions::enabled = 0;
}

int TraceInstructions::InitTrace(string pid, std::string filename)
{
    filename += "." + pid + ".trace.cdf";
    out.open(filename.c_str());
    out << hex << right;
    out.setf(ios::showbase);
    out.rdbuf()->pubsetbuf(&buffer[0], bufferSize);

    control.RegisterHandler(Handler, 0, FALSE);
    control.Activate();
    skipper.CheckKnobs(0);

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddContextChangeFunction(OnSig, 0);


    filter.Activate();
    icount.Activate();

    return 0;
}

