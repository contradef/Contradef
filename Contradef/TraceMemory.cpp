

#include "TraceMemory.h"

KNOB< BOOL > KnobTraceMemory(KNOB_MODE_WRITEONCE, "pintool", "memory", "1", "Trace memory");
KNOB< BOOL > KnobTraceMemoryOnlyStr(KNOB_MODE_WRITEONCE, "pintool", "memory-only-str", "1", "Trace memory");

std::ofstream TraceMemory::memTraceOut;
PIN_MUTEX TraceMemory::fileMemTraceOutMutex;

VOID* WriteEa[PIN_MAX_THREADS];

VOID TraceMemory::CaptureWriteEa(THREADID threadid, VOID* addr) {
    WriteEa[threadid] = addr;
}

VOID TraceMemory::WriteMemTraceOut(THREADID threadid, std::string* str, VOID* ea, UINT32 size)
{
    std::string opval = "";
    std::stringstream hexval;
    hexval << GetNumericHexValue((UINT64)ea, 8);
    ADDRINT address = reinterpret_cast<ADDRINT>(ea);

    if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(ea)))
    {
        std::string str = CopyLPCSTR(address);
        if (IsValidString(str)) {
            opval = GetNumericValueFromRef(ea, size) + " | \"" + str + "\"";
        }
        else {
            std::wstring wstr = CopyLPCWSTR(address);
            if (IsValidWideString(wstr)) {
                opval = GetNumericValueFromRef(ea, size) + " | \"" + WStringToString(wstr) + "\"";
            }
            else {
                if (IsStringPointer(address)) {
                    opval = GetNumericValueFromRef(ea, size) + " | \"" + std::string(reinterpret_cast<const char*>(ea)) + "\"";
                }
                else {
                    std::stringstream ss;
                    opval = GetNumericValueFromRef(ea, size);
                }
            }
        }

    }



    PIN_MutexLock(&fileMemTraceOutMutex);
    memTraceOut << "[T" << std::dec << threadid << std::hex << "] " << *str << "        [" << hexval.str() << "] = " << opval << "\n" << std::string(133, '-') << "\n";
    PIN_MutexUnlock(&fileMemTraceOutMutex);

}

VOID TraceMemory::EmitWrite(ADDRINT addr, THREADID threadid, std::string* str, UINT32 size)
{
    VOID* ea = WriteEa[threadid];

    WriteMemTraceOut(threadid, str, ea, size);
}

VOID TraceMemory::EmitRead(ADDRINT addr, THREADID threadid, std::string* str, VOID* ea, UINT32 size)
{
    WriteMemTraceOut(threadid, str, ea, size);
}


VOID TraceMemory::InstTraceMemory(INS ins, VOID* v)
{
    if (!KnobTraceMemory) return;

    ADDRINT addr = INS_Address(ins);

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(addr)) {
        return;
    }

    // Format the string at instrumentation time
    std::string traceString = "";
    std::string astring = FormatAddress(INS_Address(ins), RTN_FindByAddress(INS_Address(ins)));
    for (INT32 length = astring.length(); length < 30; length++)
    {
        traceString += " ";
    }
    traceString = astring + traceString;

    traceString += " | " + INS_Disassemble(ins);

    if (INS_IsMemoryWrite(ins)) // && INS_IsStandardMemop(ins)
    {
        traceString += " | [Write]: \n";

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(CaptureWriteEa), IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_END);

        LEVEL_VM::IPOINT ipoint = LEVEL_VM::IPOINT::IPOINT_INVALID;
        if (INS_IsValidForIpointAfter(ins))
        {
            ipoint = IPOINT_AFTER;
            //INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(EmitWrite), IARG_THREAD_ID, IARG_MEMORYWRITE_SIZE, IARG_END);
        }
        if (INS_IsValidForIpointTakenBranch(ins))
        {
            ipoint = IPOINT_TAKEN_BRANCH;
            //INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(EmitWrite), IARG_THREAD_ID, IARG_MEMORYWRITE_SIZE, IARG_END);
        }

        if (ipoint != LEVEL_VM::IPOINT::IPOINT_INVALID) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitWrite,
                IARG_ADDRINT, INS_Address(ins),
                IARG_THREAD_ID,
                IARG_PTR, new std::string(traceString),
                IARG_MEMORYWRITE_SIZE,
                IARG_END);
        }
    }

    if (INS_HasMemoryRead2(ins)) // && INS_IsStandardMemop(ins)
    {
        //INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitRead), IARG_THREAD_ID, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
        traceString += " | [Read 2Op]: \n";

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitRead,
            IARG_ADDRINT, INS_Address(ins),
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_MEMORYREAD2_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_END);
    }

    if (INS_IsMemoryRead(ins) && !INS_IsPrefetch(ins)) // && INS_IsStandardMemop(ins)
    {
        //INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitRead), IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
        traceString += " | [Read 1Op]: \n";

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitRead,
            IARG_ADDRINT, INS_Address(ins),
            IARG_THREAD_ID,
            IARG_PTR, new std::string(traceString),
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_END);
    }

}


int TraceMemory::InitMemoryTrace(std::string pid, std::string filename)
{
    filename += "." + pid + ".memtrace.cdf";
    memTraceOut.open(filename.c_str());
    memTraceOut << std::hex << std::right;
    memTraceOut.setf(std::ios_base::showbase);

    INS_AddInstrumentFunction(InstTraceMemory, 0);

    return 0;
}