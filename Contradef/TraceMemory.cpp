

#include "TraceMemory.h"

std::ofstream TraceMemory::memTraceOut;
// Buffer de 512 KB para memTraceOut
const std::size_t TraceMemory::bufferSize = 512 * 1024;
std::vector<char> TraceMemory::buffer(bufferSize);  // o buffer precisa durar enquanto o ofstream estiver aberto

PIN_MUTEX TraceMemory::fileMemTraceOutMutex;

VOID* WriteEa[PIN_MAX_THREADS];

VOID TraceMemory::CaptureWriteEa(THREADID threadid, VOID* addr) {
    WriteEa[threadid] = addr;
}
VOID TraceMemory::WriteMemTraceOut(THREADID threadid, std::string* str, VOID* ea, UINT32 size)
{
    ADDRINT address = reinterpret_cast<ADDRINT>(ea);
    std::string opval;
    std::stringstream hexval;
    hexval << GetNumericHexValue((UINT64)ea, 8);

    if (PIN_CheckReadAccess(ea))
    {
        std::string asciiStr = CopyLPCSTR(address);
        if (IsValidString(asciiStr)) {
            opval = GetNumericValueFromRef(ea, size) + " -> \"" + asciiStr + "\"";
        }
        else {
            std::wstring wideStr = CopyLPCWSTR(address);
            if (IsValidWideString(wideStr)) {
                opval = GetNumericValueFromRef(ea, size) + " -> \"" + WStringToString(wideStr) + "\"";
            }
            else if (IsStringPointer(address)) {
                opval = GetNumericValueFromRef(ea, size) + " -> \"" + std::string(reinterpret_cast<const char*>(ea)) + "\"";
            }
            else {
                opval = GetNumericValueFromRef(ea, size);
            }
        }
    }
    else {
        opval = " -> \"" + InterpretAddrIntAsASCII(address) + "\"";
    }

    PIN_MutexLock(&fileMemTraceOutMutex);
    memTraceOut
        << "[T" << std::dec << threadid << std::hex << "] "
        << *str << "        [" << hexval.str() << "] = "
        << opval << "\n"
        << std::string(133, '-') << "\n";
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
        }
        if (INS_IsValidForIpointTakenBranch(ins))
        {
            ipoint = IPOINT_TAKEN_BRANCH;
        }

        if (ipoint != LEVEL_VM::IPOINT::IPOINT_INVALID) {
            INS_InsertCall(ins, ipoint, AFUNPTR(EmitWrite),
                IARG_ADDRINT, INS_Address(ins),
                IARG_THREAD_ID,
                IARG_PTR, new std::string(traceString),
                IARG_MEMORYWRITE_SIZE,
                IARG_END);
        }
    }

    if (INS_HasMemoryRead2(ins)) // && INS_IsStandardMemop(ins)
    {
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
    memTraceOut.rdbuf()->pubsetbuf(&buffer[0], bufferSize);

    INS_AddInstrumentFunction(InstTraceMemory, 0);

    return 0;
}