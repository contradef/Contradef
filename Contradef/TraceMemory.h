#ifndef TRACE_MEMORY_H
#define TRACE_MEMORY_H

#include <vector>
#include <iostream>
#include <fstream>
#include "utils.h"
#include <unistd.h>
#include "pin.H"
#include "InstrumentationUtils.h"
//#include "Instrumentation.h"
#include "InitParams.h"

namespace TraceMemory {
    extern std::ofstream memTraceOut;
    extern PIN_MUTEX fileMemTraceOutMutex;

    void CaptureWriteEa(THREADID threadid, VOID* addr);
    void WriteMemTraceOut(THREADID threadid, std::string* str, VOID* ea, UINT32 size);
    void EmitWrite(ADDRINT addr, THREADID threadid, std::string* str, UINT32 size);
    void EmitRead(ADDRINT addr, THREADID threadid, std::string* str, VOID* ea, UINT32 size);
    void InstTraceMemory(INS ins, VOID* v);

    int InitMemoryTrace(std::string pid, std::string filename);
}

#endif // TRACE_MEMORY_H