// Este módulo serve para mapear os endereçõs de head da aplicação, para os casos em que código asm é descompactado e executado no heap. Vai ajudar a determinar quando o código pertence à imagem principal 
#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <sstream>
#include "HeapTracker.h"

namespace HeapTracker {

    std::vector<HeapRegion> trackedAllocations;
    PIN_MUTEX heapTrackMutex;

    VOID RecordMalloc(ADDRINT addr, size_t size)
    {
        if (addr == 0 || size == 0) return;
        PIN_MutexLock(&heapTrackMutex);
        trackedAllocations.push_back({ addr, size });
        PIN_MutexUnlock(&heapTrackMutex);
    }

    VOID RecordHeapAlloc(ADDRINT hHeap, ADDRINT addr, size_t size)
    {
        if (addr == 0 || hHeap == 0 || size == 0) return;
        PIN_MutexLock(&heapTrackMutex);
        trackedAllocations.push_back({ addr, size });
        PIN_MutexUnlock(&heapTrackMutex);
    }

    VOID RecordRtlAllocateHeap(ADDRINT hHeap, ADDRINT addr, size_t size)
    {
        if (addr == 0 || hHeap == 0 || size == 0) return;
        PIN_MutexLock(&heapTrackMutex);
        trackedAllocations.push_back({ addr, size });
        PIN_MutexUnlock(&heapTrackMutex);
    }

    BOOL IsInTrackedHeap(ADDRINT addr)
    {
        PIN_MutexLock(&heapTrackMutex);
        for (const auto& region : trackedAllocations) {
            if (addr >= region.base && addr < region.base + region.size) {
                PIN_MutexUnlock(&heapTrackMutex);
                return TRUE;
            }
        }
        PIN_MutexUnlock(&heapTrackMutex);
        return FALSE;
    }

    VOID AfterMalloc(ADDRINT ret, size_t size) {
        RecordMalloc(ret, size);
    }

    VOID AfterHeapAlloc(ADDRINT ret, ADDRINT hHeap, size_t size) {
        RecordHeapAlloc(hHeap, ret, size);
    }

    VOID AfterRtlAllocateHeap(ADDRINT ret, ADDRINT hHeap, size_t size) {
        RecordRtlAllocateHeap(hHeap, ret, size);
    }

    VOID ImageLoad(IMG img, VOID* v)
    {
        RTN mallocRtn = RTN_FindByName(img, "malloc");
        if (RTN_Valid(mallocRtn)) {
            RTN_Open(mallocRtn);
            RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)AfterMalloc,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_END);
            RTN_Close(mallocRtn);
        }

        RTN heapAllocRtn = RTN_FindByName(img, "HeapAlloc");
        if (RTN_Valid(heapAllocRtn)) {
            RTN_Open(heapAllocRtn);
            RTN_InsertCall(heapAllocRtn, IPOINT_AFTER, (AFUNPTR)AfterHeapAlloc,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_END);
            RTN_Close(heapAllocRtn);
        }

        RTN rtlAllocRtn = RTN_FindByName(img, "RtlAllocateHeap");
        if (RTN_Valid(rtlAllocRtn)) {
            RTN_Open(rtlAllocRtn);
            RTN_InsertCall(rtlAllocRtn, IPOINT_AFTER, (AFUNPTR)AfterRtlAllocateHeap,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_END);
            RTN_Close(rtlAllocRtn);
        }
    }

    VOID Init()
    {
        PIN_MutexInit(&heapTrackMutex);
        IMG_AddInstrumentFunction(ImageLoad, 0);
    }

} // namespace HeapTracker
