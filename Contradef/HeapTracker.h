#pragma once
#ifndef HEAP_TRACKER_H
#define HEAP_TRACKER_H

#include "pin.H"
#include <map>

namespace HeapTracker {

    struct HeapRegion {
        ADDRINT base;
        size_t size;
    };

    VOID Init();

    BOOL IsInTrackedHeap(ADDRINT addr);

    VOID RecordMalloc(ADDRINT addr, size_t size);
    VOID RecordHeapAlloc(ADDRINT hHeap, ADDRINT addr, size_t size);
    VOID RecordRtlAllocateHeap(ADDRINT hHeap, ADDRINT addr, size_t size);

    VOID AfterMalloc(ADDRINT ret, size_t size);
    VOID AfterHeapAlloc(ADDRINT ret, ADDRINT hHeap, size_t size);
    VOID AfterRtlAllocateHeap(ADDRINT ret, ADDRINT hHeap, size_t size);

    VOID ImageLoad(IMG img, VOID* v);

} 

#endif // HEAP_TRACKER_H