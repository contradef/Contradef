#pragma once
#ifndef INSTRUMENTATION_UTILS_H
#define INSTRUMENTATION_UTILS_H

#include "pin.H"
#include <iostream>

BOOL IsMainExecutable(ADDRINT address);
ADDRINT GetRtnAddr(ADDRINT instAddress);
VOID PauseAtAddress(ADDRINT address);
std::string FormatAddress(ADDRINT address, RTN rtn, BOOL showSymbols = true, BOOL showFullImgName = false, BOOL showLines = true);

#endif // INSTRUMENTATION_UTILS_H