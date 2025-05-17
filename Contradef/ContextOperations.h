#pragma once

#ifndef CONTEXT_OPERATIONS_H
#define CONTEXT_OPERATIONS_H

#include "pin.H"
#include <iostream>
#include <string>
#include "regvalue_utils.h"
#include "Utils.h"
#include "InstructionSequenceDetector.h"

static void PrintRegisters(CONTEXT* ctxt);
VOID SetZfToOne(CONTEXT* ctxt);
VOID SetZfToZero(CONTEXT* ctxt);
void JumpToAddress(CONTEXT* ctxt, ADDRINT destAddr);

#endif // CONTEXT_OPERATIONS_H