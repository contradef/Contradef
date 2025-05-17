#pragma once
#ifndef INSTRUMENTATION_STRATEGY_H
#define INSTRUMENTATION_STRATEGY_H

#include "pin.H"

class InstrumentationStrategy {
public:
    virtual void InstrumentFunction(RTN rtn) = 0;
    virtual ~InstrumentationStrategy() {}
};

#endif // INSTRUMENTATION_STRATEGY_H
