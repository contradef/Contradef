#pragma once
#ifndef EVENTDATA_H
#define EVENTDATA_H

#include <string>
#include <queue>

// Classe base para eventos
class EventData {
public:
    enum EventType { ExecutionCompleted };

    EventType type; // Identificador do tipo de evento

    // Construtor protegido para for�ar o uso apenas em subclasses
protected:
    explicit EventData(EventType type) : type(type) {}

public:
    virtual ~EventData() = default; // Destrutor virtual para heran�a
};

// Evento de trace
struct CallRtnInformation {
    ADDRINT address;
    std::string functionName;
    std::string imgName;
    std::string rtnCallerName;
};

// Evento de finaliza��o de execu��o
struct ExecutionInformation {
    std::string outputText;
};
class ExecutionEventData : public EventData {
public:
    ExecutionInformation executionInformation;

    ExecutionEventData(const ExecutionInformation& iInformation)
        : EventData(ExecutionCompleted), executionInformation(iInformation) {}
};

#endif // EVENTDATA_H
