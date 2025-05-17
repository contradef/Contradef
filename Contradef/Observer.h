#pragma once
#ifndef OBSERVER_H
#define OBSERVER_H

#include "EventData.h"

// Definição de ponteiro para função de callback
typedef void (*EventCallback)(const EventData*, void*);

class Observer {
public:
    EventCallback callback;
    void* context;

    Observer(EventCallback callback, void* context)
        : callback(callback), context(context) {}

    // Método para atualizar o contexto
    void SetContext(void* ctxt) { context = ctxt; } 

    // Função para invocar o callback
    void Notify(const EventData* data) {
        if (callback) {
            callback(data, context);
        }
    }
};

#endif // OBSERVER_H
