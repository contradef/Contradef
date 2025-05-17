#pragma once
#ifndef NOTIFIER_H
#define NOTIFIER_H

#include "Observer.h"
#include <vector>

class Notifier {
    std::vector<Observer*> observers;

public:
    void Attach(Observer* observer) {
        observers.push_back(observer);
    }

    void Detach(Observer* observer) {
        // Implementa��o simplificada da remo��o
        observers.erase(std::remove(observers.begin(), observers.end(), observer), observers.end());
    }

    void NotifyAll(const EventData* data) {
        for (auto& observer : observers) {
            observer->Notify(data);
        }
    }
};

#endif // NOTIFIER_H
