// SectionTracker.h
#pragma once

#include "pin.H"
#include <string>
#include <vector>
#include <fstream>

namespace SectionTracker {

    struct SectionInfo {
        std::string name;
        ADDRINT base;
        UINT64 size;
    };

    // Inicializa o rastreador de seções (registra ImageLoad)
    VOID Init(VOID* globalNotifier);

    // Verifica se um endereço pertence a uma seção conhecida
    BOOL IsInKnownSection(ADDRINT addr);

    // Extrai informações sobre seções e registra no arquivo
    VOID GetSectionInfo(IMG img);

} // namespace SectionTracker
