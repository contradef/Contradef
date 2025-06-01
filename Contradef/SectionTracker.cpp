// SectionTracker.cpp
#include "SectionTracker.h"
#include <iomanip>
#include "EventData.h"
#include "Notifier.h"

namespace SectionTracker {

    std::vector<SectionInfo> knownSections;
    Notifier* globalNotifierPtr;

    VOID GetSectionInfo(IMG img)
    {
        std::stringstream out;

        out << std::endl << "[+] Informação de seções..." << std::endl;
        out << "    Nome da imagem: " << std::string(IMG_Name(img)) << std::endl;

        int index = 0;
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), ++index)
        {
            std::string secName = SEC_Name(sec);
            secName = secName.empty() ? "[VAZIO]" : secName;
            ADDRINT secAddr = SEC_Address(sec);
            UINT64 secSize = SEC_Size(sec);

            out << "    Seção [" << index << "]" << std::endl;
            out << "        Nome da seção: " << secName << std::endl;
            out << "        Endereço: 0x" << std::hex << static_cast<uint64_t>(secAddr) << std::dec << std::endl;
            out << "        Tamanho: " << static_cast<uint64_t>(secSize) << " bytes" << std::endl;

            out << "        Características: " << std::endl;
            if (SEC_IsExecutable(sec))
            {
                out << "            A seção é executável." << std::endl;
            }
            if (SEC_IsReadable(sec))
            {
                out << "            A seção é legível." << std::endl;
            }
            if (SEC_IsWriteable(sec))
            {
                out << "            A seção é gravável." << std::endl;
            }

            SectionInfo info;
            info.name = secName;
            info.base = secAddr;
            info.size = secSize;

            knownSections.push_back(info);
        }

        out << "[*] Concluído" << std::endl << std::endl;
        out.flush();

        ExecutionInformation executionCompletedInfo = { out.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);
    }

    VOID ImageLoad(IMG img, VOID* v)
    {
        if (IMG_IsMainExecutable(img))
        {
            GetSectionInfo(img);
        }
    }

    BOOL IsInKnownSection(ADDRINT addr)
    {
        for (const auto& sec : knownSections)
        {
            if (addr >= sec.base && addr < sec.base + sec.size)
                return TRUE;
        }
        return FALSE;
    }

    VOID Init(VOID* globalNotifier)
    {
        globalNotifierPtr = reinterpret_cast<Notifier*>(globalNotifier);
        IMG_AddInstrumentFunction(ImageLoad, 0);
    }

} // namespace SectionTracker
