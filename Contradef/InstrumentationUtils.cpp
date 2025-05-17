#include "InstrumentationUtils.h"
#include "Utils.h"

BOOL IsMainExecutable(ADDRINT address) {
    PIN_LockClient();
    IMG img = IMG_FindByAddress(address);
    if (IMG_Valid(img)) {
        if (IMG_IsMainExecutable(img)) {
            PIN_UnlockClient();
            return TRUE;
        }
    }
    PIN_UnlockClient();
    return FALSE;
}

ADDRINT GetRtnAddr(ADDRINT instAddress) {
    PIN_LockClient();
    RTN rtnCall = RTN_FindByAddress(instAddress);
    ADDRINT rtnAddress = 0;
    if (RTN_Valid(rtnCall)) {
        rtnAddress = RTN_Address(rtnCall);
    }
    PIN_UnlockClient();
    return rtnAddress;
}


VOID PauseAtAddress(ADDRINT address) {
    PIN_LockClient();
    std::cout << "[CONTRADEF] O Contradef pausou no endereço " << std::hex << address << std::endl;
    std::cout << "[CONTRADEF] Anexe o depurador ao processo agora." << std::endl;
    std::cout << "[CONTRADEF] Pressione Enter para continuar a execucao..." << std::endl;

    std::cin.get(); // Aguarda entrada do usuário para continuar
    PIN_UnlockClient();
    PIN_Detach();
}


std::string FormatAddress(ADDRINT address, RTN rtn, BOOL showSymbols, BOOL showFullImgName, BOOL showLines)
{
    std::string s = StringFromAddrint(address);

    if (showSymbols && RTN_Valid(rtn))
    {
        IMG img = SEC_Img(RTN_Sec(rtn));
        s += " ";
        if (IMG_Valid(img))
        {
            if (showFullImgName)
            {
                s += IMG_Name(img) + ":";
            }
            else
            {
                s += getFileName(IMG_Name(img)) + ":";
            }
        }
        else
        {
            s += "UNKNOW-IMG:";
        }

        s += RTN_Name(rtn);

        ADDRINT delta = address - RTN_Address(rtn);
        if (delta != 0)
        {
            s += "+" + hexstr(delta, 4);
        }
    }

    if (showLines)
    {
        INT32 line;
        std::string file;

        PIN_GetSourceLocation(address, NULL, &line, &file);

        if (file != "")
        {
            s += " (" + file + ":" + decstr(line) + ")";
        }
    }
    return s;
}
