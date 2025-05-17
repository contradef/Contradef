#pragma once

#include <iostream>
#include <fstream>
#include <cctype>
#include <string>
#include "utils.h"
#include "FunctionInterceptor.h"

namespace WindowsAPI
{
    #include <Windows.h>
    #include <unistd.h>
}

namespace YaraAPI
{
    using namespace WindowsAPI;
    #include "yaracdef.h"
}

int RunYara(std::string _rules_file, std::string _target_file, std::ofstream& OutFile, std::vector<std::string>& matched);