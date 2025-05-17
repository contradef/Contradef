#include "FunctionInterceptor.h"
#include "Notifier.h"

FunctionInterceptor::FunctionInterceptor() {
    // Contrutor
}

FunctionInterceptor::~FunctionInterceptor() {
    // Não é necessário deletar os ponteiros de função

    scanScope.clear(); // Limpa a memória de scanScope ao destruir o objeto
    strategyMap.clear();  // Limpa o mapa de estratégias
}

bool FunctionInterceptor::IsStringInScanScope(const std::string& scope) const {
    return std::find(scanScope.begin(), scanScope.end(), scope) != scanScope.end();
}

void FunctionInterceptor::InitStrategies() {

    for (const std::string& scope : scanScope) {
        if (scope == "Obsidium") {

            std::cout << "[CONTRADEF] Instrumentando o Obsidium" << std::endl;
            
        }

        if (scope == "Themida") {
            //Estrategias do Themida
            std::cout << "[CONTRADEF] Instrumentando o Themida" << std::endl;
        }

        if (scope == "VM") {
            //Estrategias de virtualização
        }
    }


    strategyMap["VirtualProtect"] = &InstVirtualProtect::InstrumentFunction;
    strategyMap["CreateFileW"] = &InstCreateFileW::InstrumentFunction;
    strategyMap["GetModuleFileNameW"] = &InstGetModuleFileNameW::InstrumentFunction;
    strategyMap["GetModuleHandleA"] = &InstGetModuleHandleA::InstrumentFunction;
    strategyMap["GetModuleHandleW"] = &InstGetModuleHandleA::InstrumentFunction;
    strategyMap["GetTickCount"] = &InstGetTickCount::InstrumentFunction;

    strategyMap["NtQueryInformationProcess"] = &InstNtQueryInformationProcess::InstrumentFunction;
    strategyMap["ZwQueryInformationProcess"] = &InstNtQueryInformationProcess::InstrumentFunction;

    strategyMap["GetCurrentProcess"] = &InstGetCurrentProcess::InstrumentFunction;

    strategyMap["GetCurrentThread"] = &InstGetCurrentThread::InstrumentFunction;
    strategyMap["NtSetInformationThread"] = &InstNtSetInformationThread::InstrumentFunction;
    strategyMap["ZwSetInformationThread"] = &InstNtSetInformationThread::InstrumentFunction;
    strategyMap["RtlGetNativeSystemInformation"] = &InstRtlGetNativeSystemInformation::InstrumentFunction;

    strategyMap["CheckRemoteDebuggerPresent"] = &InstCheckRemoteDebuggerPresent::InstrumentFunction; // <- Falhando, verificar


    //Seq ANTIDBI
    strategyMap["OpenThread"] = &InstOpenThread::InstrumentFunction;
    strategyMap["RtlInstallFunctionTableCallback"] = &InstRtlInstallFunctionTableCallback::InstrumentFunction;
    strategyMap["CreateEventW"] = &InstCreateEventW::InstrumentFunction;
    strategyMap["CreateThread"] = &InstCreateThread::InstrumentFunction;
    strategyMap["WaitForSingleObject"] = &InstWaitForSingleObject::InstrumentFunction;
    strategyMap["SuspendThread"] = &InstSuspendThread::InstrumentFunction;
    strategyMap["GetThreadContext"] = &InstGetThreadContext::InstrumentFunction;
    strategyMap["SetThreadContext"] = &InstSetThreadContext::InstrumentFunction;
    strategyMap["ResumeThread"] = &InstResumeThread::InstrumentFunction;
    strategyMap["SetEvent"] = &InstSetEvent::InstrumentFunction;
    strategyMap["ResetEvent"] = &InstResetEvent::InstrumentFunction;
    strategyMap["RtlAddFunctionTable"] = &InstRtlAddFunctionTable::InstrumentFunction;
    strategyMap["RtlDeleteFunctionTable"] = &InstRtlDeleteFunctionTable::InstrumentFunction;
    //EndSeq

    strategyMap["VirtualAlloc"] = &InstVirtualAlloc::InstrumentFunction;
    strategyMap["VirtualFree"] = &InstVirtualFree::InstrumentFunction;

    strategyMap["ReadFile"] = &InstReadFile::InstrumentFunction;

    strategyMap["GetProcAddress"] = &InstGetProcAddress::InstrumentFunction;
    strategyMap["QueueUserAPC2"] = &InstQueueUserAPC2::InstrumentFunction;
    strategyMap["SleepEx"] = &InstSleepEx::InstrumentFunction;
    strategyMap["RtlAddVectoredExceptionHandler"] = &InstRtlAddVectoredExceptionHandler::InstrumentFunction;
    strategyMap["RaiseException"] = &InstRaiseException::InstrumentFunction;
    strategyMap["RtlRemoveVectoredExceptionHandler"] = &InstRtlRemoveVectoredExceptionHandler::InstrumentFunction;
    strategyMap["GetVersionExW"] = &InstGetVersionExW::InstrumentFunction;
    strategyMap["NtdllDefWindowProc_W"] = &InstNtdllDefWindowProc_W::InstrumentFunction;
    strategyMap["CreateToolhelp32Snapshot"] = &InstCreateToolhelp32Snapshot::InstrumentFunction;
    strategyMap["GetFileSizeEx"] = &InstGetFileSizeEx::InstrumentFunction;
    strategyMap["SetFilePointerEx"] = &InstSetFilePointerEx::InstrumentFunction;
    strategyMap["QueryDosDeviceW"] = &InstQueryDosDeviceW::InstrumentFunction;
    strategyMap["GetSystemFirmwareTable"] = &InstGetSystemFirmwareTable::InstrumentFunction;
    strategyMap["BasepConstructSxsCreateProcessMessage"] = &InstBasepConstructSxsCreateProcessMessage::InstrumentFunction;
    strategyMap["InstGetVolumePathNameW"] = &InstGetVolumePathNameW::InstrumentFunction;
    strategyMap["DeviceIoControl"] = &InstDeviceIoControl::InstrumentFunction;
    strategyMap["RtlQueryPerformanceCounter"] = &InstRtlQueryPerformanceCounter::InstrumentFunction;
    strategyMap["GetCommandLineA"] = &InstGetCommandLineA::InstrumentFunction;
    strategyMap["GetCommandLineW"] = &InstGetCommandLineW::InstrumentFunction;
    strategyMap["GetComputerNameA"] = &InstGetComputerNameA::InstrumentFunction;
    strategyMap["LCMapStringEx"] = &InstLCMapStringEx::InstrumentFunction;
    strategyMap["NtQuerySystemInformation"] = &InstNtQuerySystemInformation::InstrumentFunction;
    strategyMap["ZwQuerySystemInformation"] = &InstNtQuerySystemInformation::InstrumentFunction;
    strategyMap["NtQuerySystemInformationEx"] = &InstNtQuerySystemInformationEx::InstrumentFunction;
    strategyMap["ZwQuerySystemInformationEx"] = &InstNtQuerySystemInformationEx::InstrumentFunction;
    strategyMap["RtlGetNativeSystemInformation"] = &InstRtlGetNativeSystemInformation::InstrumentFunction;
    strategyMap["GetEnvironmentStringsW"] = &InstGetEnvironmentStringsW::InstrumentFunction;
    strategyMap["GetEnvironmentVariableW"] = &InstGetEnvironmentVariableW::InstrumentFunction;
    strategyMap["WriteFile"] = &InstWriteFile::InstrumentFunction;
    strategyMap["CompareStringEx"] = &InstCompareStringEx::InstrumentFunction;


    strategyMap["lstrcpynA"] = &InstLstrcpynA::InstrumentFunction;
    strategyMap["lstrcpy"] = &InstLstrcpy::InstrumentFunction;
    strategyMap["WriteConsoleW"] = &InstWriteConsoleW::InstrumentFunction;
    strategyMap["ExitProcess"] = &InstExitProcess::InstrumentFunction;
    strategyMap["GetModuleHandleA"] = &InstGetModuleHandleA::InstrumentFunction;
    strategyMap["DeleteFileA"] = &InstDeleteFileA::InstrumentFunction;
    strategyMap["ShellExecute"] = &InstShellExecute::InstrumentFunction;
    strategyMap["ShellExecuteEx"] = &InstShellExecuteEx::InstrumentFunction;


    // Com Problema, não chama o after -> strategyMap["GetForegroundWindow"] = &InstGetForegroundWindow::InstrumentFunction; // <-----Verificar, o CB after não está sendo invocado, já tentei removendo os parametros. O CB After funciona no modo Probed


    // Registro do Windows
    strategyMap["BaseRegOpenKey"] = &InstBaseRegOpenKey::InstrumentFunction;
    strategyMap["BaseRegEnumKey"] = &InstBaseRegEnumKey::InstrumentFunction;
    strategyMap["RegOpenKeyA"] = &InstRegOpenKeyA::InstrumentFunction;
    strategyMap["RegEnumKeyA"] = &InstRegEnumKeyA::InstrumentFunction;
    strategyMap["RegQueryValueA"] = &InstRegQueryValueA::InstrumentFunction;
    strategyMap["RegOpenKeyW"] = &InstRegOpenKeyW::InstrumentFunction;
    strategyMap["RegEnumKeyW"] = &InstRegEnumKeyW::InstrumentFunction;
    strategyMap["RegQueryValueW"] = &InstRegQueryValueW::InstrumentFunction;
    strategyMap["RegOpenKeyExA"] = &InstRegOpenKeyExA::InstrumentFunction;
    strategyMap["RegEnumKeyExA"] = &InstRegEnumKeyExA::InstrumentFunction;
    strategyMap["RegQueryValueExA"] = &InstRegQueryValueExA::InstrumentFunction;
    strategyMap["RegOpenKeyExW"] = &InstRegOpenKeyExW::InstrumentFunction;
    strategyMap["RegEnumKeyExW"] = &InstRegEnumKeyExW::InstrumentFunction;
    strategyMap["RegQueryValueExW"] = &InstRegQueryValueExW::InstrumentFunction;
    //strategyMap["NtOpenKey"] = &InstNtOpenKey::InstrumentFunction;
    //strategyMap["ZwOpenKey"] = &InstNtOpenKey::InstrumentFunction;
    strategyMap["NtEnumKey"] = &InstNtEnumKey::InstrumentFunction;
    strategyMap["ZwEnumKey"] = &InstNtEnumKey::InstrumentFunction;
    //strategyMap["NtQueryValueKey"] = &InstNtQueryValueKey::InstrumentFunction;
    //strategyMap["ZwQueryValueKey"] = &InstNtQueryValueKey::InstrumentFunction;
    strategyMap["NtQueryKey"] = &InstNtQueryKey::InstrumentFunction;
    strategyMap["ZwQueryKey"] = &InstNtQueryKey::InstrumentFunction;


    //// // Experimentando
    strategyMap["CoCreateInstance"] = &InstWmi::InstrumentFunction;
    strategyMap["ConnectServer"] = &InstWmi::InstrumentFunction;
    strategyMap["ExecQuery"] = &InstWmi::InstrumentFunction;
    strategyMap["CoCreateInstanceEx"] = &InstWmiEx::InstrumentFunction;
    strategyMap["ConnectServer"] = &InstWmiEx::InstrumentFunction;
    strategyMap["ExecQuery"] = &InstWmiEx::InstrumentFunction;
    strategyMap["GetObject"] = &InstWmiEx::InstrumentFunction;
    strategyMap["GetObjectA"] = &InstWmiEx::InstrumentFunction;
    strategyMap["GetObjectW"] = &InstWmiEx::InstrumentFunction;
    strategyMap["GetWriteWatch"] = &InstGetWriteWatch::InstrumentFunction;
    //// // Fin Experimentando

    //// 
    // // Falta implementar a lógica de detecção
    strategyMap["GetModuleHandleA"] = &InstGetModuleHandleA::InstrumentFunction;
    strategyMap["GetModuleHandleW"] = &InstGetModuleHandleW::InstrumentFunction;
    strategyMap["GetModuleFileNameExA"] = &InstGetModuleFileNameExA::InstrumentFunction;
    strategyMap["GetModuleFileNameExW"] = &InstGetModuleFileNameExW::InstrumentFunction;
    strategyMap["GetModuleFileNameA"] = &InstGetModuleFileNameA::InstrumentFunction;
    strategyMap["GetModuleFileNameW"] = &InstGetModuleFileNameW::InstrumentFunction;
    strategyMap["GetWindowTextA"] = &InstGetWindowTextA::InstrumentFunction;
    strategyMap["GetWindowTextW"] = &InstGetWindowTextW::InstrumentFunction;
    strategyMap["IsDebuggerPresent"] = &InstIsDebuggerPresent::InstrumentFunction;
    strategyMap["CheckRemoteDebuggerPresent"] = &InstCheckRemoteDebuggerPresent::InstrumentFunction;
    strategyMap["OutputDebugStringW"] = &InstOutputDebugStringW::InstrumentFunction;
    strategyMap["FindWindowA"] = &InstFindWindowA::InstrumentFunction;
    strategyMap["FindWindowW"] = &InstFindWindowW::InstrumentFunction;
    strategyMap["KiUserExceptionDispatcher"] = &InstKiUserExceptionDispatcher::InstrumentFunction;
    strategyMap["GetTickCount64"] = &InstGetTickCount64::InstrumentFunction;
    strategyMap["GetLocalTime"] = &InstGetLocalTime::InstrumentFunction;
    strategyMap["GetSystemTime"] = &InstGetSystemTime::InstrumentFunction;
    strategyMap["OutputDebugStringA"] = &InstOutputDebugStringA::InstrumentFunction;
    strategyMap["BlockInput"] = &InstBlockInput::InstrumentFunction;
    strategyMap["OpenProcess"] = &InstOpenProcess::InstrumentFunction;
    strategyMap["CreateProcess"] = &InstCreateProcess::InstrumentFunction;
    strategyMap["CreateProcessAsUser"] = &InstCreateProcessAsUser::InstrumentFunction;
    strategyMap["ShellExecute"] = &InstShellExecute::InstrumentFunction;
    // strategyMap["ShellExecuteEx"] = &InstShellExecuteEx::InstrumentFunction;
    strategyMap["WinExec"] = &InstWinExec::InstrumentFunction;
    strategyMap["CreateService"] = &InstCreateService::InstrumentFunction;
    strategyMap["StartService"] = &InstStartService::InstrumentFunction;
    strategyMap["CoCreateInstance"] = &InstCoCreateInstance::InstrumentFunction;
    strategyMap["LoadLibrary"] = &InstLoadLibrary::InstrumentFunction;
    strategyMap["LoadLibraryEx"] = &InstLoadLibraryEx::InstrumentFunction;
    strategyMap["NtOpenProcess"] = &InstNtOpenProcess::InstrumentFunction;
    strategyMap["NtSetInformationThread"] = &InstNtSetInformationThread::InstrumentFunction;
    strategyMap["ZwSetInformationThread"] = &InstNtSetInformationThread::InstrumentFunction;
    strategyMap["NtSetInformationProcess"] = &InstNtSetInformationProcess::InstrumentFunction;
    strategyMap["ZwSetInformationProcess"] = &InstNtSetInformationProcess::InstrumentFunction;
    strategyMap["NtQueryObject"] = &InstNtQueryObject::InstrumentFunction;
    strategyMap["ZwQueryObject"] = &InstNtQueryObject::InstrumentFunction;
    strategyMap["NtYieldExecution"] = &InstNtYieldExecution::InstrumentFunction;
    strategyMap["ZwYieldExecution"] = &InstNtYieldExecution::InstrumentFunction;
    strategyMap["NtCreateProcessEx"] = &InstNtCreateProcessEx::InstrumentFunction;
    strategyMap["ZwCreateProcessEx"] = &InstNtCreateProcessEx::InstrumentFunction;
    strategyMap["NtCreateThreadEx"] = &InstNtCreateThreadEx::InstrumentFunction;
    strategyMap["ZwCreateThreadEx"] = &InstNtCreateThreadEx::InstrumentFunction;
    strategyMap["NtUserFindWindowEx"] = &InstNtUserFindWindowEx::InstrumentFunction;
    strategyMap["ZwUserFindWindowEx"] = &InstNtUserFindWindowEx::InstrumentFunction;
    /*strategyMap["NtUserBuildHwndList"] = &InstNtUserBuildHwndList::InstrumentFunction;
    strategyMap["ZwUserBuildHwndList"] = &InstNtUserBuildHwndList::InstrumentFunction;*/
    strategyMap["NtUserQueryWindow"] = &InstNtUserQueryWindow::InstrumentFunction;
    strategyMap["ZwUserQueryWindow"] = &InstNtUserQueryWindow::InstrumentFunction;
    strategyMap["NtSetDebugFilterState"] = &InstNtSetDebugFilterState::InstrumentFunction;
    strategyMap["ZwSetDebugFilterState"] = &InstNtSetDebugFilterState::InstrumentFunction;
    strategyMap["NtClose"] = &InstNtClose::InstrumentFunction;
    strategyMap["ZwClose"] = &InstNtClose::InstrumentFunction;
    strategyMap["NtGetContextThread"] = &InstNtGetContextThread::InstrumentFunction;
    strategyMap["ZwGetContextThread"] = &InstNtGetContextThread::InstrumentFunction;
    strategyMap["NtSetContextThread"] = &InstNtSetContextThread::InstrumentFunction;
    strategyMap["ZwSetContextThread"] = &InstNtSetContextThread::InstrumentFunction;
    strategyMap["NtContinue"] = &InstNtContinue::InstrumentFunction;
    strategyMap["ZwContinue"] = &InstNtContinue::InstrumentFunction;
    strategyMap["NtQuerySystemTime"] = &InstNtQuerySystemTime::InstrumentFunction;
    strategyMap["ZwQuerySystemTime"] = &InstNtQuerySystemTime::InstrumentFunction;
    strategyMap["NtQueryInformationThread"] = &InstNtQueryInformationThread::InstrumentFunction;
    strategyMap["ZwQueryInformationThread"] = &InstNtQueryInformationThread::InstrumentFunction;
    //strategyMap["NtQueryVirtualMemory"] = &InstNtQueryVirtualMemory::InstrumentFunction;
    //strategyMap["ZwQueryVirtualMemory"] = &InstNtQueryVirtualMemory::InstrumentFunction;
    strategyMap["NtQuerySystemInformation"] = &InstNtQuerySystemInformation::InstrumentFunction;
    strategyMap["ZwQuerySystemInformation"] = &InstNtQuerySystemInformation::InstrumentFunction;
    strategyMap["EnumProcessModulesEx"] = &InstEnumProcessModulesEx::InstrumentFunction;
    strategyMap["EnumProcessModules"] = &InstEnumProcessModules::InstrumentFunction;
    strategyMap["VirtualProtect"] = &InstVirtualProtect::InstrumentFunction;
    strategyMap["VirtualProtectEx"] = &InstVirtualProtectEx::InstrumentFunction;
    //strategyMap["VirtualQuery"] = &InstVirtualQuery::InstrumentFunction;
    //strategyMap["VirtualQueryEx"] = &InstVirtualQueryEx::InstrumentFunction;
    strategyMap["QueryPerformanceCounter"] = &InstQueryPerformanceCounter::InstrumentFunction;
    strategyMap["NtQueryPerformanceCounter"] = &InstNtQueryPerformanceCounter::InstrumentFunction;
    strategyMap["ZwQueryPerformanceCounter"] = &InstNtQueryPerformanceCounter::InstrumentFunction;

}

void FunctionInterceptor::ExecuteStrategy(const std::string& name, RTN rtn, Notifier& globalNotifier) {
    auto it = strategyMap.find(name);
    if (it != strategyMap.end()) {
        (*it->second)(rtn, globalNotifier);
    }
}

bool FunctionInterceptor::HasStrategy(const std::string& name) const {
    return strategyMap.find(name) != strategyMap.end();
}

void FunctionInterceptor::ExecuteAllStrategies(IMG img, Notifier& globalNotifier) {
    ModuleRange range;
    range.start = IMG_LowAddress(img);
    range.end = IMG_HighAddress(img);
    range.name = IMG_Name(img);

    moduleRanges.push_back(range);

    std::string moduleName = IMG_Name(img);
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
        RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
        if (RTN_Valid(rtn)) {
            std::string funcName = RTN_Name(rtn);
            for (const auto& pair : strategyMap) {
                std::string strategyName = pair.first.c_str();
                if (strategyName == funcName) {
                    RTNFunction func = pair.second;
                    func(rtn, globalNotifier);
                }
            }
        }
    }

}