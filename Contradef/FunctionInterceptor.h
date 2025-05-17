#pragma once
#ifndef FUNCTION_INTERCEPTOR_H
#define FUNCTION_INTERCEPTOR_H

#include <iostream>
#include "InstrumentationStrategy.h"
#include "Instrumentation.h"
#include <map>
#include <string>
#include <functional>
#include <deque>
#include "EvasiveRetDetector.h"

#include "InstIsDebuggerPresent.h"
#include "InstCheckRemoteDebuggerPresent.h"
#include "InstOutputDebugStringW.h"
#include "InstGetForegroundWindow.h"
#include "InstNtQueryInformationProcess.h"
#include "InstBaseRegOpenKey.h"
#include "InstBaseRegEnumKey.h"
#include "InstRegOpenKeyW.h"
#include "InstRegEnumKeyW.h"
#include "InstRegOpenKeyA.h"
#include "InstRegEnumKeyA.h"
#include "InstRegOpenKeyExW.h"
#include "InstRegEnumKeyExW.h"
#include "InstRegOpenKeyExA.h"
#include "InstRegEnumKeyExA.h"
#include "InstRegQueryValueW.h"
#include "InstRegQueryValueA.h"
#include "InstRegQueryValueExW.h"
#include "InstRegQueryValueExA.h"
//#include "InstNtOpenKey.h"
#include "InstNtEnumKey.h"
//#include "InstNtQueryValueKey.h"
#include "InstGetModuleHandleW.h"
#include "InstGetModuleHandleA.h"
#include "InstGetModuleFileNameW.h"
#include "InstGetModuleFileNameA.h"
#include "InstGetModuleFileNameExW.h"
#include "InstGetModuleFileNameExA.h"
#include "InstGetWindowTextW.h"
#include "InstGetWindowTextA.h"
#include "InstGetTickCount.h"
//#include "InstVirtualQuery.h"
//#include "InstVirtualQueryEx.h"

#include "InstWmi.h"
#include "InstWmiEx.h"
#include "InstOpenProcess.h"
#include "InstCreateProcess.h"
#include "InstCreateProcessAsUser.h"
#include "InstShellExecute.h"
#include "InstShellExecuteEx.h"
#include "InstWinExec.h"
#include "InstNtCreateProcessEx.h"
#include "InstNtCreateThreadEx.h"
#include "InstCreateService.h"
#include "InstStartService.h"
#include "InstCoCreateInstance.h"
#include "InstLoadLibrary.h"
#include "InstLoadLibraryEx.h"
#include "InstNtOpenProcess.h"
#include "InstNtSetInformationThread.h"
#include "InstNtSetInformationProcess.h"
#include "InstNtQueryObject.h"
#include "InstNtYieldExecution.h"
#include "InstOutputDebugStringA.h"
#include "InstBlockInput.h"
#include "InstNtUserFindWindowEx.h"
#include "InstNtUserBuildHwndList.h"
#include "InstNtUserQueryWindow.h"
#include "InstNtSetDebugFilterState.h"
#include "InstNtClose.h"
#include "InstNtGetContextThread.h"
#include "InstNtSetContextThread.h"
#include "InstNtContinue.h"
#include "InstKiUserExceptionDispatcher.h"
#include "InstGetTickCount64.h"
#include "InstGetLocalTime.h"
#include "InstGetSystemTime.h"
#include "InstNtQuerySystemTime.h"
#include "InstNtQueryInformationThread.h"
#include "InstFindWindowA.h"
#include "InstFindWindowW.h"
#include "InstNtQueryVirtualMemory.h"
#include "InstNtCreateTimer2.h"
#include "InstNtQueryKey.h"
#include "InstNtQuerySystemInformation.h"
#include "InstEnumProcessModulesEx.h"
#include "InstEnumProcessModules.h"
#include "InstVirtualProtect.h"
#include "InstVirtualProtectEx.h"
#include "InstQueryPerformanceCounter.h"
#include "InstNtQueryPerformanceCounter.h"
#include "InstCreateFileW.h"
#include "InstLstrcpynA.h"
#include "InstLstrcpy.h"
#include "InstWriteConsoleW.h"
#include "InstExitProcess.h"
#include "InstDeleteFileA.h"
#include "InstGetWriteWatch.h"
#include "InstRtlGetNativeSystemInformation.h"
#include "InstGetCurrentProcess.h"
#include "InstGetCurrentThread.h"
#include "InstOpenThread.h"
#include "InstSetThreadContext.h"
#include "InstGetThreadContext.h"
#include "InstSuspendThread.h"
#include "InstWaitForSingleObject.h"
#include "InstCreateThread.h"
#include "InstCreateEventW.h"
#include "InstRtlInstallFunctionTableCallback.h"
#include "InstResumeThread.h"
#include "InstSetEvent.h"
#include "InstResetEvent.h"
#include "InstRtlDeleteFunctionTable.h"
#include "InstNtQuerySystemInformationEx.h"
#include "InstGetEnvironmentStringsW.h"
#include "InstGetEnvironmentVariableW.h"
#include "InstVirtualAlloc.h"
#include "InstVirtualFree.h"
#include "InstReadFile.h"
#include "InstRtlAddFunctionTable.h"
#include "InstGetProcAddress.h"
#include "InstQueueUserAPC2.h"
#include "InstSleepEx.h"
#include "InstRtlAddVectoredExceptionHandler.h"
#include "InstRaiseException.h"
#include "InstRtlRemoveVectoredExceptionHandler.h"
#include "InstGetVersionExW.h"
#include "InstNtdllDefWindowProc_W.h"
#include "InstCreateToolhelp32Snapshot.h"
#include "InstGetFileSizeEx.h"
#include "InstSetFilePointerEx.h"
#include "InstQueryDosDeviceW.h"
#include "InstGetSystemFirmwareTable.h"
#include "InstBasepConstructSxsCreateProcessMessage.h"
#include "InstGetVolumePathNameW.h"
#include "InstDeviceIoControl.h"
#include "InstRtlQueryPerformanceCounter.h"
#include "InstGetCommandLineA.h"
#include "InstGetCommandLineW.h"
#include "InstGetComputerNameA.h"
#include "InstLCMapStringEx.h"
#include "InstWriteFile.h"
#include "InstCompareStringEx.h"

typedef void (*RTNFunction)(RTN, Notifier&);

class FunctionInterceptor {
private:
    std::map<std::string, RTNFunction> strategyMap;

public:
    FunctionInterceptor();
    ~FunctionInterceptor();


    std::vector<std::string> scanScope;

    bool IsStringInScanScope(const std::string& scope) const;
    void InitStrategies();
    void ExecuteStrategy(const std::string& name, RTN rtn, Notifier& globalNotifier);
    bool HasStrategy(const std::string& name) const;
    void ExecuteAllStrategies(IMG img, Notifier& globalNotifier);
};

#endif // FUNCTION_INTERCEPTOR_H