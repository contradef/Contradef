@echo off
echo.
echo [*] Desativando UAC...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

echo [*] Desativando Windows Defender (via chave de política)...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

echo [*] Desativando Proteção em tempo real (se aplicável)...
PowerShell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

echo.
echo [!] Reinicie o sistema para que o UAC seja completamente desativado.
pause
