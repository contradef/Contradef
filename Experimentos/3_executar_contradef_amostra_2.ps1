echo [*] Executando a Contradef na amostra 36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe...  

echo [*] Criando pasta para resultados  

mkdir 36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f
cd 36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f

echo [*] Executando a Contradef com todos os módulos
"..\..\pin\intel64\bin\pin.exe" -t "..\..\ContradefDll\contradef.dll" -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm -- "..\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe"

echo [!] Execução finalizada.
pause