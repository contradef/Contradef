echo [*] Executando a Contradef na amostra 0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe...  

echo [*] Criando pasta para resultados  

mkdir 0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b
cd 0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b

echo [*] Executando a Contradef com todos os módulos
"..\..\pin\intel64\bin\pin.exe" -t "..\..\ContradefDll\contradef.dll" -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm -- "..\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe"

echo [!] Execução finalizada.
pause