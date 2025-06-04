echo [*] Descompactando as amostras...  

# amostra 1
powershell -c "Expand-Archive -Path .\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.zip -DestinationPath .\Amostras -Password infected"

# amostra 2
powershell -c "Expand-Archive -Path .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.zip -DestinationPath .\Amostras -Password infected"

echo [!] Amostras descompactadas na pasta Amostras  
pause
