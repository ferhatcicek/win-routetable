@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Once install.bat calistirin.
 pause
 exit /b 1
)
set "PORT=5000"
if "%~1"=="-p" (
  set "PORT=%~2"
) else if "%~1"=="--port" (
  set "PORT=%~2"
) else if not "%~1"=="" (
  set "PORT=%~1"
)

start "" "http://127.0.0.1:%PORT%"
.venv\Scripts\python.exe app.py --port %PORT%
pause
