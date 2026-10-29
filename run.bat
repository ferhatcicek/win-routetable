@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Once install.bat calistirin.
 pause
 exit /b 1
)
start "" http://127.0.0.1:5000
.venv\Scripts\python.exe app.py
pause
