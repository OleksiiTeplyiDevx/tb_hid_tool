@echo off
rem Builds dist\TBHidTool\ (exe + tb_commands.json) and dist\TBHidTool_<version>.zip
rem Build number = number of git commits, major.minor are in tb_hid_tool.py.
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    where py >nul 2>nul && (py -3 -m venv .venv) || (python -m venv .venv)
)
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt pyinstaller
if errorlevel 1 exit /b 1

set BUILD=0
for /f %%i in ('git rev-list --count HEAD 2^>nul') do set BUILD=%%i
>build_number.py echo BUILD_NUMBER = %BUILD%

".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onedir --windowed --name TBHidTool tb_hid_tool.py
if errorlevel 1 exit /b 1
copy /y tb_commands.json dist\TBHidTool\ >nul

for /f %%v in ('.venv\Scripts\python.exe -c "import tb_hid_tool as t;print(t.APP_VERSION)"') do set VER=%%v
powershell -NoProfile -Command "Compress-Archive -Force -Path dist\TBHidTool -DestinationPath dist\TBHidTool_%VER%.zip"
echo Done: dist\TBHidTool_%VER%.zip
