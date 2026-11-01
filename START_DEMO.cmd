@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
echo Демонстрация микросервисов: локальный режим с SQLite.
echo Требуется Python 3.12. При первом запуске библиотеки загружаются из Интернета.
py -3.12 -c "import sys; assert sys.version_info[:2] == (3, 12)" >nul 2>&1
if not errorlevel 1 goto use_py
python -c "import sys; assert sys.version_info[:2] == (3, 12)" >nul 2>&1
if not errorlevel 1 goto use_python
echo Не найден Python 3.12. Откройте docs\SHOWCASE.md: раздел запуска на компьютере.
goto failed
:use_py
if not exist ".venv\Scripts\python.exe" py -3.12 -m venv .venv
goto ready
:use_python
if not exist ".venv\Scripts\python.exe" python -m venv .venv
:ready
if not exist ".venv\Scripts\python.exe" goto failed
".venv\Scripts\python.exe" -c "import sys; assert sys.version_info[:2] == (3, 12)"
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo Запускаются пять сервисов и выполняется проверка удаления и восстановления...
".venv\Scripts\python.exe" scripts\run_local.py --smoke
if errorlevel 1 goto failed
".venv\Scripts\python.exe" scripts\make_demo_report.py
if errorlevel 1 goto failed
echo Готово. Открывается отчёт с результатами.
start "" "%CD%\artifacts\demo-report.html"
pause
exit /b 0
:failed
echo Запуск не завершён. Скопируйте сообщение об ошибке из этого окна.
echo Для показа без установки программ используйте GitHub Actions по инструкции docs\SHOWCASE.md.
pause
exit /b 1
