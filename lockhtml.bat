@echo off
rem LockHTML launcher - Windows.
rem
rem   lockhtml.bat lock secret.pdf --pin 4821
rem   lockhtml.bat unlock secret.pdf.locked.html
rem   lockhtml.bat gui
rem
rem Runs the CLI straight from this folder, so no install step is needed as long
rem as Python 3.9+ and the two dependencies are available.

setlocal
set "DIR=%~dp0"

set "PY="
if exist "%DIR%.venv\Scripts\python.exe" set "PY=%DIR%.venv\Scripts\python.exe"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  where py >nul 2>nul && set "PY=py"
)

if not defined PY (
  echo LockHTML: Python 3.9+ was not found on your PATH. 1>&2
  echo Install it from https://www.python.org/downloads/ and try again. 1>&2
  exit /b 1
)

%PY% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if errorlevel 1 (
  echo LockHTML: Python 3.9 or newer is required. 1>&2
  exit /b 1
)

%PY% -c "import argon2, cryptography" >nul 2>nul
if errorlevel 1 (
  echo LockHTML: the Python dependencies are not installed yet. Run: 1>&2
  echo   %PY% -m pip install -r "%DIR%requirements.txt" 1>&2
  echo or, from the project folder:  %PY% -m pip install -e . 1>&2
  exit /b 1
)

set "PYTHONPATH=%DIR%;%PYTHONPATH%"
%PY% -m lockhtml %*
exit /b %ERRORLEVEL%
