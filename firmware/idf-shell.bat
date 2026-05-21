@echo off
:: Open an ESP-IDF v5.4.2 cmd here, with the right Python venv.
:: Workaround for global Python 3.12 confusing the auto-detect.
set "IDF_PYTHON_ENV_PATH=C:\Espressif\python_env\idf5.4_py3.11_env"
set "IDF_TOOLS_PATH=C:\Espressif"
call "C:\Espressif\frameworks\esp-idf-v5.4.2\export.bat"
cmd /k
