
set BAT_PATH=%~dp0
set PYTHONPATH=%BAT_PATH:~0,-4%
python -O -m saam.analyse %*