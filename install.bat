@echo off
echo Creating virtual environment...
python -m venv venv

echo Activating venv...
call venv\Scripts\activate

echo Installing requirements...
pip install --upgrade pip
pip install -r requirements.txt

echo.
echo Installation complete.
echo Run the tool with:
echo venv\Scripts\python.exe run_gui.py
pause