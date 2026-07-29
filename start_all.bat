@echo off
echo Starting NIDS Dashboard and Services...

echo [1] Starting React UI...
start cmd /k "cd frontend && npm run dev"

echo [2] Starting API / WebSocket Server...
start cmd /k "cd backend && python api_server.py"

echo [3] Starting Live Intrusion Detector...
start cmd /k "set PYTHONIOENCODING=utf-8 && python backend\run_detector.py"


echo All services launched in separate windows!
pause
