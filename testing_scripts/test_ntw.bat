@echo off

echo ===== GET =====
curl https://httpbin.org/get

echo.
echo ===== POST =====
curl -X POST https://httpbin.org/post ^
    -H "Content-Type: application/json" ^
    -d "{\"hello\":\"world\"}" 

pause
