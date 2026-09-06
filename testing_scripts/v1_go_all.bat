@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "script_dir=%~dp0"
set /a total=0
set /a failures=0

for %%F in ("%script_dir%v1_*.bat") do (
    if exist "%%~fF" if /I not "%%~nxF"=="%~nx0" (
        set /a total+=1
        echo.
        echo [v1_go_all] Running %%~nxF
        call "%%~fF" %*
        set "status=!errorlevel!"

        if !status! equ 0 (
            echo [v1_go_all] PASS %%~nxF
        ) else (
            set /a failures+=1
            echo [v1_go_all] FAIL %%~nxF ^(exit !status!^) 1>&2
        )
    )
)

echo.
if %total% equ 0 (
    echo [v1_go_all] No v1 test scripts found in %script_dir% 1>&2
    exit /b 1
)

if %failures% gtr 0 (
    echo [v1_go_all] %failures% of %total% test scripts failed 1>&2
    exit /b 1
)

echo [v1_go_all] All %total% test scripts passed
exit /b 0
