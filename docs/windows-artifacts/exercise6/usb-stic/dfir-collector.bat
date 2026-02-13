@echo off
setlocal enabledelayedexpansion

:: -------------------------------
:: Define output folder
:: -------------------------------
set "outputFolder=%~dp0OUTPUT"
if not exist "%outputFolder%" mkdir "%outputFolder%"

goto Start

:: -------------------------------
:: Functions
:: -------------------------------
:RunCommand
:: %1 = command to run (use quotes if command has arguments)
:: %2 = output file name (optional)
if "%2"=="" (
    echo Running: %~1
    %~1
) else (
    echo Running: %~1 and saving to "%outputFolder%\%2"
    %~1 > "%outputFolder%\%2"
)
goto :eof

:: -------------------------------
:: Manual menu
:: -------------------------------
:ShowMenu
cls
echo Select the option to execute:
echo -----------------------------------------------
echo 1  - Show logged on users
echo 2  - List active processes
echo 3  - List running processes (tasklist)
echo 4  - Show processes per user (CProcess)
echo 5  - List process DLLs (Listdlls)
echo 6  - Show open ports (Openports)
echo 7  - Show open files (Handle)
echo 8  - Show services (PsService)
echo 9  - Show network interfaces (ipconfig /all)
echo 10 - Show DNS cache (ipconfig /displaydns)
echo 11 - Detect promiscuous adapters (promiscdetect)
echo 12 - Show TCP connections (nbtstat -s)
echo 13 - Show NetBIOS cache (nbtstat -c)
echo 14 - Show active connections (netstat -an)
echo 15 - Show applications and open ports (netstat -anob)
echo 16 - Show routing table (netstat -r)
echo 17 - Show all active connections (netstat -ano)
echo 18 - Show hosts file
echo 19 - Show shared files (net file)
echo 20 - Show ARP cache (arp -a)
echo 21 - Show routing (route print)
echo 22 - Show installed protocols (urlprotocolview)
echo 23 - Show mapped network drives (net use)
echo 24 - Show shared folders (net share)
echo 25 - Show open files view (openedfilesview)
echo 26 - Show remote open files (psfile)
echo 27 - Show NetBIOS shared users (nbtstat -n)
echo 28 - Show local and remote users (net users)
echo 29 - Show remote sessions (net sessions)
echo 30 - Show active sessions (logonsessions)
echo 31 - Show users SID (psgetsid)
echo 32 - Show clipboard content (insideclipboard)
echo 33 - Show CMD history (doskey /history)
echo 34 - Show services execution (SC query)
echo 0  - Exit
echo -----------------------------------------------
set /p choice="Enter the number: "

if "%choice%"=="1"  call :RunCommand "%~dp0tools\psloggedon.exe"
if "%choice%"=="2"  call :RunCommand "%~dp0tools\pslist.exe"
if "%choice%"=="3"  call :RunCommand tasklist
if "%choice%"=="4"  call :RunCommand "%~dp0tools\CProcess.exe"
if "%choice%"=="5"  call :RunCommand "%~dp0tools\Listdlls.exe"
if "%choice%"=="6"  call :RunCommand "%~dp0tools\openports.exe"
if "%choice%"=="7"  call :RunCommand "%~dp0tools\handle.exe"
if "%choice%"=="8"  call :RunCommand "%~dp0tools\PsService.exe"
if "%choice%"=="9"  call :RunCommand "ipconfig /all"
if "%choice%"=="10" call :RunCommand "ipconfig /displaydns"
if "%choice%"=="11" call :RunCommand "%~dp0tools\promiscdetect.exe"
if "%choice%"=="12" call :RunCommand "nbtstat -s"
if "%choice%"=="13" call :RunCommand "nbtstat -c"
if "%choice%"=="14" call :RunCommand "netstat -an"
if "%choice%"=="15" call :RunCommand "netstat -anob"
if "%choice%"=="16" call :RunCommand "netstat -r"
if "%choice%"=="17" call :RunCommand "netstat -ano"
if "%choice%"=="18" call :RunCommand "type C:\Windows\System32\drivers\etc\hosts"
if "%choice%"=="19" call :RunCommand "net file"
if "%choice%"=="20" call :RunCommand "arp -a"
if "%choice%"=="21" call :RunCommand "route print"
if "%choice%"=="22" call :RunCommand "%~dp0tools\urlprotocolview.exe"
if "%choice%"=="23" call :RunCommand "net use"
if "%choice%"=="24" call :RunCommand "net share"
if "%choice%"=="25" call :RunCommand "%~dp0tools\openedfilesview.exe"
if "%choice%"=="26" call :RunCommand "%~dp0tools\psfile.exe"
if "%choice%"=="27" call :RunCommand "nbtstat -n"
if "%choice%"=="28" call :RunCommand "net users"
if "%choice%"=="29" call :RunCommand "net sessions"
if "%choice%"=="30" call :RunCommand "%~dp0tools\logonsessions.exe"
if "%choice%"=="31" call :RunCommand "%~dp0tools\psgetsid.exe"
if "%choice%"=="32" call :RunCommand "%~dp0tools\insideclipboard.exe"
if "%choice%"=="33" call :RunCommand "doskey /history"
if "%choice%"=="34" call :RunCommand "SC query"
if "%choice%"=="0" exit
pause
goto ShowMenu

:: -------------------------------
:: Automatic mode
:: -------------------------------
:Automatic
echo Running all commands and saving output to "%outputFolder%"
call :RunCommand "%~dp0tools\psloggedon.exe" "LoggedOnUsers.txt"
call :RunCommand "%~dp0tools\pslist.exe" "ActiveProcesses.txt"
call :RunCommand tasklist "RunningProcesses.txt"
call :RunCommand "%~dp0tools\CProcess.exe" "UserProcesses.txt"
call :RunCommand "%~dp0tools\Listdlls.exe" "ProcessDependencies.txt"
call :RunCommand "%~dp0tools\openports.exe" "OpenPorts.txt"
call :RunCommand "%~dp0tools\handle.exe" "OpenFiles.txt"
call :RunCommand "%~dp0tools\PsService.exe" "Services.txt"
call :RunCommand "ipconfig /all" "NetworkConfiguration.txt"
call :RunCommand "ipconfig /displaydns" "DNSCache.txt"
call :RunCommand "%~dp0tools\promiscdetect.exe" "PromiscuousAdapters.txt"
call :RunCommand "nbtstat -s" "NetbiosSessions.txt"
call :RunCommand "nbtstat -c" "NetbiosCache.txt"
call :RunCommand "netstat -an" "ActiveConnections.txt"
call :RunCommand "netstat -anob" "OpenPortsApplications.txt"
call :RunCommand "netstat -r" "RoutingTable.txt"
call :RunCommand "netstat -ano" "FullConnections.txt"
call :RunCommand "type C:\Windows\System32\drivers\etc\hosts" "Hosts.txt"
call :RunCommand "net file" "SharedFiles.txt"
call :RunCommand "arp -a" "ArpCache.txt"
call :RunCommand "route print" "RoutingConfig.txt"
call :RunCommand "%~dp0tools\urlprotocolview.exe" "InstalledProtocols.txt"
call :RunCommand "net use" "MappedDrives.txt"
call :RunCommand "net share" "SharedFolders.txt"
call :RunCommand "%~dp0tools\openedfilesview.exe" "OpenedFiles.txt"
call :RunCommand "%~dp0tools\psfile.exe" "RemoteOpenFiles.txt"
call :RunCommand "nbtstat -n" "SharedUsers.txt"
call :RunCommand "net users" "LocalAndRemoteUsers.txt"
call :RunCommand "net sessions" "RemoteSessions.txt"
call :RunCommand "%~dp0tools\logonsessions.exe" "ActiveSessions.txt"
call :RunCommand "%~dp0tools\psgetsid.exe" "UsersSid.txt"
call :RunCommand "%~dp0tools\insideclipboard.exe" "ClipboardInfo.txt"
call :RunCommand "doskey /history" "CMDHistory.txt"
call :RunCommand "SC query" "ServicesExecution.txt"
echo All commands completed.
goto :eof

:: -------------------------------
:: Main logic
:: -------------------------------
:Start
echo Select mode:
echo 1 - Automatic (run all and save to files)
echo 2 - Manual (menu selection)
set /p mode="Enter 1 or 2: "
if "%mode%"=="1" goto Automatic
if "%mode%"=="2" goto ShowMenu
echo Invalid option.
goto Start
