<#
.SYNOPSIS
Dynamic malware analysis and threat hunting helper script.
.DESCRIPTION
- Sets a series of baselines.
    - Creates a WMI event to monitor newly created processes.
        - Prints out modules.
    - Creates filesystem watcher events.
        - Copies created files to script root.
    - Runs pe-sieve over all newly created processes.
- Sets a second series of baselines
- Checks for diffs between baselines and prints/logs results.
.LINK
Required in script root:
- https://github.com/hasherezade/pe-sieve/releases/tag/v0.3.9
- https://github.com/jschicht/ExtractUsnJrnl?tab=readme-ov-file
- https://github.com/EricZimmerman/MFTECmd
.NOTES 
- If hitting [Enter] once doesn't trigger the closing of events and the 
start of the second round of baselines, spam [Enter] a few more times.
#>

$compareBaselines = @"
using System;
using System.IO;
using System.Collections.Generic;

public class CompareBaselines
{
    public static Tuple<List<string>, List<string>> Compare(string blOne, string blTwo)
    {
        int index = 0;
        var result = GetDifferences(blOne, blTwo, index);
        return result;
    }

    private static Tuple<List<string>, List<string>> GetDifferences(string blOne, string blTwo, int index)
    {
        var fullRowsInFirst = new Dictionary<string, string>();
        var fullRowsInSecond = new Dictionary<string, string>();

        foreach (var line in File.ReadAllLines(blOne))
        {
            var columns = line.Split(',');
            if (columns.Length > index)
                fullRowsInFirst[columns[index]] = line;
        }

        foreach (var line in File.ReadAllLines(blTwo))
        {
            var columns = line.Split(',');
            if (columns.Length > index)
                fullRowsInSecond[columns[index]] = line;
        }

        var newKeys = new List<string>();
        foreach (var key in fullRowsInSecond.Keys)
        {
            if (!fullRowsInFirst.ContainsKey(key))
                newKeys.Add(fullRowsInSecond[key]);
        }

        var removedKeys = new List<string>();
        foreach (var key in fullRowsInFirst.Keys)
        {
            if (!fullRowsInSecond.ContainsKey(key))
                removedKeys.Add(fullRowsInFirst[key]);
        }
        return Tuple.Create(newKeys, removedKeys);
    }
}
"@

function Compare-BaseLines {

    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$true)]
        [string]$blDirOne,
        [Parameter(Position=1,Mandatory=$true)]
        [string]$blDirTwo,
        [Parameter(Position=2,Mandatory=$true)]
        [string]$reportPath
    )

    BEGIN {
        Add-Type -TypeDefinition $compareBaselines -Language CSharp
        $dirOneFiles = Get-ChildItem -Path $blDirOne -Filter *.csv
        $dirTwoFiles = Get-ChildItem -Path $blDirTwo -Filter *.csv
        $total = $dirOneFiles.Count 

        $dirTwoHT = @{}
        foreach ($file in $dirTwoFiles) { $dirTwoHT[$file.Name] = $file.FullName }
    }

    PROCESS {
        foreach ($file in $dirOneFiles) {
            if ($dirTwoHT.ContainsKey($file.Name)) {
                $bl1 = $file.FullName
                $bl2 = $dirTwoHT[$file.Name]

                $blType = switch -regex ($file) {
                    '^AccessFeatures'   { 'Win Accessability Features' }
                    '^Addresses'        { 'Addresses' }
                    '^BTJobs'           { 'Background Intelligent Transfer Jobs' }
                    '^Certs'            { 'Certificates' }
                    '^InProcSrv'        { 'InProcServer32' }
                    '^LocalSrv'         { 'LocalServer32'}
                    '^DnsCache'         { 'DNS Cache' }
                    '^DLILCOM'          { 'Disabled LowIL Isolation COM' }
                    '^Drivers'          { 'Drivers' }
                    '^EvtConsumers'     { 'Event Consumers' }
                    '^USNJrnl'          { 'Change Journal' }
                    '^FirewallRules'    { 'Firewall Rules' }
                    '^Files'			{ 'Files' }
                    '^FWLog'            { 'Firewall Logs' }
                    '^Links'            { 'Links' }
                    '^Pipes'            { 'Named Pipes' }
                    '^NSPipes'          { 'NullSession Pipes' }
                    '^NSShares'         { 'NullSession Shares' }
                    '^PendingRenames'   { 'Pending Renames' }
                    '^Processes'        { 'Processes' }
                    '^RootTPs'          { 'Root Thumbprints' }
                    '^SchTasks'         { 'Sch Tasks' }
                    '^Services'         { 'Services' }
                    '^Shims'            { 'Shims' }
                    '^Software'         { 'Software' }
                    '^StartUp'          { 'Start Up' }
                    '^StartUpCmd'       { 'Start Up Cmd' }
                    '^Streams'          { 'Streams' }
                    '^SMCmdLine'		{ 'Proc Creation CmdLine' }
                    '^SMDNS'			{ 'DNS Query Evts' }
                    '^SMImgLoad' 		{ 'Image Load Evts' }
                    '^TcpConnections'   { 'Network Traffic' }
                    '^UrlCache'         { 'INet Cache' }
                    default             { 'Type Unknown' }
                }

                $diffs = [CompareBaselines]::Compare($bl1, $bl2)
                $newEntries = $diffs.Item1
                $removedEntries = $diffs.Item2
                
                $title = "`n=======================> [ $blType ] <======================="
                $new = "------------------------------ [ New ] ------------------------------"
                $removed = "`n--------------------------- [ Removed ] ---------------------------"
                
                if ($newEntries -ne $null) {
                    Write-Host = $title -Fore Cyan
                    Write-Host $new -Fore Green
                    foreach ($entry in $newEntries) { Write-Host $entry }

                    $title | Out-File -FilePath $reportPath -Append
                    $new | Out-File -FilePath $reportPath -Append
                    foreach ($entry in $newEntries) { Add-Content -Path $reportPath $entry }

                    if ($removedEntries -ne $null) {
                        Write-Host $removed -Fore Red
                        foreach ($entry in $removedEntries) { Write-Host $entry }

                        $removed | Out-File -FilePath $reportPath -Append
                        foreach ($entry in $removedEntries) { Add-Content -Path $reportPath $entry }
                    }
                }
            } else {
            Write-Warning "[!] File $($file.Name) does not exist in second directory."
            }
        }
    }
 
    END {
        Write-Host "[>] Comparisons complete!" -Fore Cyan
    }
}

$kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(
        IntPtr Pipe, out uint ServerProcessId);
}
"@

function Export-Baselines {

    [CmdletBinding()]
    param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$blDirectory
    )

    BEGIN {
        Write-Host "[>] Starting baseline export.." -Fore Cyan
        Add-Type -TypeDefinition $kernel32
    }

    PROCESS {
        <#
        Write-Host "    [>] Getting streams.." -Fore Magenta
        $streamJob = Start-Job -ArgumentList $blDirectory -ScriptBlock { 
            param ($blDirectory)
            $streams = Get-ChildItem -Path 'C:\' -Recurse -Force -PipelineVariable FullName |
                       ForEach-Object { Get-Item $_.FullName -Stream * } | 
                       Where-Object { ($_.Stream -notlike "*DATA") -and ($_.Stream -ne "Zone.Identifier")} 
        
            $streamResults = @()
            foreach ($stream in $streams) { 
                $file = Get-Item -Path $stream.FileName
                $content = Get-Content -Path $stream.FileName -Stream $stream.Stream 
                $streamResults += [PSCustomObject]@{
                    File = $file 
                    StreamContent = $content 
                }
            }
            $streamResults | Export-Csv -Path "$blDirectory\Streams.csv" -NoTypeInformation
        }#>
        
        Write-Host "	[>] Getting files.." -Fore Magenta
        $fileSystemJob = Start-Job -ArgumentList $blDirectory -ScriptBlock { 
            param ($blDirectory)
            Get-ChildItem -Path C:\Windows -Recurse -Force | 
                Where-Object { $_.FullName -notlike '*\System32\*' -and $_.FullName -notlike '*\SysWOW64\*' -and $_.FullName -notlike '*\WinSxS\*' } | 
                Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -NoTypeInformation
            
            Get-ChildItem -Path C:\ -Force | Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -Append -NoTypeInformation
            Get-ChildItem -Path "C:\Program Files" -Recurse | Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -Append -NoTypeInformation
            Get-ChildItem -Path "C:\Program Files (x86)" -Recurse | Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -Append -NoTypeInformation
        }

        <#Write-Host "    [>] Getting InProcServer32.." -Fore Magenta 
        $inprocServerJob = Start-Job -ArgumentList $blDirectory -ScriptBlock {
            param ($blDirectory)
            $hkcrCLSID = "Registry::HKEY_CLASSES_ROOT\CLSID"
            $clsidKeys = Get-ChildItem -Path $hkcrCLSID
            foreach ($key in $clsidKeys) {
                $inprocServer32Path = "None"
                $fileHash = "None"

                try {
                    $inprocServer32RegistryPath = "$($key.PSPath)\InprocServer32"
                    $inprocServer32Key = Get-ItemProperty -Path $inprocServer32RegistryPath
                    $inprocServer32Path = $inprocServer32Key."(default)"

                    if ($inprocServer32Path -ne $null -and $inprocServer32Path -ne "") {
                        $fileHash = (Get-FileHash -Path $inprocServer32Path -Algorithm SHA256).Hash
                    }
                } catch { Write-Host $_ }

                $item = [PSCustomObject]@{
                    FileHash       = $fileHash
                    InprocServer32 = $inprocServer32Path
                    CLSID          = $key.PSChildName  
                }
                $item | Export-Csv -Path "$blDirectory\InProcSrv.csv" -Append -NoTypeInformation -Encoding utf8
            }
        }#>

        Write-Host "    [>] Getting LocalServer32.." -Fore Magenta 
        $localServerJob = Start-Job -ArgumentList $blDirectory -ScriptBlock {
            param ($blDirectory)
            $hkcrCLSID = "Registry::HKEY_CLASSES_ROOT\CLSID"
            $clsidKeys = Get-ChildItem -Path $hkcrCLSID
            foreach ($key in $clsidKeys) {
                $localServer32Path = "None"
                $fileHash = "None"

                try {
                    $localServer32RegistryPath = "$($key.PSPath)\LocalServer32"
                    $localServer32Key = Get-ItemProperty -Path $localServer32RegistryPath
                    $localServer32Path = $localServer32Key."(default)"

                    if ($localServer32Path -ne $null -and $localServer32Path -ne "") {
                        $fileHash = (Get-FileHash -Path $localServer32Path -Algorithm SHA256).Hash
                    }
                } catch { Write-Host $_ }

                $item = [PSCustomObject]@{
                    FileHash       = $fileHash
                    LocalServer32  = $localServer32Path
                    CLSID          = $key.PSChildName  
                }
                $item | Export-Csv -Path "$blDirectory\LocalSrv.csv" -Append -NoTypeInformation -Encoding utf8
            }
        }
        
        Write-Host "    [>] Getting USNJournal.." -Fore Magenta
        Extract-USNJournal $blDirectory
        
        Write-Host "    [>] Getting root thumbprints and certs.." -Fore Magenta
        Get-RootThumprints | Export-Csv -Path "$blDirectory\RootTPs.csv" -NoTypeInformation

        Get-ChildItem -Path cert:\ -Recurse | Select-Object ThumbPrint, FriendlyName, Subject | 
            Export-Csv -Path "$blDirectory\Certs.csv" -NoTypeInformation

        Write-Host "    [>] Getting process information.." -Fore Magenta
        Get-CimInstance -Class Win32_Process | Select-Object ExecutablePath, ProcessId, CommandLine | 
            Export-Csv -Path "$blDirectory\Processes.csv" -NoTypeInformation
        
        Get-Addresses | Export-Csv -Path "$blDirectory\Addresses.csv" -NoTypeInformation 

        Write-Host "    [>] Getting network information.." -Fore Magenta
        Get-NetTCPConnection | Select-Object RemoteAddress, RemotePort, LocalAddress, LocalPort, OwningProcess, `
            @{ Name="Path"; Expression={ (Get-Process -Id $_.OwningProcess).Path } } | 
            Export-Csv -Path "$blDirectory\TcpConnections.csv" -NoTypeInformation
        
        Get-DnsClientCache | Select-Object Name, Data | Export-Csv -Path "$blDirectory\DnsCache.csv" -NoTypeInformation
        
        Get-Content $env:WINDIR\System32\LogFiles\Firewall\*.log | Select-String "ALLOW TCP" | out-string | 
            Export-Csv -Path "$blDirectory\FWLog.csv" -NoTypeInformation

        Get-NetFirewallRule | Select-Object Name, Direction, Action | 
            Export-Csv -Path "$blDirectory\FirewallRules.csv" -NoTypeInformation

        Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\INetCache" -Recurse -Force | Select-Object Name | 
            Export-Csv -Path "$blDirectory\UrlCache.csv" -NoTypeInformation
        
        Write-Host "    [>] Getting event consumers.." -Fore Magenta
        Get-WmiObject -NameSpace root\Subscription -Class __EventConsumer | Select-Object __PATH, __NAMESPACE, options, ClassPath | 
            Export-Csv -Path "$blDirectory\EvtConsumers.csv" -NoTypeInformation

        Write-Host "    [>] Getting pending rename operations.." -Fore Magenta
        Get-ItemProperty ("HKLM:\System\CurrentControlSet\Control\Session Manager").FileRenameOperations | 
            Export-Csv -Path "$blDirectory\PendingRenames.csv" -NoTypeInformation

        Write-Host "    [>] Getting drivers.." -Fore Magenta
        Get-WmiObject Win32_SystemDriver | Select Name, DisplayName, PathName | 
            Export-Csv -Path "$blDirectory\Drivers.csv" -NoTypeInformation

        Write-Host "    [>] Getting services.." -Fore Magenta
        Get-ChildItem -Path "HKLM:\System\CurrentControlSet\Services\*" | Select-Object Name | 
            Export-Csv -Path "$blDirectory\Services.csv" -NoTypeInformation

        Write-Host "    [>] Getting software.." -Fore Magenta
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object DisplayName, Publisher, InstallLocation |
            Export-Csv -Path "$blDirectory\Software.csv" -NoTypeInformation

        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object DisplayName, Publisher, InstallLocation |
            Export-Csv -Path "$blDirectory\Software.csv" -NoTypeInformation

        Write-Host "    [>] Getting shims.." -Fore Magenta
        Get-ItemProperty HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\*" | 
            Export-Csv "$blDirectory\Shims.csv" -NoTypeInformation

        Get-ItemProperty HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\*" | 
            Export-Csv "$blDirectory\Shims.csv" -Append -NoTypeInformation

        Write-Host "    [>] Getting scheduled tasks.." -Fore Magenta
        Get-ScheduledTask | Select-Object TaskPath, TaskName, Source | 
            Export-Csv -Path "$blDirectory\SchTasks.csv" -NoTypeInformation

        Write-Host "    [>] Getting start up.." -Fore Magenta
        Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\startup" -Recurse -Attributes !Directory -Force | 
            Select-Object PSPath | Export-Csv -Path "$blDirectory\StartUp.csv" -NoTypeInformation

        Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\startup" -Recurse -Attributes !Directory -Force |
            Select-Object PSPath | Export-Csv -Path "$blDirectory\StartUp.csv" -Append -NoTypeInformation
            
        Get-CimInstance Win32_StartupCommand | Select-Object Command, Location, Name | 
            Export-Csv -Path "$blDirectory\StartUpCmd.csv" -NoTypeInformation

        Write-Host "    [>] Getting accessibility features.." -Fore Magenta 
        $accessibilityFeatures = @(
                "$env_homedrive\Program Files\Common Files\microsoft shared\ink\HID.dll"
                "$env_homedrive\Windows\System32\AtBroker.exe",
                "$env_homedrive\Windows\System32\DisplaySwitch.exe",
                "$env_homedrive\Windows\System32\Magnify.exe",
                "$env_homedrive\Windows\System32\Narrator.exe",
                "$env_homedrive\Windows\System32\osk.exe",
                "$env_homedrive\Windows\System32\sethc.exe",
                "$env_homedrive\Windows\System32\utilman.exe"
            )

        foreach ($feature in $accessibilityFeatures) {
            $info = Get-Item $feature | Select-Object CreationTime, LastWriteTime
            $features = [PSCustomObject]@{
                WriteTime    = $info.LastWriteTime
                CreationTime = $info.CreationTime
                Feature      = $feature 
            }
            $features | Export-Csv -Path "$blDirectory\AccessFeatures.csv" -Append -NoTypeInformation
        }

        Write-Host "    [>] Getting BITS jobs.." -Fore Magenta
        $btJobs = Get-BitsTransfer -AllUsers | Select-Object *
        foreach ($job in $btJobs) {
            $btJob = [PSCustomObject]@{
                JobId    = $job.JobId 
                Method   = $job.HttpMethod
                Type     = $job.TransferType 
                Bytes    = $job.BytesTotal 
                FileList = $job.FileList
            }
            $btJob | Export-Csv -Path "$blDirectory\BTJobs.csv" -Append -NoTypeInformation
        }

        Write-Host "    [>] Getting pipes.." -Fore Magenta
        $pipes = try { [System.IO.Directory]::GetFiles("\\.\pipe\") } catch { @() }

        $pipesResult = @()
        foreach ($pipe in $pipes) {
            $hPipe = [Kernel32]::CreateFile($pipe, 0x80000000, 0, [System.IntPtr]::Zero, 3, 0x80, [System.IntPtr]::Zero)

            if ($hPipe -eq [System.IntPtr]::Zero) { continue }

            $owner = 0
            if (-not [Kernel32]::GetNamedPipeServerProcessId($hPipe, [ref]$owner)) {
                [Kernel32]::CloseHandle($hPipe)
                continue
            }

            $proc = Get-WmiObject -Query "SELECT Caption FROM Win32_Process WHERE ProcessId = $owner" | Select -ExpandProperty Caption
            $pipesResult += [PSCustomObject]@{ 
                Pipe  = $pipe
                Proc  = $proc 
                Owner = $owner
            }
            [Kernel32]::CloseHandle($hPipe)
        }
        $pipesResult | Export-Csv -Path "$blDirectory\Pipes.csv" -NoTypeInformation

        (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parametesr).NullSessionPipes |
            Export-Csv -Path "$blDirectory\NSPipes.csv" -NoTypeInformation

        (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).NullSessionShares |
            Export-Csv -Path "$blDirectory\NSShares.csv" -NoTypeInformation

        Write-Host "    [>] Getting .lnks.." -Fore Magenta
        $wScript = New-Object -ComObject WScript.Shell 
        $lnks = Get-ChildItem -Path "$env:APPDATA" -File -Recurse | Where-Object {$_.extension -in ".lnk"} | select-Object * 
        foreach ($lnk in $lnks) {
            $target = $wScript.CreateShortcut($lnk.FullName).TargetPath 
            if ($target -notlike $("$PSScriptRoot\*")) {
                $link = [PSCustomObject]@{
                    TargetPath = $target
                    LnkFile    = $lnk.FullName 
                    WriteTime  = $lnk.LastWriteTime 
                }
            }
            $link | Export-Csv -Path "$blDirectory\Links.csv" -Append -NoTypeInformation
        }

        Write-Host "    [>] Getting DisableLowILProcessIsolation COM objects.." -Fore Magenta
        try {
            $hkcrCLSID = "Registry::HKEY_CLASSES_ROOT\CLSID"
            $clsid = Get-ChildItem -LiteralPath $hkcrCLSID | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
            foreach ($item in $clsid) {
                $path = "Registry::"+$item.Name 
                $data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
                $data.PSObject.Properties | ForEach-Object {
                    if ($_.Name -eq 'DisableLowILProcessIsolation' -and $_.Value -eq 1) {
                        $lowILCOM = [PSCustomObject]@{
                            Key  = $item.Name 
                            Name = $data.DisplayName  
                        }
                        $lowILCOM | Export-Csv -Path "$blDirectory\DLILCOM.csv" -Append -NoTypeInformation
                    }
                }
            }
        } catch { Write-Host $_ }
                    
        Write-Host "	[>] Getting sysmon events.." -Fore Magenta
        Extract-From-Sysmon $blDirectory
        
        Write-Host "[>] Waiting for jobs.." -Fore Green
        #Wait-Job $streamJob
        Wait-Job $fileSystemJob
        #Wait-Job $inprocServerJob
        Wait-Job $localServerJob
    }

    END {
        #Remove-Job $streamJob
        Remove-Job $fileSystemJob
        #Remove-Job $inprocServerJob
        Remove-Job $localServerJob
        Write-Host "[>] Baselines exported!" -Fore Cyan
    }
}

function Check-NewProcs {
<#
.DESCRIPTION
Starts a file system watcher for temp directories; copies created files to script root.
Registers a WMI event to monitor new processes that open.
Runs pe-sieve on the process and checks it's loaded modules.
.NOTES 
- Generates a lot of output.
- Could add exclusions for processes with the WQL query.
#>

    BEGIN {
        if (-not (Test-Path -Path '.\pe-sieve64.exe')) {
            Write-Warning "[!] pe-sieve not found, skipping proc watch" 
            return 
        }
    }

    PROCESS {
        Write-Host "[>] Monitoring processes! Run sample then hit [Enter] when ready continue!" -Fore Cyan
        Copy-OnCreate 

        $eventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' " +
              "AND TargetInstance.Name != 'pe-sieve64.exe' " +
              "AND TargetInstance.Name != 'SearchProtocolHost.exe' " +
              "AND TargetInstance.Name != 'SearchFilterHost.exe' " +
              "AND TargetInstance.Name != 'dllhost.exe' " +
              "AND TargetInstance.Name != 'svchost.exe'" + 
              "AND TargetInstance.Name != 'smartscreen.exe'"
              
        Register-WmiEvent -Query $eventQuery -SourceIdentifier ProcessCreation -Action {
            $process = $event.SourceEventArgs.NewEvent.TargetInstance

            Write-Host "[>] New process started: $($process.Name), PID: $($process.ProcessId)" -Fore Cyan
            cmd /c pe-sieve64.exe /pid $process.ProcessId /dir "$PSScriptRoot\sieve_output" /quiet /iat 3 /obfusc 3 /shellc 3 /threads /dmode 3 /imp 1 /minidmp

            $modules = Get-Process -id $process.ProcessId | Select-Object -ExpandProperty Modules | 
                Select-Object ModuleName, FileName, Company

            foreach ($module in $modules) { 
                $authSig = Get-AuthenticodeSignature $module.FileName 
                if ($authSig.Status -ne 'Valid') {
                    Write-Host "    [!] Invalid Module: $($module.FileName)" -Fore Red
                } else {
                    Write-Host "    [!] Module: $($module.FileName)" -Fore Green 
                }
            }
        }
    
        $continue = $true 
        while ($continue) {
            if ([console]::KeyAvailable) {
                $key = [System.Console]::ReadKey($true)
                if ($key.Key -eq 'Enter') {
                    $continue = $false
                }
            }
            else { Start-Sleep -Seconds 1 }
        }
    }    
    END {
        Get-EventSubscriber | Unregister-Event
        Remove-Job *
    }
}

function Copy-OnCreate {
    $filter = '*.*'
    $tempPath = "$env:WINDIR\Temp"
    $appDataPath = [System.IO.Path]::Combine($env:USERPROFILE, 'AppData')
    $publicPath = "$env:PUBLIC"
    $programDataPath = "$env:PROGRAMDATA"

    $tempFSW = New-Object IO.FileSystemWatcher $tempPath, $filter -Property @{
        IncludeSubdirectories = $true
        NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'
    }
    $appDataFSW = New-Object IO.FileSystemWatcher $appDataPath, $filter -Property @{
        IncludeSubdirectories = $true 
        NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite' 
    }
    $publicFSW = New-Object IO.FileSystemWatcher $publicPath, $filter -Property @{
        IncludeSubdirectories = $true 
        NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'
    }
    $programDataFSW = New-Object IO.FileSystemWatcher $programDataPath, $filter -Property @{
        IncludeSubdirectories = $true 
        NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'
    }
    
    Register-ObjectEvent $tempFSW Created -SourceIdentifier TempFileCreated -Action {
        $fName = $Event.SourceEventArgs.Name 
        $fullPath = $Event.SourceEventArgs.FullPath 

        Write-Host "[>] File created: '$fullPath'" -Fore Magenta
        try {
            Copy-Item -Path $fullPath -Destination "$PSScriptRoot\copied_files" 
            Write-Host "    [+] Copy success" -Fore Green 
        } catch {
            Write-Host "    [!] Failed copy - $_" -Fore DarkRed
        }
    }

    Register-ObjectEvent $appDataFSW Created -SourceIdentifier AppDataFileCreated -Action {
        $fName = $Event.SourceEventArgs.Name 
        $fullPath = $Event.SourceEventArgs.FullPath 

        Write-Host "[>] File created: '$fullPath'" -Fore Magenta
        try {
            Copy-Item -Path $fullPath -Destination "$PSScriptRoot\copied_files" 
            Write-Host "    [+] Copy success" -Fore Green 
        } catch {
            Write-Host "    [!] Failed copy - $_" -Fore DarkRed
        }
    }

    Register-ObjectEvent $publicFSW Created -SourceIdentifier PublicFileCreated -Action {
        $fName = $Event.SourceEventArgs.Name 
        $fullPath = $Event.SourceEventArgs.FullPath 

        Write-Host "[>] File created: '$fullPath'" -Fore Magenta 
        try {
            Copy-Item -Path $fullPath -Destination "$PSScriptRoot\copied_files"
            Write-Host "    [+] Copy success" -Fore Green 
        } catch {
            Write-Host "    [!] Failed copy - $_" -Fore DarkRed 
        }
    }
    
    Register-ObjectEvent $programDataFSW Created -SourceIdentifier ProgramDataFileCreated -Action {
        $fName = $Event.SourceEventArgs.Name 
        $fullPath = $Event.SourceEventArgs.FullPath 

        Write-Host "[>] File created: '$fullPath'" -Fore Magenta 
        try {
            Copy-Item -Path $fullPath -Destination "$PSScriptRoot\copied_files"
            Write-Host "    [+] Copy success" -Fore Green 
        } catch {
            Write-Host "    [!] Failed copy - $_" -Fore DarkRed 
        }
    }
}

function Extract-USNJournal {
    [CmdletBinding()]
    param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$blDirectory
    )

    $dotNetRuntimes = dotnet --list-runtimes
    $dn6Installed = $dotNetRuntimes -like "*Microsoft.NETCore.App 6.*"
    if (-not $dn6Installed) {
        try {
            winget install --id=Microsoft.DotNet.Runtime.6 -e
        } catch {
            Write-Error "[!] Error installing DotNet6 Runtime for MFTECmd $_"
            Write-Host "[>] Skipping USNJournal"
            return
        }
    }
    
    if (Test-Path "ExtractUsnJrnl64.exe") {
        cmd /c ExtractUsnJrnl64.exe /DevicePath:c: /OutputName:usnjrnl.bin | Out-Null
    } else { Write-Warning "[!] Missing ExtractUsnJrnl64.exe, skipping"}
    
    if (Test-Path "MFTECmd.exe") {
        cmd /c MFTECmd.exe -f usnjrnl.bin --csv "$blDirectory" --csvf USNJrnl.csv | Out-Null
    } else { Write-Warning "[!] Missing MFTECmd.exe, skipping"}
    
    del usnjrnl.bin
}

function Extract-From-Sysmon {
    param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$blDirectory
    )
    
    $isRules = Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -Include 'Parameters' | 
               Where-Object { $_.Property -contains 'Rules' } 
               
    if ($isRules -eq $null) { 
        Write-Warning "[!] Sysmon not detected, skipping" 
        return 
    }	
    
    $cmdLineResults = @()
    $procCreateEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Where-Object { $_.Id -eq 1 }
    foreach ($event in $procCreateEvents) {
        $processXML = [xml]$event.ToXml()
        $properties = @{
            ParentCmdLine = $processXML.Event.EventData.Data[21].'#text'
            CMDLine = $processXML.Event.EventData.Data[10].'#text'
        }
        $cmdLineResults += New-Object -Type PSObject -Property $properties
    }
    $cmdLineResults | Export-Csv -Path "$blDirectory\SMCmdLine.csv" -NoTypeInformation
    
    $dnsResults = @()
    $dnsEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Where-Object { $_.Id -eq 22 }
    foreach ($event in $dnsEvents) {
        $processXML = [xml]$event.ToXml()
        $properties = @{
            Query = $processXML.Event.EventData.Data[4].'#text'
        }
        $dnsResults += New-Object -Type PSObject -Property $properties
    }
    $dnsResults | Export-Csv -Path "$blDirectory\SMDNS.csv" -NoTypeInformation
    
    $imgLoadResults = @()
    $imgLoadEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Where-Object { $_.Id -eq 7 }
    foreach ($event in $imgLoadEvents) {
        $processXML = [xml]$event.ToXml()
        $properties = @{
            Image = $processXML.Event.EventData.Data[4].'#text'
            ImageLoaded = $processXML.Event.EventData.Data[5].'#text'
            OrigFile = $processXML.Event.EventData.Data[10].'#text'
        }
        $imgLoadResults += New-Object -Type PSObject -Property $properties
    }
    $imgLoadResults | Export-Csv -Path "$blDirectory\SMImgLoad.csv" -NoTypeInformation
}
 

function Get-Addresses {
    $unicodeExp = [Regex] "[\u0020-\u007E]{7,}"
    $asciiExp = [Regex] "[\x20-\x7E]{7,}"
    $ipExp = [Regex] '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$'
    $urlExp = [Regex] '^(http|https)://.*$'
    $ftpsExp = [Regex] "/^(ftps?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/"

    $procs = Get-CimInstance -Class Win32_Process | Where-Object { $null -ne $_.Path } | Select-Object -Unique Path

    $results = @()
    try {
        foreach ($proc in $procs) {
            $path = $proc.Path
            $unicodeContent = Get-Content -Encoding Unicode -Path $path 
            if ($unicodeContent) {
                $matches = $unicodeExp.Matches($unicodeContent).Value
                foreach ($match in $matches) {
                    if ($ipExp.IsMatch($match)) {
                        $results += [PSCustomObject]@{
                            MatchedString   = $match
                            ProcessPath     = $path
                            Type            = "IP Address"
                        }
                    } elseif ($urlExp.IsMatch($match)) {
                        $results += [PSCustomObject]@{
                            MatchedString   = $match
                            ProcessPath     = $path
                            Type            = "URL"
                        }
                    } elseif ($ftpsExp.IsMatch($match)) {
                        $results += [PSCustomObject]@{
                            MatchedString   = $match 
                            ProcessPath     = $path 
                            Type            = "FTPS"
                        }
                    }
                }
            }

            $asciiContent = Get-Content -Encoding UTF7 -Path $path 
            if ($asciiContent) {
                $matches = $asciiExp.Matches($asciiContent).Value
                foreach ($match in $matches) {
                    if ($ipExp.IsMatch($match)) {
                        $results += [PSCustomObject]@{
                            MatchedString   = $match
                            ProcessPath     = $path
                            Type            = "IP Address"
                        }
                    } elseif ($urlExp.IsMatch($match)) {
                        $results += [PSCustomObject]@{
                            MatchedString   = $match
                            ProcessPath     = $path
                            Type            = "URL"
                        }
                    } elseif ($ftpsExp.IsMatch($match)) {
                        $results += [PSCustomObject]@{
                            MatchedString   = $match 
                            ProcessPath     = $path 
                            Type            = "FTPS"
                        }
                    }
                }
            }
        }
    } catch { Write-Host $_ }
    return $results
}

function Get-RootThumprints {
# https://posts.specterops.io/what-is-it-that-makes-a-microsoft-executable-a-microsoft-executable-b43ac612195e

    $rootThumbprints = @()
    $bins = Get-ChildItem -Path "C:\Windows\System32\*.exe" -Recurse -Force
    $bins += Get-ChildItem -Path "C:\Windows\SysWOW64\*.dll" -Recurse -Force
    $bins += Get-ChildItem -Path "C:\Windows\SysWOW64\*.exe" -Recurse -Force
    
    foreach ($bin in $bins) {
        $path = $bin.FullName
        $fileInfo = Get-Item -Path $path  
        $verInfo = $fileInfo.VersionInfo 
        $originalName = $verInfo.OriginalFilename 
        $signatureInfo = Get-AuthenticodeSignature $path

        $rootThumprint = $null 
        if ($signatureInfo.SignerCertificate) {
            $signerCert = $signatureInfo.SignerCertificate
            $signerChain = New-Object -TypeName Security.Cryptography.X509Certificates.X509Chain
            $null = $signerChain.Build($signerCert)

            $rootCert = $signerChain.ChainElements[$signerChain.ChainElements.Count - 1].Certificate
            $rootTumbprint = $rootCert.Thumbprint
            if ($rootThumbprint -eq $null) { $rootThumbprint = "None" }
        }

        $rootThumbprints += [PSCustomObject]@{
            RootThumbprint  = $rootTumbprint 
            FileName        = $fileInfo.Name 
            OriginalName    = $originalName
        } 
    }
    return $rootThumbprints
}

function Kill-Edge {
    foreach ($service in (Get-Service -Name "*edge*" | Where-Object { $_.DisplayName -like "*Microsoft Edge*" }).Name) {
        Stop-Service -Name $service -Force
    }
    foreach ($proc in (Get-Process | Where-Object {($_.Path -like "$([Environment]::GetFolderPath('ProgramFilesX86'))\Microsoft\*") `
        -or ($_.Name -like "*msedge*")}).Id) {
            Stop-Process -Id $proc -Force 
    }
}

#Requires -RunAsAdministrator 
$ErrorActionPreference = "SilentlyContinue"

$isRules = Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -Include 'Parameters' | 
           Where-Object { $_.Property -contains 'Rules' }
if ($isRules -ne $null) {
    Write-Host "[>] Sysmon detected" -Fore Green 
    $clearSysmon = Read-Host "[?] Clear sysmon logs before starting? [y/n]" 
    if ($clearSysmon -eq 'y') {
        wevtutil cl "Microsoft-Windows-Sysmon/Operational"
    }
}
               
Kill-Edge

Write-Host "`n[>] Exporting first round of baselines.." -Fore Green
$stampOne = Get-Date -Format "yyyyMMdd_HHmmss"
$blDirOne = New-Item -Path "$PSScriptRoot\baselines_$stampOne" -ItemType Directory
Export-Baselines $blDirOne

$copiedFilesOutputDir = "$PSScriptRoot\copied_files"
$sieveOutputDir = "$PSScriptRoot\sieve_output"
if (-not(Test-Path $copiedFilesOutputDir)) { New-Item -Path $copiedFilesOutputDir -ItemType Directory | Out-Null }
if (-not(Test-Path $sieveOutputDir)) { New-Item -Path $sieveOutputDir -ItemType Directory | Out-Null }

Check-NewProcs
Write-Host "[>] Process monitoring stopped!" -Fore Cyan 
Read-Host "`n[+] Hit any key to run the second round of baselines"

Write-Host "[>] Exporting second round of baselines.." -Fore Green
$stampTwo = Get-Date -Format "yyyyMMdd_HHmmss"
$blDirTwo = New-Item -Path "$PSScriptRoot\baselines_$stampTwo" -ItemType Directory
Export-Baselines $blDirTwo

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = New-Item -Path "$PSScriptRoot\report_$stamp.txt" -ItemType File
New-Item -Path $reportPath -ItemType File

Write-Host "[>] Printing results..`n" -Fore Green
Compare-Baselines $blDirOne $blDirTwo $reportPath


