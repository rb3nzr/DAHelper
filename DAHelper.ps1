<#
.DESCRIPTION
[+] Sets a series of baselines.
[+] Creates a WMI event to monitor newly created processes.
    -> Runs pe-sieve over all newly created processes.
[+] Creates filesystem watcher events.
    -> Copies created files to a directory.
[+] Sets a second series of baselines
[+] Checks for diffs between baselines, prints and logs results.

.LINK
Tools used:
- https://github.com/hasherezade/pe-sieve/releases/tag/v0.3.9
- https://github.com/jschicht/ExtractUsnJrnl?tab=readme-ov-file
- https://github.com/EricZimmerman/MFTECmd

.NOTES 
[!] If hitting [Enter] once doesn't trigger the closing of events and the 
start of the second round of baselines, hit [Enter] again.

[!] Option given on first run to download tools and setup sysmon with a trace config.
If using without network connection, make a copy of the tools
and match or change the paths at the bottom of the script.

.USAGE 
[>] ./DAHelper.ps1 [command] <args>

[Ex] ./DAHelper.ps1 Run-All
[Ex] ./DAHelper.ps1 Compare C:\Temp\baselines_<time> C:\Temp\baselines_<time>

.OPTIONS
[Run-All]
\__ Runs everything in the script
\__ Baselines > Watchers/Process Monitoring > Baselines > Compare

[Watch]
\__ Starts up the only the process monitoring and file creation functions

[Single] <OutputPath>
\__ Runs a single baseline set

[Compare] <Dir 1> <Dir 2>
\__ Compares two previously exported baseline sets

[Help] Print help
#>

param(
    [Parameter(Position=0)]
    [string]$command,
    [Parameter(Position=1)]
    [string]$argPathOne,
    [Parameter(Position=2)]
    [string]$argPathTwo
)

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
        string[] firstFileLines = File.ReadAllLines(blOne);
        string[] secondFileLines = File.ReadAllLines(blTwo);
        string headers = firstFileLines[0];

        for (int i = 1; i < firstFileLines.Length; i++)
        {
            var columns = firstFileLines[i].Split(',');
            if (columns.Length > index)
                fullRowsInFirst[columns[index]] = firstFileLines[i];
        }

        for (int i = 1; i < secondFileLines.Length; i++)
        {
            var columns = secondFileLines[i].Split(',');
            if (columns.Length > index)
                fullRowsInSecond[columns[index]] = secondFileLines[i];
        }

        var newKeys = new List<string> { headers };  
        foreach (var key in fullRowsInSecond.Keys)
        {
            if (!fullRowsInFirst.ContainsKey(key))
                newKeys.Add(fullRowsInSecond[key]);
        }

        var removedKeys = new List<string> { headers }; 
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
    Param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$blDirOne,
        [Parameter(Position=1, Mandatory=$true)]
        [string]$blDirTwo,
        [Parameter(Position=2, Mandatory=$true)]
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
                    '^COMexe'           { 'COM exe' }
                    '^COMdll'           { 'COM dll'}
                    '^DnsCache'         { 'DNS Cache' }
                    '^DLILCOM'          { 'Disabled LowIL Isolation COM' }
                    '^Drivers'          { 'Drivers' }
                    '^EvtConsumers'     { 'Event Consumers' }
                    '^USNJrnl'          { 'Change Journal' }
                    '^FirewallRules'    { 'Firewall Rules' }
                    '^Files'            { 'Files' }
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
                    '^SMCmdLine'        { 'Proc Creation CmdLine' }
                    '^SMDNS'            { 'DNS Query Evts' }
                    '^SMImgLoad'        { 'Image Load Evts' }
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
                
                $printNew = $newEntries.Count -gt 1
                $printRemoved = $removedEntries.Count -gt 1

                if ($printNew -or $printRemoved) {
                    Write-Host $title -Fore Cyan
                    $title | Out-File -FilePath $reportPath -Append
                }

                if ($printNew) {
                    Write-Host $new -Fore Green

                    $headers = $newEntries[0] -split ','

                    $counter = 0
                    foreach ($entry in $newEntries) { 
                        if ($counter -gt 0) {  
                            $color = if ($counter % 2 -eq 0) { "White" } else { "Gray" }
                            $columns = $entry -split ','

                            for ($i = 0; $i -lt $columns.Length; $i++) {
                                Write-Host "$($headers[$i]): $($columns[$i])" -Fore $color
                            }
                            Write-Host ""
                        }
                        $counter++
                    }

                    $new | Out-File -FilePath $reportPath -Append
                    foreach ($entry in $newEntries) { Add-Content -Path $reportPath $entry }
                }

                if ($printRemoved) {
                    Write-Host $removed -Fore Red

                    $headers = $removedEntries[0] -split ','

                    $counter = 0
                    foreach ($entry in $removedEntries) {
                        if ($counter -gt 0) {  
                            $color = if ($counter % 2 -eq 0) { "White" } else { "Gray" }
                            $columns = $entry -split ','

                            for ($i = 0; $i -lt $columns.Length; $i++) {
                                Write-Host "$($headers[$i]): $($columns[$i])" -Fore $color
                            }
                            Write-Host ""
                        }
                        $counter++
                    }

                    $removed | Out-File -FilePath $reportPath -Append
                    foreach ($entry in $removedEntries) { Add-Content -Path $reportPath $entry }
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
    param (
        [Parameter(Position=0)]
        [string]$blDirectory
    )

    BEGIN {
        Write-Host "[>] Starting baseline export.." -Fore Cyan
        Add-Type -TypeDefinition $kernel32
    }

    PROCESS {
        <#
        Write-Host "    [>] Getting streams.." -Fore Magenta
	$streams = Get-ChildItem -Path C:\ -Recurse -Force |
				ForEach-Object { Get-Item -Path $_.FullName -Stream * } |
				Where-Object { ($_.Stream -notlike "*DATA") -and ($_.Stream -ne "Zone.Identifier") }
						
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
        #>
	Write-Host "    [>] Getting files.." -Fore Magenta
	Get-ChildItem -Path C:\Windows -Recurse -Force | 
		Where-Object { $_.FullName -notlike '*\System32\*' -and $_.FullName -notlike '*\SysWOW64\*' -and $_.FullName -notlike '*\WinSxS\*' } | 
		Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -NoTypeInformation
		
	Get-ChildItem -Path C:\ -Force | Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -Append -NoTypeInformation
	Get-ChildItem -Path "C:\Program Files" -Recurse | Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -Append -NoTypeInformation
	Get-ChildItem -Path "C:\Program Files (x86)" -Recurse | Select-Object FullName | Export-Csv -Path "$blDirectory\Files.csv" -Append -NoTypeInformation

        Write-Host "    [>] Getting COM bin file hashes.." -Fore Magenta 
        Get-COMHashes $blDirectory
        
        Write-Host "    [>] Getting USNJournal.." -Fore Magenta
        Extract-USNJournal $blDirectory
        
        Write-Host "    [>] Getting root thumbprints and certs.." -Fore Magenta
        Get-RootThumprints | Export-Csv -Path "$blDirectory\RootTPs.csv" -NoTypeInformation
		#>
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
        $lnks = Get-ChildItem -Path "C:\Users\benzr\Desktop" -File -Recurse | Where-Object { $_.extension -in ".lnk" } | select-Object * 
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
        } catch {
            $errMsg = "[X] $($_.Exception.Message)"
            Write-Host $errMsg -Fore Red
        }
        
        Write-Host "    [>] Getting sysmon events.." -Fore Magenta
        Extract-Sysmon $blDirectory
    }

    END {
        Write-Host "[>] Baselines exported!" -Fore Cyan
    }
}

# --------------------------------- [ Monitoring Functions ] ---------------------------------

function Monitor-CreationEvents {
<#
.DESCRIPTION
[+] Starts a file system watcher for temp directories; copies created files to script root.
[+] Registers a WMI event to monitor new processes that open.
[+] Runs pe-sieve on the process and checks it's loaded modules.
.NOTES 
- Edit the exclusions in the event query.
- Edit pe-sieve args.
#>
    param (
        [Parameter(Position=0)]
        [string]$resultsDir
    )

    BEGIN {
        if (-not(Test-Path -Path "$PSScriptRoot\Tools\pe-sieve64.exe")) {
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
              "AND TargetInstance.Name != 'smartscreen.exe'" +
              "AND TargetInstance.Name != 'RuntimeBroker.exe'" + 
              "AND TargetInstance.Name != 'ApplicationFrameHost.exe'" + 
              "AND TargetInstance.Name != 'backgroundTaskHost.exe'" 
              
        Register-WmiEvent -Query $eventQuery -SourceIdentifier ProcessCreation -Action {
            $process = $event.SourceEventArgs.NewEvent.TargetInstance

            Write-Host "[>] New process started: $($process.Name), PID: $($process.ProcessId)" -Fore Cyan
            cmd /c "$PSScriptRoot\Tools\pe-sieve64.exe" /pid $process.ProcessId /dir "$PSScriptRoot\sieve_output" `
                   /quiet /iat 3 /obfusc 3 /shellc 3 /threads /dmode 3 /imp 1 /minidmp

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
        Get-Job | Remove-Job
        Move-Item -Path "$PSScriptRoot\sieve_output" -Destination $resultsDir -Force 
        Move-Item -Path "$PSScriptRoot\copied_files" -Destination $resultsDir -Force 
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
    
    $action = {
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

    Register-ObjectEvent $tempFSW Created -SourceIdentifier TempFileCreated -Action $action
    Register-ObjectEvent $appDataFSW Created -SourceIdentifier AppDataFileCreated -Action $action
    Register-ObjectEvent $publicFSW Created -SourceIdentifier PublicFileCreated -Action $action
    Register-ObjectEvent $programDataFSW Created -SourceIdentifier ProgramDataFileCreated -Action $action
}

# --------------------------------- [ Functions for Export-Baselines ] ---------------------------------

function Get-COMHashes {
	param (
		[Parameter(Position=0)]
		[string]$blDirectory
	)
	
    $clsidDLL = reg query HKLM\SOFTWARE\Classes\CLSID\ /s /f ".dll" | 
        ForEach-Object { if ($_ -match "([A-Z]:\\.*\.(dll))") { $matches[1] }}
    
    $clsidEXE = reg query HKLM\SOFTWARE\Classes\CLSID\ /s /f ".exe" |
        ForEach-Object { if ($_ -match "([A-Z]:\\.*\.(exe))") { $matches[1] }}

    $clsidDLLResult = @()
    foreach ($path in $clsidDLL) {
        if (Test-Path $path) {
            try {
                $fileHash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            } catch {
                $fileHash = "Error calculating hash"
            }
        } else {
            $fileHash = "File not found"
        }
        $clsidDLLResult += [pscustomobject]@{
            FileHash = $fileHash
            FilePath = $path
        }
    }
    $clsidDLLResult | Export-Csv -Path "$blDirectory\COMdll.csv" -NoTypeInformation

    $clsidEXEResult = @()
    foreach ($path in $clsidEXE) {
        if (Test-Path $path) {
            try {
                $fileHash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            } catch {
                $fileHash = "Error calculating hash"
            }
        } else {
            $fileHash = "File not found"
        }
        $clsidEXEResult += [pscustomobject]@{
            FileHash = $fileHash
            FilePath = $path
        }
    }
    $clsidEXEResult | Export-Csv -Path "$blDirectory\COMexe.csv" -NoTypeInformation
}

function Extract-USNJournal {
    param (
        [Parameter(Position=0)]
        [string]$blDirectory
    )
	
	$dotnetExec = "C:\Program Files\dotnet\dotnet.exe"
    $dotNetRuntimes = & $dotnetExec --list-runtimes
    $dn6Installed = $dotNetRuntimes -like "*Microsoft.NETCore.App 6.*"
    if (-not $dn6Installed) {
        try {
            Write-Host "[>] Installing .NET 6 Runtime" -Fore Green 
            winget install --id=Microsoft.DotNet.Runtime.6 -e
        } catch {
            Write-Error "[!] Error installing .NET 6 Runtime for MFTECmd $_"
            Write-Host "[>] Skipping USNJournal extraction" -Fore Yellow
            return
        }
    }
    
    if (Test-Path $exUsnJrnl) {
        & $exUsnJrnl /DevicePath:c: /OutputName:usnjrnl.bin | Out-Null
    } else { Write-Warning "[!] Missing ExtractUsnJrnl64.exe, skipping"}
    
    if (Test-Path $mfteCmd) {
        & $mfteCmd -f $usnJrnlBin --csv $blDirectory --csvf journal.csv | Out-Null
        $jrnl = Import-Csv -Path "$blDirectory\journal.csv"
        $jrnl | Select-Object Name, FileAttributes | Export-Csv -Path "$blDirectory\USNJrnl.csv" -NoTypeInformation
        Remove-Item -Path "$blDirectory\journal.csv" -Force
    } else { Write-Warning "[!] Missing MFTECmd.exe, skipping"}
    
    Remove-Item -Path $usnJrnlBin -Force 
}

function Extract-Sysmon {
    param (
        [Parameter(Position=0)]
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

            $asciiContent = Get-Content -Encoding UTF7 -Path $path | Out-Null
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
    } catch {
        $errMsg = "[X] $($_.Exception.Message)"
        Write-Host $errMsg -Fore Red
    }
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

# --------------------------------- [ Helper Functions ] ---------------------------------

function Get-Tools {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        function Get-LatestReleaseAssetUrl {
            param (
                [string]$repo,
                [string]$assetPattern
            )
            $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" `
                                             -Headers @{ "User-Agent" = "PowerShell" }
            $asset = $releaseInfo.assets | Where-Object { $_.name -like $assetPattern }
            return $asset.browser_download_url
        }

        $mfteCmdUrl = "https://download.mikestammer.com/MFTECmd.zip"
        Invoke-WebRequest -Uri $mfteCmdUrl -OutFile "$tools\MFTECmd.zip"

        $peSieveUrl = Get-LatestReleaseAssetUrl "hasherezade/pe-sieve" "*pe-sieve64.exe"
        Invoke-WebRequest -Uri $peSieveUrl -OutFile "$tools\pe-sieve64.exe"

        $exUsnJrnlUrl = "https://github.com/jschicht/ExtractUsnJrnl/archive/refs/heads/master.zip"
        Invoke-WebRequest -Uri $exUsnJrnlUrl -OutFile "$tools\ExtractUsnJrnl.zip"

        $sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
        Invoke-WebRequest -Uri $sysmonUrl -OutFile "$tools\sysmon.zip"

        $smTraceConfigUrl = "https://github.com/bakedmuffinman/Neo23x0-sysmon-config/archive/refs/heads/main.zip"
        Invoke-WebRequest -Uri $smTraceConfigUrl -OutFile "$tools\sysmon-configs.zip"

        Expand-Archive -Path "$tools\MFTECmd.zip" -Destination "$tools\MFTECmd" -Force
        Expand-Archive -Path "$tools\ExtractUsnJrnl.zip" -Destination "$tools\ExtractUsnJrnl" -Force 
        Expand-Archive -Path "$tools\sysmon.zip" -Destination "$tools\sysmon" -Force 
        Expand-Archive -Path "$tools\sysmon-configs.zip" -Destination "$tools\sysmon-configs" -Force

        Remove-Item "$tools\MFTECmd.zip" -Force
        Remove-Item "$tools\ExtractUsnJrnl.zip" -Force 
        Remove-Item "$tools\sysmon.zip" -Force
        Remove-Item "$tools\sysmon-configs.zip" -Force

        Write-Host "[>] Tools downloaded" -Fore Green
    } catch {
        $errMsg = "[X] $($_.Exception.Message)"
        Write-Host $errMsg -Fore Red
    }
}

function Kill-Edge {
    $kEdge = Read-Host "[?] Kill Edge processes? [y/n]"
    if ($kEdge -eq 'y') {
        foreach ($service in (Get-Service -Name "*edge*" | Where-Object { $_.DisplayName -like "*Microsoft Edge*" }).Name) {
            Stop-Service -Name $service -Force
        }

        foreach ($proc in (Get-Process | Where-Object {($_.Path -like "$([Environment]::GetFolderPath('ProgramFilesX86'))\Microsoft\*") `
            -or ($_.Name -like "*msedge*")}).Id) {
                Stop-Process -Id $proc -Force 
        }
    } else {
        return
    }
}

function Check-Sysmon {
    $isRules = Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -Include 'Parameters' | 
               Where-Object { $_.Property -contains 'Rules' }

    if ($isRules -ne $null) {
        Write-Host "[>] Sysmon detected" -Fore Green 
        $clearSysmon = Read-Host "[?] Clear sysmon logs before starting? [y/n]" 

        if ($clearSysmon -eq 'y') {
            wevtutil cl "Microsoft-Windows-Sysmon/Operational"
            return 
        } else {
            return
        }
        
    } else {
        Write-Host "[>] Sysmon not detedcted" -Fore Yellow
        $installSysmon = Read-Host "[?] Install with trace config? [y/n]"
        if ($installSysmon -eq 'y') {
            & $sysmon64 -accepteula -i $sysmonConfig
            return 
        } else {
            return 
        }
    }
}

function Check-FirstRun {
    $runFile = Join-Path -Path $PSScriptRoot -ChildPath "has_run.txt"
    if (-not(Test-Path -Path $runFile)) {
        "qwerty123" | Out-File -FilePath $runFile

        Write-Host "[>] First run detected" -Fore Green 
        $install = Read-Host "[?] Install tools? [y/n]"
        if ($install -eq 'y') {
            Get-Tools 
        } else {
            return 
        } 
    } else { 
        return 
    }
}

function Check-EventsAndJobs {
    $subscribers = Get-EventSubscriber 
    $jobs = Get-Job 
    
    if ($subscribers -gt 0) {
        Write-Host "[>] Found event subscribers: " -Fore Yellow
        $subscribers | fl *

        $unregister = Read-Host "[?] Unregister all? [y/n]"
        if ($unregister -eq 'y') {
            $subscribers | ForEach-Object { 
                Unregister-Event -SubscriptionId $_.SubscriptionId
            }
        }
    }

    if ($jobs.Count -gt 0) {
        Write-Host "[>] Found open jobs" -Fore Yellow
        $jobs | fl *

        $remove = Read-Host "[?] Remove all? [y/n]"
        if ($remove -eq 'y') {
            $jobs | ForEach-Object { Remove-Job -Id $_.Id }
        }
    }
}

function Print-Help {
    Write-Host "`n  [DAHelper Options]  `n" -Fore Cyan

    Write-Host "[Run-All]" -Fore Green
    Write-Host "\__ Runs everything in the script" -Fore Magenta
    Write-Host "\__ Baselines > Watchers/Process Monitoring > Baselines > Compare`n" -Fore Magenta

    Write-Host "[Watch]" -Fore Green
    Write-Host "\__ Starts up the only the process monitoring and file creation functions`n" -Fore Magenta

    Write-Host "[Single] <OutputPath>" -Fore Green
    Write-Host "\__ Runs a single baseline set`n" -Fore Magenta

    Write-Host "[Compare] <Dir 1> <Dir 2>" -Fore Green
    Write-Host "\__ Compares two previously exported baseline sets`n" -Fore Magenta

    Write-Host "[Help] To print this menu again`n" -Fore Green

    Write-Host "Example: .\DAHelper.ps1 Compare .\baselines_<time> .\baslines_<time>`n" -Fore Cyan

    Write-Host "Prompts given on a first run:" -Fore Yellow
    Write-Host "-- Option to download tools" -Fore Cyan
    Write-Host "-- Option to install sysmon with a trace config" -Fore Cyan
    Write-Host "-- Option to kill all MS Edge processes`n" -Fore Cyan
}

# --------------------------------- [ Tool Paths ] ---------------------------------

$script:tools = "$PSScriptRoot\Tools"
if (-not(Test-Path $tools)) { New-Item -Path $tools -ItemType Directory | Out-Null }

$script:sieveOutput = "$PSScriptRoot\sieve_output"
$script:copiedFiles = "$PSScriptRoot\copied_files"
$script:sysmonConfig = "$tools\sysmon-configs\Neo23x0-sysmon-config-main\sysmonconfig-trace.xml"
$script:mfteCmd = "$tools\MFTECmd\MFTECmd.exe"
$script:exUsnJrnl = "$tools\ExtractUsnJrnl\ExtractUsnJrnl-master\ExtractUsnJrnl64.exe"
$script:usnJrnlBin = "$tools\ExtractUsnJrnl\ExtractUsnJrnl-master\usnjrnl.bin"
$script:sysmon64 = "$tools\sysmon\Sysmon64.exe"

# --------------------------------- [ Main ] ---------------------------------

function Main {
    param (
        [Parameter(Position=0)]
        [string]$command,
        [Parameter(Position=1)]
        [string]$argPathOne,
        [Parameter(Position=2)]
        [string]$argPathTwo
    )

    if (-not $command) {
        Write-Host "[X] No commands provided" -Fore Red 
        Print-Help 
        exit 
    }

    switch ($command.ToLower()) {
        "run-all" {
            Check-FirstRun
            Check-EventsAndJobs
            Check-Sysmon 
            Kill-Edge  

            $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $resultsDir = "Results_$stamp"
            $reportPath = "results_$stamp.txt"

            New-Item -Path $sieveOutput -ItemType Directory | Out-Null
            New-Item -Path $copiedFiles -ItemType Directory | Out-Null
            New-Item -Path $resultsDir -ItemType Directory | Out-Null 
            New-Item -Path $reportPath -ItemType File | Out-Null 
            
            Write-Host "`n[>] Exporting first round of baselines.." -Fore Green

            $stampOne = Get-Date -Format "yyyyMMdd_HHmmss"
            $blDirOne = "baselines_$stampOne"
            New-Item -Path $blDirOne -ItemType Directory | Out-Null
            Export-Baselines $blDirOne

            Read-Host "`n[+] Hit any key to start processes monitoring`n"

            Monitor-CreationEvents $resultsDir

            Write-Host "[>] Process monitoring stopped!" -Fore Cyan 
            Read-Host "`n[+] Hit any key to run the second round of baselines`n"
            Write-Host "[>] Exporting second round of baselines.." -Fore Green

            $stampTwo = Get-Date -Format "yyyyMMdd_HHmmss"
            $blDirTwo = "baselines_$stampTwo"
            New-Item -Path $blDirTwo -ItemType Directory | Out-Null
            Export-Baselines $blDirTwo

            Write-Host "[>] Printing results..`n" -Fore Green
            Compare-Baselines $blDirOne $blDirTwo $reportPath
            Move-Item -Path $reportPath -Destination $resultsDir -Force
            Move-Item -Path $blDirOne -Destination $resultsDir -Force 
            Move-Item -Path $blDirTwo -Destination $resultsDir -Force
            Write-Host "[>] Results exported to $($resultsDir)" -Fore Green
        }
        "watch" {
            Check-FirstRun
            Check-EventsAndJobs
            Kill-Edge

            $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            New-Item -Path $resultsDir -ItemType Directory | Out-Null

            New-Item -Path $sieveOutput -ItemType Directory | Out-Null 
            New-Item -Path $copiedFile -ItemType Directory | Out-Null 

            Write-Host "[>] Starting event and watchers.." -Fore Green 
            Write-Host "[+] Hit any key to stop" -Fore Green
            Monitor-CreationEvents $resultsDir 
            Write-Host "[>] Results exported to $($resultsDir)" -Fore Green
        }
        "single" {
            if ($argPathOne) {
                Check-FirstRun
                Check-EventsAndJobs 
                Check-Sysmon 
                Kill-Edge 

                $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                $blDir = "$argPathOne\baselines_$stamp"
                New-Item -Path $blDir -ItemType Directory | Out-Null
                 
                Write-Host "`n[>] Setting baselines.." -Fore Green
                Export-Baselines $blDir
                Write-Host "[>] Done!" -Fore Green
                Write-Host "[>] Results in $($blDir)" -Fore Green
            }
            else {
                Write-Host "[X] Error: Single requires the output directory path for the report`n" -Fore Red
                Print-Help
                exit
            }
        }
        "compare" {
            if ($argPathOne -and $argPathTwo) {
                $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                $reportPath = "results_$stamp.txt"
                New-Item -Path $reportPath -ItemType File | Out-Null 

                Write-Host "[>] Starting comparisons" -Fore Green
                Compare-Baselines $argPathOne $argPathTwo $reportPath
            }
            else {
                Write-Host "[X] Error: Compare requires two baseline directory paths`n" -Fore Red
                Print-Help
                exit
            }
        }
        "help" {
            Print-Help
            exit
        }
        default {
            Write-Host "[X] Invalid command!`n" -Fore Red
            Print-Help
            exit
        }
    }
}

#Requires -RunAsAdministrator 
$ErrorActionPreference = "SilentlyContinue"  

switch ($true) {
    { $argPathOne -and $argPathTwo } {
        Main $command $argPathOne $argPathTwo
    }
    { $argPathOne -and -not $argPathTwo } {
        Main $command $argPathOne
    }
    default {
        Main $command
    }
}
