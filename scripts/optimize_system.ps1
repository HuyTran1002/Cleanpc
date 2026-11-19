param(
    [ValidateSet("Optimize", "Restore")]
    [string]$Action = "Optimize"
)

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackupPath = Join-Path $ScriptDir "backup_original_settings.json"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PowerCfgValues {
    param([string]$Subgroup, [string]$Setting)
    $out = & powercfg /q SCHEME_CURRENT $Subgroup $Setting 2>&1 | Out-String
    $ac = $null
    $dc = $null
    if ($out -match "Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)") {
        $ac = [Convert]::ToInt32($Matches[1], 16)
    }
    if ($out -match "Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)") {
        $dc = [Convert]::ToInt32($Matches[1], 16)
    }
    return @{ AC = $ac; DC = $dc }
}

function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-RegString {
    param([string]$Path, [string]$Name, [string]$Value)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

function Get-RegValueOrNull {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path $Path)) { return $null }
    $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $prop) { return $null }
    return $prop.$Name
}

function Get-TargetBackgroundAppPaths {
    $paths = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $staticCandidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\CocCoc\Browser\Application\browser.exe",
        "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\Programs\Opera\opera.exe",
        "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe",
        "$env:LOCALAPPDATA\Programs\Antigravity\Antigravity.exe",
        "$env:ProgramFiles\Antigravity\Antigravity.exe",
        "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe"
    )
    foreach ($p in $staticCandidates) {
        if ($p -and (Test-Path $p)) { [void]$paths.Add($p) }
    }

    $discordBase = "$env:LOCALAPPDATA\Discord"
    if (Test-Path $discordBase) {
        Get-ChildItem -Path $discordBase -Filter "Discord.exe" -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$paths.Add($_.FullName)
        }
    }

    $webviewBase = "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application"
    if (Test-Path $webviewBase) {
        Get-ChildItem -Path $webviewBase -Filter "msedgewebview2.exe" -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$paths.Add($_.FullName)
        }
    }

    $procNames = @("chrome.exe", "msedge.exe", "browser.exe", "msedgewebview2.exe", "IDMLite.exe", "steamwebhelper.exe", "Discord.exe", "Antigravity.exe")
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $procNames -and $_.ExecutablePath } | ForEach-Object {
        if (Test-Path $_.ExecutablePath) {
            [void]$paths.Add($_.ExecutablePath)
        }
    }

    return @($paths)
}

function Merge-DxGlobalSettings {
    param([string]$Existing)
    $map = [ordered]@{}
    if (-not [string]::IsNullOrWhiteSpace($Existing)) {
        foreach ($pair in ($Existing -split ";")) {
            if ($pair -match "^\s*([^=]+?)\s*=\s*(.+?)\s*$") {
                $map[$Matches[1]] = $Matches[2]
            }
        }
    }
    $map["SwapEffectUpgradeEnable"] = "1"
    $map["VRROptimizeEnable"] = "1"
    return (($map.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ";") + ";"
}

function Invoke-NvidiaOptimizer {
    param([ValidateSet("Optimize", "Restore")][string]$Mode)
    $nvScript = Join-Path $ScriptDir "optimize_nvidia.py"
    if (-not (Test-Path $nvScript)) {
        Write-Host "      [Bo qua] Khong tim thay $nvScript" -ForegroundColor DarkGray
        return
    }
    $pyExe = $null
    foreach ($cand in @("python", "py", "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { $pyExe = $cmd.Source; break }
        if (Test-Path $cand) { $pyExe = $cand; break }
    }
    if (-not $pyExe) {
        Write-Host "      [Canh bao] Khong tim thay Python de chay toi uu NVIDIA NVAPI." -ForegroundColor Yellow
        return
    }
    & $pyExe $nvScript --action $Mode
    if ($LASTEXITCODE -ne 0) {
        Write-Host "      [Canh bao] Khong the cap nhat NVIDIA Profile (ma loi $LASTEXITCODE)." -ForegroundColor Yellow
    }
}

if (-not (Test-IsAdmin)) {
    Write-Host "[ERROR] Script can chay voi quyen Administrator!" -ForegroundColor Red
    exit 1
}

$gfxDriversPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
$gameBarPath     = "HKCU:\Software\Microsoft\GameBar"
$gameCfgPath     = "HKCU:\System\GameConfigStore"
$gameDvrPath     = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
$gpuPrefPath     = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"
$personalizePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
$uwpBgPath       = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
$edgePolicyPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$intelGfxSub     = "44f3beca-a7c0-460e-9df2-bb8b99e0cba6"
$intelGfxSet     = "3619c3f2-afb2-4afc-b0e9-e7fef372de36"

if ($Action -eq "Optimize") {
    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host "   TOI UU HIEU NANG & NHIET DO (GAMING + LAM VIEC MAT MAY)" -ForegroundColor Cyan
    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host ""

    $appPaths = Get-TargetBackgroundAppPaths

    # 1. Backup original settings once before making changes
    if (-not (Test-Path $BackupPath)) {
        Write-Host "[1/8] Dang sao luu cau hinh goc de co the khoi phuc..." -ForegroundColor Yellow
        $gpuPrefBackup = @{}
        foreach ($exe in $appPaths) {
            $gpuPrefBackup[$exe] = Get-RegValueOrNull -Path $gpuPrefPath -Name $exe
        }
        $backup = @{
            Timestamp = (Get-Date).ToString("o")
            Power = @{
                PROCTHROTTLEMIN = Get-PowerCfgValues -Subgroup "SUB_PROCESSOR" -Setting "PROCTHROTTLEMIN"
                PROCTHROTTLEMAX = Get-PowerCfgValues -Subgroup "SUB_PROCESSOR" -Setting "PROCTHROTTLEMAX"
                PERFBOOSTMODE   = Get-PowerCfgValues -Subgroup "SUB_PROCESSOR" -Setting "PERFBOOSTMODE"
                PROCFREQMAX     = Get-PowerCfgValues -Subgroup "SUB_PROCESSOR" -Setting "75b0ae3f-bce0-45a7-8c89-c9611c25e100"
                PROCFREQMAX1    = Get-PowerCfgValues -Subgroup "SUB_PROCESSOR" -Setting "75b0ae3f-bce0-45a7-8c89-c9611c25e101"
                ASPM            = Get-PowerCfgValues -Subgroup "SUB_PCIEXPRESS" -Setting "ASPM"
                INTEL_GFX       = Get-PowerCfgValues -Subgroup $intelGfxSub -Setting $intelGfxSet
            }
            Registry = @{
                HwSchMode                 = Get-RegValueOrNull -Path $gfxDriversPath -Name "HwSchMode"
                AutoGameModeEnabled       = Get-RegValueOrNull -Path $gameBarPath -Name "AutoGameModeEnabled"
                AllowAutoGameMode         = Get-RegValueOrNull -Path $gameBarPath -Name "AllowAutoGameMode"
                GameDVR_Enabled           = Get-RegValueOrNull -Path $gameCfgPath -Name "GameDVR_Enabled"
                AppCaptureEnabled         = Get-RegValueOrNull -Path $gameDvrPath -Name "AppCaptureEnabled"
                DirectXUserGlobal         = Get-RegValueOrNull -Path $gpuPrefPath -Name "DirectXUserGlobalSettings"
                EnableTransparency        = Get-RegValueOrNull -Path $personalizePath -Name "EnableTransparency"
                UwpGlobalUserDisabled     = Get-RegValueOrNull -Path $uwpBgPath -Name "GlobalUserDisabled"
                EdgeBackgroundModeEnabled = Get-RegValueOrNull -Path $edgePolicyPath -Name "BackgroundModeEnabled"
                EdgeStartupBoostEnabled   = Get-RegValueOrNull -Path $edgePolicyPath -Name "StartupBoostEnabled"
                ChromeBackgroundMode      = Get-RegValueOrNull -Path $chromePolicyPath -Name "BackgroundModeEnabled"
                AppGpuPreferences         = $gpuPrefBackup
            }
        }
        $backup | ConvertTo-Json -Depth 6 | Set-Content -Path $BackupPath -Encoding UTF8
        Write-Host "      -> Da luu ban sao luu tai: $BackupPath" -ForegroundColor Green
    } else {
        Write-Host "[1/8] Da co ban sao luu cau hinh goc, bo qua buoc backup." -ForegroundColor DarkGray
    }

    # 2. Power Plan Tuning (Sweet-spot 3800 MHz Turbo Cap on AC & DC to eliminate 97C voltage spikes)
    Write-Host "[2/8] Dang tinh chinh CPU (Diem ngot 3800 MHz), PCIe & Intel iGPU Power Plan..." -ForegroundColor Yellow
    & powercfg -attributes SUB_PROCESSOR PERFBOOSTMODE -ATTRIB_HIDE 2>$null | Out-Null
    & powercfg -attributes SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e100 -ATTRIB_HIDE 2>$null | Out-Null
    & powercfg -attributes SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e101 -ATTRIB_HIDE 2>$null | Out-Null
    # AC (Plugged in): 5% min idle, 100% max, Efficient Aggressive (4) boost, 3800 MHz cap, PCIe ASPM Off (0), Intel iGPU Max Perf (2)
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 4
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e100 3800
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e101 3800
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0
    & powercfg /setacvalueindex SCHEME_CURRENT $intelGfxSub $intelGfxSet 2 2>$null | Out-Null
    # DC (Battery): 5% min idle, 100% max, Efficient Aggressive (4) boost, 3800 MHz cap, PCIe ASPM Max Savings (2), Intel iGPU Max Battery (0)
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 4
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e100 3800
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e101 3800
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 2
    & powercfg /setdcvalueindex SCHEME_CURRENT $intelGfxSub $intelGfxSet 0 2>$null | Out-Null
    & powercfg /setactive SCHEME_CURRENT
    Write-Host "      -> AC: Min 5% | Max 100% | Boost: Efficient Aggressive | Cap: 3800 MHz | ASPM: Off" -ForegroundColor Green
    Write-Host "      -> DC: Min 5% | Max 100% | Boost: Efficient Aggressive | Cap: 3800 MHz | ASPM: Max Sav" -ForegroundColor Green

    # 3. Disable Hardware-Accelerated GPU Scheduling (HwSchMode = 1) to avoid P0 idle lock & CPU Latency Hint heat
    Write-Host "[3/8] Dang tat Hardware-Accelerated GPU Scheduling (HwSchMode = 1)..." -ForegroundColor Yellow
    Set-RegDword -Path $gfxDriversPath -Name "HwSchMode" -Value 1
    Write-Host "      -> Da dat HAGS = OFF (co hieu luc sau khi khoi dong lai may)." -ForegroundColor Green

    # 4. Keep Windows Game Mode OFF (let Intel Thread Director schedule P/E cores coolly) & Disable Game DVR
    Write-Host "[4/8] Dang tat Game Mode & tat quay nen Game DVR..." -ForegroundColor Yellow
    Set-RegDword -Path $gameBarPath -Name "AutoGameModeEnabled" -Value 0
    Set-RegDword -Path $gameBarPath -Name "AllowAutoGameMode" -Value 0
    Set-RegDword -Path $gameCfgPath -Name "GameDVR_Enabled" -Value 0
    Set-RegDword -Path $gameDvrPath -Name "AppCaptureEnabled" -Value 0
    $existingDxGlobal = Get-RegValueOrNull -Path $gpuPrefPath -Name "DirectXUserGlobalSettings"
    $mergedDxGlobal = Merge-DxGlobalSettings -Existing $existingDxGlobal
    Set-RegString -Path $gpuPrefPath -Name "DirectXUserGlobalSettings" -Value $mergedDxGlobal
    Write-Host "      -> Game Mode: OFF | Game DVR: OFF | $mergedDxGlobal" -ForegroundColor Green

    # 5. Disable Windows Transparency & UWP Background Apps
    Write-Host "[5/8] Dang tat hieu ung trong suot & app UWP chay nen..." -ForegroundColor Yellow
    Set-RegDword -Path $personalizePath -Name "EnableTransparency" -Value 0
    Set-RegDword -Path $uwpBgPath -Name "GlobalUserDisabled" -Value 1
    Write-Host "      -> Transparency: OFF | UWP Background Apps: OFF" -ForegroundColor Green

    # 6. Disable Chrome / Edge background processes & Startup Boost
    Write-Host "[6/8] Dang tat che do chay nen cua trinh duyet (Edge & Chrome)..." -ForegroundColor Yellow
    Set-RegDword -Path $edgePolicyPath -Name "BackgroundModeEnabled" -Value 0
    Set-RegDword -Path $edgePolicyPath -Name "StartupBoostEnabled" -Value 0
    Set-RegDword -Path $chromePolicyPath -Name "BackgroundModeEnabled" -Value 0
    Write-Host "      -> Edge Startup Boost & Chrome/Edge Background Mode: OFF" -ForegroundColor Green

    # 7. Route browsers & background utilities to Intel Iris Xe (Power Saving), and FORCE Games to NVIDIA RTX 3060 (High Performance)
    Write-Host "[7/8] Dang tach iGPU cho app nen va ep 100% Game chay card roi RTX 3060..." -ForegroundColor Yellow
    $safeIgpuNames = @("chrome.exe", "msedge.exe", "browser.exe", "brave.exe", "opera.exe", "code.exe", "antigravity.exe", "idman.exe", "idmlite.exe", "discord.exe", "msedgewebview2.exe", "steamwebhelper.exe")
    foreach ($exe in $appPaths) {
        Set-RegString -Path $gpuPrefPath -Name $exe -Value "GpuPreference=1;"
        Write-Host "      -> iGPU Power Saving: $(Split-Path -Leaf $exe)" -ForegroundColor Gray
    }

    if (Test-Path $gpuPrefPath) {
        $prefProps = (Get-Item -Path $gpuPrefPath).Property
        foreach ($propName in $prefProps) {
            if ($propName -match "\.exe$") {
                $baseName = (Split-Path -Leaf $propName).ToLowerInvariant()
                if ($safeIgpuNames -notcontains $baseName) {
                    $curVal = Get-RegValueOrNull -Path $gpuPrefPath -Name $propName
                    if ($curVal -match "GpuPreference=1") {
                        Set-RegString -Path $gpuPrefPath -Name $propName -Value "GpuPreference=2;"
                        Write-Host "      -> Fix Game sang RTX 3060: $baseName" -ForegroundColor Cyan
                    }
                }
            }
        }
    }

    $gameExes = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $knownGames = @("D:\NG Launcher\Mod Library\New Legacy\GTA5.exe")
    foreach ($g in $knownGames) {
        if (Test-Path $g) { [void]$gameExes.Add($g) }
    }
    Get-ChildItem "HKCU:\System\GameConfigStore\Children" -ErrorAction SilentlyContinue | ForEach-Object {
        $gPath = (Get-ItemProperty -Path $_.PSPath -Name "MatchedExeFullPath" -ErrorAction SilentlyContinue).MatchedExeFullPath
        if ($gPath -and (Test-Path $gPath)) {
            $gBase = (Split-Path -Leaf $gPath).ToLowerInvariant()
            if ($safeIgpuNames -notcontains $gBase) {
                [void]$gameExes.Add($gPath)
            }
        }
    }
    foreach ($gExe in $gameExes) {
        Set-RegString -Path $gpuPrefPath -Name $gExe -Value "GpuPreference=2;"
        Write-Host "      -> RTX 3060 High Perf: $(Split-Path -Leaf $gExe)" -ForegroundColor Green
    }

    # 8. Optimize NVIDIA Control Panel Global Profile via NVAPI DRS
    Write-Host "[8/8] Dang toi uu toan bo thiet lap NVIDIA Control Panel (NVAPI)..." -ForegroundColor Yellow
    Invoke-NvidiaOptimizer -Mode "Optimize"

    Write-Host ""
    if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
        Write-Host "[Trang thai GPU NVIDIA hien tai]" -ForegroundColor Cyan
        & nvidia-smi --query-gpu=name,pstate,temperature.gpu,power.draw,clocks.gr --format=csv,noheader
    }

    Write-Host ""
    Write-Host "=====================================================================" -ForegroundColor Green
    Write-Host " HOAN TAT TOI UU TOAN BO HE THONG & NVIDIA!" -ForegroundColor Green
    Write-Host " 1. Khoi dong lai may (Restart) 1 lan de HAGS (HwSchMode=1) va Optimus" -ForegroundColor White
    Write-Host "    cap nhat day du cho cac tien trinh desktop." -ForegroundColor White
    Write-Host " 2. Neu muon hoan tac ve nhu cu, chay file: restore_system_defaults.bat" -ForegroundColor White
    Write-Host "=====================================================================" -ForegroundColor Green
}
elseif ($Action -eq "Restore") {
    function Restore-RegDword {
        param([string]$Path, [string]$Name, $Value)
        if ($null -ne $Value) {
            Set-RegDword -Path $Path -Name $Name -Value ([int]$Value)
        } else {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        }
    }

    Write-Host "=====================================================================" -ForegroundColor Yellow
    Write-Host "   KHOI PHUC CAU HINH NANG LUONG & GPU VE MAC DINH BAN DAU" -ForegroundColor Yellow
    Write-Host "=====================================================================" -ForegroundColor Yellow
    Write-Host ""

    if (-not (Test-Path $BackupPath)) {
        Write-Host "[CANH BAO] Khong tim thay file sao luu ($BackupPath)." -ForegroundColor Yellow
        Write-Host "Dang dat lai Power Plan Balanced ve gia tri chuan Windows..." -ForegroundColor Yellow
        & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5
        & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5
        & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
        & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
        & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2
        & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2
        & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e100 0
        & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e100 0
        & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e101 0
        & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e101 0
        & powercfg /setacvalueindex SCHEME_CURRENT $intelGfxSub $intelGfxSet 1 2>$null | Out-Null
        & powercfg /setdcvalueindex SCHEME_CURRENT $intelGfxSub $intelGfxSet 1 2>$null | Out-Null
        & powercfg /setactive SCHEME_CURRENT
        Write-Host "Da khoi phuc Power Plan." -ForegroundColor Green
        exit 0
    }

    $b = Get-Content -Path $BackupPath -Raw -Encoding UTF8 | ConvertFrom-Json

    if ($null -ne $b.Power.PROCTHROTTLEMIN.AC) { & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN $b.Power.PROCTHROTTLEMIN.AC }
    if ($null -ne $b.Power.PROCTHROTTLEMIN.DC) { & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN $b.Power.PROCTHROTTLEMIN.DC }
    if ($null -ne $b.Power.PROCTHROTTLEMAX.AC) { & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX $b.Power.PROCTHROTTLEMAX.AC }
    if ($null -ne $b.Power.PROCTHROTTLEMAX.DC) { & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX $b.Power.PROCTHROTTLEMAX.DC }
    if ($null -ne $b.Power.PERFBOOSTMODE.AC)   { & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE   $b.Power.PERFBOOSTMODE.AC }
    if ($null -ne $b.Power.PERFBOOSTMODE.DC)   { & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE   $b.Power.PERFBOOSTMODE.DC }
    $freqAc  = if ($null -ne $b.Power.PROCFREQMAX.AC)  { $b.Power.PROCFREQMAX.AC }  else { 0 }
    $freqDc  = if ($null -ne $b.Power.PROCFREQMAX.DC)  { $b.Power.PROCFREQMAX.DC }  else { 0 }
    $freq1Ac = if ($null -ne $b.Power.PROCFREQMAX1.AC) { $b.Power.PROCFREQMAX1.AC } else { 0 }
    $freq1Dc = if ($null -ne $b.Power.PROCFREQMAX1.DC) { $b.Power.PROCFREQMAX1.DC } else { 0 }
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e100 $freqAc
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e100 $freqDc
    & powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e101 $freq1Ac
    & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR 75b0ae3f-bce0-45a7-8c89-c9611c25e101 $freq1Dc
    if ($null -ne $b.Power.ASPM.AC)            { & powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM           $b.Power.ASPM.AC }
    if ($null -ne $b.Power.ASPM.DC)            { & powercfg /setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM           $b.Power.ASPM.DC }
    if ($null -ne $b.Power.INTEL_GFX.AC)       { & powercfg /setacvalueindex SCHEME_CURRENT $intelGfxSub $intelGfxSet      $b.Power.INTEL_GFX.AC 2>$null | Out-Null }
    if ($null -ne $b.Power.INTEL_GFX.DC)       { & powercfg /setdcvalueindex SCHEME_CURRENT $intelGfxSub $intelGfxSet      $b.Power.INTEL_GFX.DC 2>$null | Out-Null }
    & powercfg /setactive SCHEME_CURRENT

    if ($null -ne $b.Registry.HwSchMode) { Set-RegDword -Path $gfxDriversPath -Name "HwSchMode" -Value $b.Registry.HwSchMode }
    if ($null -ne $b.Registry.AutoGameModeEnabled) { Set-RegDword -Path $gameBarPath -Name "AutoGameModeEnabled" -Value $b.Registry.AutoGameModeEnabled }
    Restore-RegDword -Path $gameBarPath -Name "AllowAutoGameMode" -Value $b.Registry.AllowAutoGameMode
    Restore-RegDword -Path $gameCfgPath -Name "GameDVR_Enabled" -Value $b.Registry.GameDVR_Enabled
    Restore-RegDword -Path $gameDvrPath -Name "AppCaptureEnabled" -Value $b.Registry.AppCaptureEnabled
    Restore-RegDword -Path $personalizePath -Name "EnableTransparency" -Value $b.Registry.EnableTransparency
    Restore-RegDword -Path $uwpBgPath -Name "GlobalUserDisabled" -Value $b.Registry.UwpGlobalUserDisabled
    Restore-RegDword -Path $edgePolicyPath -Name "BackgroundModeEnabled" -Value $b.Registry.EdgeBackgroundModeEnabled
    Restore-RegDword -Path $edgePolicyPath -Name "StartupBoostEnabled" -Value $b.Registry.EdgeStartupBoostEnabled
    Restore-RegDword -Path $chromePolicyPath -Name "BackgroundModeEnabled" -Value $b.Registry.ChromeBackgroundMode
    if ($null -ne $b.Registry.DirectXUserGlobal) {
        Set-RegString -Path $gpuPrefPath -Name "DirectXUserGlobalSettings" -Value $b.Registry.DirectXUserGlobal
    }

    if ($null -ne $b.Registry.AppGpuPreferences) {
        foreach ($prop in $b.Registry.AppGpuPreferences.PSObject.Properties) {
            if ($null -eq $prop.Value -or $prop.Value -eq "") {
                Remove-ItemProperty -Path $gpuPrefPath -Name $prop.Name -ErrorAction SilentlyContinue
            } else {
                Set-RegString -Path $gpuPrefPath -Name $prop.Name -Value $prop.Value
            }
        }
    }

    Write-Host "Dang khoi phuc cau hinh NVIDIA Control Panel..." -ForegroundColor Yellow
    Invoke-NvidiaOptimizer -Mode "Restore"

    Write-Host "Da khoi phuc toan bo thiet lap Windows & NVIDIA ve nguyen ban!" -ForegroundColor Green
}
