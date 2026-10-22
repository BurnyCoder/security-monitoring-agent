# Global: collect Windows installation evidence without repairs. Local: use registry/CIM read APIs.
# Sources: https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix
$ErrorActionPreference = 'Stop' # Local: each failed scope is caught independently below.
$result = @{os=@{}; apps=@(); appx=@(); hotfixes=@(); errors=@()} # Global: one JSON result carries evidence and gaps.
try { # Local: isolate operating-system discovery from application discovery.
    $version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' # Local: obtain the installed build and revision.
    $os = Get-CimInstance Win32_OperatingSystem # Local: OS inventory avoids the repair-triggering Win32_Product class.
    $result.os = @{name=$os.Caption; build=($version.CurrentBuildNumber + '.' + $version.UBR); edition=$version.EditionID; display_version=$version.DisplayVersion; architecture=$os.OSArchitecture} # Global: exact branch/build evidence supports vendor applicability.
} catch { $result.errors += @{component='windows_os'; detail=$_.Exception.Message} } # Local: expose OS failure.
$paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') # Global: cover system/current-user and both registry views.
foreach ($path in $paths) { # Local: process independent registry scopes.
    try { # Local: one unavailable registry scope does not discard other applications.
        if (Test-Path $path) { # Local: nonexistent install scopes are normal.
            $result.apps += @(Get-ItemProperty $path | Where-Object DisplayName | ForEach-Object { @{name=$_.DisplayName; version=[string]$_.DisplayVersion; publisher=[string]$_.Publisher; location=$_.PSPath} }) # Global: preserve occurrence identities even when names repeat.
        } # Local: complete this optional registry scope.
    } catch { $result.errors += @{component='windows_registry'; detail=($path + ': ' + $_.Exception.Message)} } # Local: retain scope-specific gap.
} # Local: finish registry enumeration.
try { # Local: Store/MSIX applications use a separate inventory interface.
    $result.appx = @(Get-AppxPackage | ForEach-Object { @{name=$_.Name; version=[string]$_.Version; publisher=[string]$_.Publisher; location=$_.PackageFullName} }) # Global: collect current-user packages without requesting elevation.
} catch { $result.errors += @{component='windows_appx'; detail=$_.Exception.Message} } # Local: retain AppX gap.
try { # Local: hotfixes provide supplementary evidence only.
    $result.hotfixes = @(Get-HotFix | ForEach-Object { [string]$_.HotFixID }) # Global: missing KBs cannot establish vulnerability or supersedence.
} catch { $result.errors += @{component='windows_hotfixes'; detail=$_.Exception.Message} } # Local: preserve unavailable KB coverage.
$result | ConvertTo-Json -Depth 6 -Compress # Global: return complete structured evidence to Python.
