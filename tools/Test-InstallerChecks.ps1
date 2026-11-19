#Requires -Version 5.1
# Checks installer logic that can run without administrator rights:
# password check result handling and syntax of the installer scripts.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "Installer check failed: $Message"
    }
}

foreach ($script in @(
    'installer\Install-DiskControl.ps1',
    'installer\Uninstall-DiskControl.ps1',
    'installer\Launch-Uninstall-DiskControl.ps1',
    'installer\Build-InstallerPackage.ps1'
    'installer\ClientLifecycle.ps1'
    'tools\Repair-Uninstall-DistControl.ps1'
)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $script), [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "$script has syntax errors: $($errors | ForEach-Object Message)"
}

Add-Type -Path (Join-Path $root 'installer\CredentialCheck.cs')

$cases = @(
    @{ Code = 0; Result = 'Valid'; Counts = $false; Continue = $false },
    @{ Code = 1326; Result = 'WrongPassword'; Counts = $true; Continue = $false },
    @{ Code = 1909; Result = 'LockedOut'; Counts = $false; Continue = $false },
    @{ Code = 1331; Result = 'Disabled'; Counts = $false; Continue = $false },
    @{ Code = 1330; Result = 'PasswordExpired'; Counts = $false; Continue = $false },
    @{ Code = 1907; Result = 'PasswordExpired'; Counts = $false; Continue = $false },
    @{ Code = 1793; Result = 'AccountExpired'; Counts = $false; Continue = $false },
    @{ Code = 1385; Result = 'LogonRestricted'; Counts = $false; Continue = $true },
    @{ Code = 1311; Result = 'DomainUnavailable'; Counts = $false; Continue = $true },
    @{ Code = 1789; Result = 'DomainUnavailable'; Counts = $false; Continue = $true },
    @{ Code = 5; Result = 'Unknown'; Counts = $false; Continue = $true }
)
foreach ($case in $cases) {
    $result = [CredentialCheck]::Classify($case.Code)
    Assert-True ($result.ToString() -eq $case.Result) "code $($case.Code) must be $($case.Result), got $result"
    Assert-True ([CredentialCheck]::CountsAsWrongPassword($result) -eq $case.Counts) "code $($case.Code) attempt counting"
    Assert-True ([CredentialCheck]::MayContinueUnverified($result) -eq $case.Continue) "code $($case.Code) continue rule"
    $message = [CredentialCheck]::Message($result, 'OSNOVA\user', $case.Code)
    Assert-True (-not [string]::IsNullOrWhiteSpace($message) -and $message.Contains('OSNOVA\user')) "code $($case.Code) message"
}
Assert-True ([CredentialCheck]::MaximumWrongPasswordAttempts -eq 3) 'at most three wrong passwords are allowed'
Assert-True ([CredentialCheck]::Message('WrongPassword', 'OSNOVA\user', 1326) -eq 'Неверный пароль для OSNOVA\user.') 'wrong password message'

$wix = Get-Content -LiteralPath (Join-Path $root 'installer\msi\DistControl.Client.wxs') -Raw
Assert-True ($wix.Contains('Id="RunDistControlUninstall"')) 'MSI must run the DistControl client uninstaller'
Assert-True ($wix.Contains('ExeCommand="--msi-uninstall"')) 'MSI uninstall custom action argument'
Assert-True ($wix.Contains('NOT DISTCONTROLCLIENTREMOVED')) 'MSI uninstall must skip the recursive EXE cleanup path'
Assert-True ($wix.Contains('NOT UPGRADINGPRODUCTCODE')) 'major upgrades must not remove the installed client payload'

$installScript = Get-Content -LiteralPath (Join-Path $root 'installer\Install-DiskControl.ps1') -Raw
$uninstallScript = Get-Content -LiteralPath (Join-Path $root 'installer\Uninstall-DiskControl.ps1') -Raw
$uninstallBootstrapper = Get-Content -LiteralPath (Join-Path $root 'installer\UninstallBootstrapper.cs') -Raw
Assert-True ($installScript.Contains('Register-MachineInstallContext')) 'installer must persist the user profile context for MSI uninstall'
Assert-True ($uninstallScript.Contains('{8E2503E8-7098-4FF1-9278-7AC5C473E0CF}')) 'EXE uninstall must query MSI products by UpgradeCode'
Assert-True ($uninstallScript.Contains('DISTCONTROLCLIENTREMOVED=1')) 'EXE uninstall must protect the MSI callback from recursion'
Assert-True ($uninstallBootstrapper.Contains('--skip-msi-unregister')) 'MSI uninstall must pass the recursion guard to the client uninstaller'
Assert-True ($uninstallBootstrapper.Contains('--silent')) 'MSI uninstall must not display a service-session message box'

Write-Output 'Installer checks passed: syntax, credentials, and complete MSI/EXE uninstall wiring.'
