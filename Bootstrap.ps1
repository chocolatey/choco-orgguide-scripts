<#
    .SYNOPSIS
        Kickstart the organisation guide by downloading everything you need.

    .DESCRIPTION
        Downloads the scripts, modules, and the initial setup for use.

    .EXAMPLE
        .\Bootstrap.ps1
#>
[CmdletBinding()]
param(
    # The path to your current Chocolatey license.
    [string]$LicensePath = $(
        if ($env:ChocolateyInstall -and (Test-Path $env:ChocolateyInstall\license\chocolatey.license.xml)) {
            # Chocolatey is already installed, we can use that license.
            Write-Verbose "Using the license found in $env:ChocolateyInstall"
            Join-Path $env:ChocolateyInstall license\chocolatey.license.xml
        } else {
            # Prompt the user for the license.
            $Wshell = New-Object -ComObject Wscript.Shell
            $null = $Wshell.Popup('You will need to provide the license file location. Please select your Chocolatey License in the next file dialog.')
            $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = "$env:USERPROFILE\Downloads"
            $OpenFileDialog.filter = 'All Files (*.*)| *.*'
            $null = $OpenFileDialog.ShowDialog()

            $OpenFileDialog.filename
        }
    ),

    # The path to save all the files to.
    [string]$OutputPath = $(
        Join-Path $env:TEMP "c4b-bootstrap"
    )
)

$DefaultEap, $ErrorActionPreference = $ErrorActionPreference, 'Stop'

if (-not (Test-Path $OutputPath)) {
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
}

# Download Chocolatey
if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
    Invoke-RestMethod https://ch0.co/go | Invoke-Expression
}

if (-not $env:ChocolateyInstall) {
    Import-Module C:\ProgramData\chocolatey\helpers\chocolateyProfile.psm1
    refreshenv
}

# Ensure the license is available
if (-not (Test-Path $env:ChocolateyInstall\license\chocolatey.license.xml)) {
    if (-not (Test-Path $env:ChocolateyInstall\license)) {
        $null = New-Item -Path $env:ChocolateyInstall -Name license -ItemType Directory
    }
    Copy-Item -Path $LicensePath -Destination $env:ChocolateyInstall\license\chocolatey.license.xml -Force
}

if (-not (Test-Path $env:ChocolateyInstall\extensions\chocolatey)) {
    choco upgrade chocolatey.extension --confirm --package-parameters='/NoContextMenu' --no-progress | Write-Host
}

# Download the module
if (-not (Get-Module C4B-Environment -ListAvailable)) {
    choco upgrade c4b-environment.powershell --confirm  --no-progress
}

if (-not (Get-ChildItem $OutputPath) -or $env:UpdateBootstrap) {
    Invoke-WebRequest -Uri "https://api.github.com/repos/chocolatey/choco-orgguide-scripts/zipball/main" -OutFile $env:Temp\orgscripts.zip
    Expand-Archive $env:Temp\orgscripts.zip $OutputPath -Force
    Copy-Item $OutputPath\chocolatey-choco-orgguide-scripts-*\* $OutputPath -Force
    Remove-Item $env:Temp\orgscripts.zip
    Remove-Item $OutputPath\chocolatey-choco-orgguide-scripts-* -Recurse
}

# TEMPORARY WORKAROUND FOR LICENSE FEED
# TODO: Remove
if (Test-Path ~\Desktop\c4b-environment.powershell.*.nupkg) {
    try {
        Push-Location ~\Desktop
        choco upgrade c4b-environment.powershell --source . --confirm  --no-progress
    } finally {
        Pop-Location
    }
}

# Open the new location
Set-Location $OutputPath