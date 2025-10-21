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
    # The path to your current Chocolatey license
    $LicensePath = $(
        if ($env:ChocolateyInstall -and (Test-Path $env:ChocolateyInstall\licenses\chocolatey.license.xml)) {
            # Chocolatey is already installed, we can use that license.
            Write-Verbose "Using the license found in $env:ChocolateyInstall"
            Join-Path $env:ChocolateyInstall licenses\chocolatey.license.xml
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

    $OutputPath = $(
        Join-Path $env:TEMP "c4b-bootstrap"
    )
)

# Download Chocolatey
if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
    Invoke-RestMethod https://ch0.co/go | Invoke-Expression
}

# Ensure the license is available
if (-not (Test-Path $env:ChocolateyInstall\licenses\chocolatey.license.xml)) {
    Copy-Item -Path $LicensePath -Destination $env:ChocolateyInstall\licenses\chocolatey.license.xml -Force
}

# Download the module
if (-not (Get-Module C4B-Environment -ListAvailable)) {
    choco install c4b-environment.powershell --confirm
}

# Download the base files
Get-ChocolateyBusinessManifest -ServerType * | Save-ChocolateyInternalizedPackage -Path $OutputPath

# Open the new location
Set-Location $OutputPath
explorer $OutputPath