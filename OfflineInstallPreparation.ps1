<#
    .Synopsis
        Downloads the prerequisite files for a Chocolatey for Business environment.

    .Description
        Using Chocolatey for Business, downloads all the requirements for an offline install of a Chocolatey for Business environment.

    .Notes
        This must be run on a Windows system with access to the internet because
        it uses Chocolatey for Business' Package Internalizer.

    .Example
        .\OfflineInstallPreparation.ps1 -CCMHostName ccm.example.org -RepositoryHostName nexus.example.org -AutomationHostName jenkins.example.org -Archive

        # Creates offline deployments for each of the three hosts.

    .Example
        .\OfflineInstallPreparation.ps1 -CCMHostName choco.example.org -RepositorySolution nexus -AutomationPlatform jenkins

        # Creates offline deployments for all products on the single host. Does not archive the folder.

    .Example
        .\OfflineInstallPreparation.ps1 -CCMWebsiteHostName ccm.example.org -CCMServiceHostName ccmservice.example.org

        # Creates offline deployments for CCM products only, divided into two hosts.
#>
[CmdletBinding(DefaultParameterSetName = "CCM,Repository,Automation")]
param(
    [ValidateScript({
            if (-not (Test-Path (Convert-Path $_))) {
                throw "License file does not exist at '$($_)'. Please provide a valid -LicensePath"
            }
            try {
                [xml]$License = Get-Content $_
                $Expiry = Get-Date $License.license.expiration
                if (-not $Expiry -or $Expiry -lt (Get-Date)) { throw }
            } catch {
                throw "License '$($_)' is not valid.$(if ($Expiry) {" It expired at '$($Expiry)'."})"
            }
            $true
        })]
    [string]$LicensePath = $(
        if (Test-Path $PSScriptRoot\files\chocolatey.license.xml) {
            # Offline setup has been run, we should use that license.
            Join-Path $PSScriptRoot "files\chocolatey.license.xml"
        } elseif (Test-Path $env:ChocolateyInstall\license\chocolatey.license.xml) {
            # Chocolatey is already installed, we can use that license.
            Join-Path $env:ChocolateyInstall "license\chocolatey.license.xml"
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

    # The host you intend to install the Chocolatey Central Management website on.
    [Parameter(Mandatory, ParameterSetName = "CCM")]
    [Parameter(Mandatory, ParameterSetName = "CCM,Repository")]
    [Parameter(ParameterSetName = "CCM,Repository,Automation")]
    [Alias('CCMHostName')]
    [string]$CCMWebsiteHostName = $env:COMPUTERNAME,

    # The host you intend to install the Chocolatey Central Management Service on.
    [Parameter(ParameterSetName = "CCM")]
    [Parameter(ParameterSetName = "CCM,Repository")]
    [Parameter(ParameterSetName = "CCM,Repository,Automation")]
    [string]$CCMServiceHostName = $CCMWebsiteHostName,

    # A connection string for the database you want to use for Chocolatey Central Management.
    # Must be accessible from the CCM Service host.
    [Parameter(ParameterSetName = "CCM")]
    [Parameter(ParameterSetName = "CCM,Repository")]
    [Parameter(ParameterSetName = "CCM,Repository,Automation")]
    [string]$ConnectionString,

    # The repository solution you want to install.
    [Parameter(ParameterSetName = "Repository")]
    [Parameter(ParameterSetName = "CCM,Repository")]
    [Parameter(ParameterSetName = "CCM,Repository,Automation")]
    [ValidateSet("nexus")]
    [string]$RepositorySolution = "nexus",

    # The host you intend to install the repository solution on.
    [Parameter(ParameterSetName = "Repository")]
    [Parameter(ParameterSetName = "CCM,Repository")]
    [Parameter(ParameterSetName = "CCM,Repository,Automation")]
    [string]$RepositoryHostName = $CCMWebsiteHostName,

    # The automation platform you want to install.
    [Parameter(ParameterSetName = "Automation")]
    [Parameter(ParameterSetName = "Repository,Automation")]
    [Parameter(ParameterSetName = "CCM,Repository,Automation")]
    [ValidateSet("jenkins")]
    [string]$AutomationPlatform = "jenkins",

    # The host you intend to install the repository solution on.
    [Parameter(ParameterSetName = "Automation")]
    [Parameter(ParameterSetName = "Repository,Automation")]
    [Parameter(ParameterSetName = "CCM,Repository,Automation")]
    [string]$AutomationHostName = $CCMWebsiteHostName,

    # Archives the host directories at the end of the process
    [switch]$Archive
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$LicensePath = Convert-Path $LicensePath

# Download Chocolatey Central Management files
if ($PSCmdlet.ParameterSetName.Split(',') -contains 'CCM') {
    Get-ChocolateyBusinessManifest -ServerType chocolatey-management-web | Save-ChocolateyInternalizedPackage -OutputDirectory $PSScriptRoot\$CCMWebsiteHostName
    Get-ChocolateyBusinessManifest -ServerType chocolatey-management-service | Save-ChocolateyInternalizedPackage -OutputDirectory $PSScriptRoot\$CCMServiceHostName
    Get-ChocolateyBusinessManifest -ServerType chocolatey-management-database | Save-ChocolateyInternalizedPackage -OutputDirectory $PSScriptRoot\$CCMServiceHostName

    foreach ($Destination in "$PSScriptRoot\$CCMWebsiteHostName", "$PSScriptRoot\$CCMServiceHostName" | Select-Object -Unique) {
        Copy-Item "$PSScriptRoot\Install-ChocolateyCentralManagement.ps1" -Destination $Destination
    }
}

if (-not $ConnectionString -and $PSCmdlet.ParameterSetName.Split(',') -contains 'CCM') {
    Get-ChocolateyBusinessManifest -ServerType database | Save-ChocolateyInternalizedPackage -OutputDirectory $PSScriptRoot\$CCMServiceHostName
}

# Download Repository Solution files
if ($RepositorySolution -and $PSCmdlet.ParameterSetName.Split(',') -contains 'Repository') {
    Get-ChocolateyBusinessManifest -ServerType $RepositorySolution | Save-ChocolateyInternalizedPackage -OutputDirectory $PSScriptRoot\$RepositoryHostName
    Copy-Item "$PSScriptRoot\Install-C4BRepositoryPlatform$($RepositorySolution).ps1" -Destination $PSScriptRoot\$AutomationHostName
}

# Download Automation Platform files
if ($AutomationPlatform -and $PSCmdlet.ParameterSetName.Split(',') -contains 'Automation') {
    Get-ChocolateyBusinessManifest -ServerType $AutomationPlatform | Save-ChocolateyInternalizedPackage -OutputDirectory $PSScriptRoot\$AutomationHostName
    Copy-Item "$PSScriptRoot\Install-C4BAutomationPlatform$($AutomationPlatform).ps1" -Destination $PSScriptRoot\$AutomationHostName
}

# Configure script default values
Set-ClientScriptDefaultParameterValue -Path $PSScriptRoot\ClientSetup.ps1 -Replacements @{
    RepositoryUrl                  = if ($RepositoryHostName) { "https://$($RepositoryHostName)/repository/" } else { $null }
    ChocolateyCentralManagementUrl = if ($CCMServiceHostName) { "https://$($CCMServiceHostName):24020/ChocolateyManagementService" } else { $null }
}

# Add the rest of the required files to each directory
foreach ($Directory in Get-ChildItem $PSScriptRoot -Directory) {
    Copy-Item $LicensePath -Destination $Directory.FullName
    Copy-Item $PSScriptRoot\ClientSetup.ps1 -Destination $Directory.FullName

    if ($Archive) {
        Compress-Archive -Path $Directory.FullName -DestinationPath "$($PSScriptRoot)\$($Directory.Name).zip"
    }
}