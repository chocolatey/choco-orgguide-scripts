<#
    .SYNOPSIS
        Installs Chocolatey for Business' client products, with a baseline configuration.

    .DESCRIPTION
        Installs Chocolatey CLI, Chocolatey Extension, and Chocolatey Agent.

        Optionally also installs ChocolateyGUI and the package building assets.

        If provided, sets up external repositories from an C4B Organizational Guide deployment,
        along with Chocolatey Central Management reporting and deployments.

    .EXAMPLE
        .\ClientSetup.ps1 -RepositoryUrl https://nexus.example.org:8843/repository/choco-prod/index.json -RepositoryCredential $Cred

        # Installs everything, and configures the system with your base sources.

    .EXAMPLE
        .\ClientSetup.ps1 -RepositoryUrl https://nexus.example.org:8843/repository/choco-prod/index.json -RepositoryCredential $Cred -ChocolateyCentralManagementUrl https://ccm.example.org:24020/ChocolateyManagementService

        # Installs everything, and configures the system with your base sources and Chocolatey Central Management instance.

    .EXAMPLE
        .\ClientSetup.ps1 -LicensePath ~\Downloads\chocolatey.license.xml -ChocolateyCentralManagementUrl https://ccm.example.org:24020/ChocolateyManagementService

        # Installs everything, and configures the system with Chocolatey Central Management.

    .EXAMPLE
        .\ClientSetup.ps1 -LicensePath ~\Downloads\chocolatey.licensed.xml

        # Installs everything.
#>
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    <# Main Repository Parameters #>

    # The URL of the the internal Nexus repository to install Chocolatey from.
    # This URL will be used to create the internal package source configuration.
    [Parameter(ParameterSetName = "Repository", Mandatory)]
    [Parameter(ParameterSetName = "CCM,Repository", Mandatory)]
    [Alias('Url')]
    [string]$RepositoryUrl,

    # The credential used to access the internal Nexus repository.
    [Parameter(ParameterSetName = "Repository", Mandatory)]
    [Parameter(ParameterSetName = "CCM,Repository", Mandatory)]
    [Alias('Credential')]
    [pscredential]$RepositoryCredential,

    # Specifies a target version of Chocolatey to install. By default, the
    # latest stable version is installed.
    [Parameter(ParameterSetName = "Repository")]
    [Parameter(ParameterSetName = "CCM,Repository")]
    [string]$ChocolateyVersion = $env:chocolateyVersion,

    <# Proxy Configuration #>

    # Specifies whether to ignore any configured proxy. This will override any
    # specified proxy environment variables.
    [Parameter()]
    [switch]$IgnoreProxy = [bool]$env:chocolateyIgnoreProxy,

    # The URL of a proxy server to use for connecting to the repository.
    [Parameter()]
    [string]$ProxyUrl = $env:chocolateyProxyLocation,

    # The credentials to connect to the proxy server.
    [Parameter()]
    [pscredential]$ProxyCredential,

    <# Chocolatey Central Management Parameters #>

    # Specifies a URL to connect Chocolatey Agent to.
    [Parameter(ParameterSetName = "CCM,Repository", Mandatory)]
    [Parameter(ParameterSetName = "CCM", Mandatory)]
    [string]$ChocolateyCentralManagementUrl,

    # Client salt value used to populate the centralManagementClientCommunicationSaltAdditivePassword
    # value in the Chocolatey config file
    [Parameter(ParameterSetName = "CCM,Repository")]
    [Parameter(ParameterSetName = "CCM")]
    [Alias('ClientSalt')]
    [string]$ClientCommunicationSalt,

    # Server salt value used to populate the centralManagementServiceCommunicationSaltAdditivePassword
    # value in the Chocolatey config file
    [Parameter(ParameterSetName = "CCM,Repository")]
    [Parameter(ParameterSetName = "CCM")]
    [Alias('ServiceSalt')]
    [string]$ServiceCommunicationSalt,

    <# Additional Configuration Parameters #>

    # Path to a valid Chocolatey license file, if not using a repository with a chocolatey-license package.
    [ValidateScript(
        {
            $R = [xml](Get-Content $_)
            if (-not $R.license.id) { throw "Not a valid Chocolatey license!" }
            if ((Get-Date $R.license.expiration) -lt (Get-Date)) { throw "License expired at $($R.license.expiration)!" }
            $true
        }
    )]
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "CCM")]
    $LicensePath = $(
        if ($PSCmdlet.ParameterSetName -in @('CCM', 'Default') -and $env:ChocolateyInstall -and (Test-Path "$env:ChocolateyInstall\license\chocolatey.license.xml")) {
            # Chocolatey is already installed, we can use that license.
            Write-Verbose "Using the license found in $env:ChocolateyInstall"
            Join-Path $env:ChocolateyInstall license\chocolatey.license.xml
        } elseif ($PSCmdlet.ParameterSetName -in @('CCM', 'Default')) {
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
        # TODO: Test that this doesn't trigger if we're in any ParameterSetName that contains Repository
    ),

    # Install the Chocolatey Licensed Extension with right-click context menus available
    [Parameter()]
    [switch]$IncludePackageTools,

    # If set, does not install Chocolatey GUI for user interaction.
    [Parameter()]
    [switch]$SkipGUI,

    # Allows for the application of user-defined configuration that is applied after the base configuration.
    # Can override base configuration with this parameter.
    # We expect to pass in a hashtable with configuration information in the following format:
    # @{
    #     BackgroundServiceAllowedCommands = 'install,upgrade,uninstall'
    #     commandExecutionTimeoutSeconds = 6000
    # }
    [Parameter()]
    [Hashtable]$AdditionalConfiguration,

    # Allows for the toggling of additional features that is applied after the base configuration.
    # Can override base configuration with this parameter.
    # We expect to pass in feature information as a hashtable in the following format:
    # @{
    #     useBackgroundservice = 'Enabled'
    # }
    [Parameter()]
    [Hashtable]$AdditionalFeatures,

    # Allows for the installation of additional packages after the system base packages have been installed.
    # We expect to pass in one or more hashtables with package information in the following format:
    # @{
    #     Id = 'firefox'
    #     # Optional:
    #     Version = 123.4.56
    #     Pin = $true
    # }
    [Parameter()]
    [Hashtable[]]$AdditionalPackages,

    # Allows for the addition of alternative sources after the base conifguration  has been applied.
    # Can override base configuration with this parameter.
    # We expect to pass in one or more hashtables with source information in the following format:
    # @{
    #     Name = 'MySource'
    #     Source = 'https://nexus.fabrikam.com/repository/MyChocolateySource'
    #     # Optional:
    #     Credentials = $MySourceCredential
    #     AllowSelfService = $true
    #     AdminOnly = $true
    #     BypassProxy = $true
    #     Priority = 10
    #     Certificate = 'C:\cert.pfx'
    #     CertificatePassword = 's0mepa$$'
    # }
    [Parameter()]
    [Hashtable[]]$AdditionalSources
)

Set-ExecutionPolicy RemoteSigned -Scope Process -Force

$ChocoInstallParams = @{
    ChocolateyVersion = $ChocolateyVersion
    IgnoreProxy       = $IgnoreProxy
    UseNativeUnzip    = $true
}

if (-not $IgnoreProxy -and $ProxyUrl) {
    Write-Verbose "Setting Proxy Configuration for '$($ProxyUrl)'"
    $Proxy = [System.Net.WebProxy]::new(
        $ProxyUrl,
        $true  # Bypass Local Addresses
    )
    $ChocoInstallParams.Add('ProxyUrl', $ProxyUrl)

    if ($ProxyCredential) {
        $Proxy.Credentials = $ProxyCredential
        $ChocoInstallParams.Add('ProxyCredential', $ProxyCredential)
    } elseif ($DefaultProxyCredential = [System.Net.CredentialCache]::DefaultCredentials) {
        $Proxy.Credentials = $DefaultProxyCredential
        $ChocoInstallParams.Add('ProxyCredential', $DefaultProxyCredential)
    }
}

$WebClient = [System.Net.WebClient]::new()
if ($RepositoryCredential) {
    $WebClient.Credentials = $RepositoryCredential.GetNetworkCredential()
}

# Find the latest version of Chocolatey, if a version was not specified
if ($RepositoryUrl) {
    $RepositoryType = switch -Regex  ($RepositoryUrl) {
        '\/repository\/(?<RepositoryName>.+)\/(index.json)?$' { 'nexus-repository' }
        '\/nuget\/(?<RepositoryName>.+)\/v3\/(index.json)?$' { 'proget' }
        '\/artifactory\/api\/nuget\/(v3\/)?(?<RepositoryName>.+)\/?$' { 'artifactory' }
    }
    $NupkgUrl = if (-not $ChocolateyVersion) {
        Write-Verbose "Finding latest version of Chocolatey CLI"
        $QueryUrl = switch ($RepositoryType) {
            'nexus-repository' { (($RepositoryUrl -replace '/index\.json$'), "v3/registration/Chocolatey/index.json") -join '/' }
            'proget' { (($RepositoryUrl -replace '/index\.json$'), "registrations/Chocolatey/index.json") -join '/' }
            'artifactory' { (($RepositoryUrl.TrimEnd('/')), "/registration/chocolatey/index.json") -join '/' }
        }
        $Result = $WebClient.DownloadString($QueryUrl) | ConvertFrom-Json
        $Result.items.items[-1].packageContent
    } else {
        # Otherwise, assume the URL
        switch ($RepositoryType) {
            'nexus-repository' { "$($RepositoryUrl -replace '/index\.json$')/v3/content/chocolatey/$($ChocolateyVersion)/chocolatey.$($ChocolateyVersion).nupkg" }
        }
    }
    $WebClient.Proxy = if ($Proxy -and -not $Proxy.IsBypassed($NupkgUrl)) { $Proxy }

    # Download the NUPKG
    $NupkgPath = Join-Path $env:TEMP "$(New-Guid).zip"
    $WebClient.DownloadFile($NupkgUrl, $NupkgPath)

    # Add ChocolateyDownloadUrl pointing to the NUPKG's path
    $ChocoInstallParams.Add('ChocolateyDownloadUrl', $NupkgPath)
}

$InstallScriptUrl = if ($RepositoryUrl) {
    $RepositoryUrl -replace '\/repository\/(?<RepositoryName>.+)\/(index.json)?$', '/repository/choco-install/ChocolateyInstall.ps1'
} else {
    "https://community.chocolatey.org/Install.ps1"
}
$WebClient.Proxy = if ($Proxy -and -not $Proxy.IsBypassed($InstallScriptUrl)) { $Proxy }
$Script = $WebClient.DownloadString($InstallScriptUrl)
& ([scriptblock]::Create($Script)) @ChocoInstallParams

# If FIPS is enabled, configure Chocolatey to use FIPS compliant checksums
$fipsStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name Enabled
if ($fipsStatus.Enabled -eq 1) {
    Write-Warning -Message "FIPS is enabled on this system. Ensuring Chocolatey uses FIPS compliant checksums"
    choco feature enable --name='useFipsCompliantChecksums' --limit-output
}

Write-Verbose "Applying Chocolatey recommendations"
choco config set cacheLocation $env:ChocolateyInstall\choco-cache --limit-output
choco config set commandExecutionTimeoutSeconds 14400 --limit-output
choco feature enable --name="'usePackageHashValidation'" --limit-output

# Nexus NuGet V3 Compatibility
if ($RepositoryType -eq 'nexus-repository') {
    choco feature disable --name="'usePackageRepositoryOptimizations'" --limit-output
}

if ($RepositoryUrl) {
    Write-Verbose "Configuring Internal Sources"
    # Add internal sources
    choco source add --name="'choco-core'" --source="'$($RepositoryUrl -replace '(?<=\/repository\/).+(?=\/index\.json$)', 'choco-core')'" --allow-self-service --admin-only --user="'$($RepositoryCredential.UserName)'" --password="'$($RepositoryCredential.GetNetworkCredential().Password)'" --priority=2 --limit-output
    if ($RepositoryUrl -match '(?<=\/repository\/)(?<RepositoryName>.+)(?=\/index\.json$)') {
        choco source add --name="'$($Matches.RepositoryName)'" --source="'$RepositoryUrl'" --allow-self-service --user="'$($RepositoryCredential.UserName)'" --password="'$($RepositoryCredential.GetNetworkCredential().Password)'" --priority=1 --limit-output
    }

    # Disable external sources
    choco source disable --name="'Chocolatey'" --limit-output
    choco source disable --name="'chocolatey.licensed'" --limit-output

    # Install the license package
    choco upgrade chocolatey-license --confirm --limit-output
} elseif ($LicensePath) {
    if ($LicensePath -ne "$env:ChocolateyInstall\license\chocolatey.license.xml") {
        Copy-Item $LicensePath -Destination $env:ChocolateyInstall\license\chocolatey.license.xml -Force
    }
} else {
    Write-Error "No license found. Please provide -RepositoryUrl or -LicensePath to continue!"
}

Write-Verbose "Installing Chocolatey for Business Packages"
choco upgrade chocolatey.extension --confirm --no-progress --limit-output @(
    if (-not $IncludePackageTools) {
        '--params="/NoContextMenu"'
    } else {
        Write-Verbose "IncludePackageTools was passed. Right-Click context menus will be available for installers, .nupkg, and .nuspec file types!"
    }
)

choco upgrade chocolatey-agent --confirm --limit-output

if (-not $SkipGUI) {
    Write-Verbose "Installing ChocolateyGUI"
    choco upgrade chocolateygui --confirm --no-progress --limit-output
    choco upgrade chocolateygui.extension --confirm --no-progress --limit-output
}

Write-Verbose "Configuring Chocolatey for Business Self-Service for Install, Upgrade, and Uninstall"
choco feature enable --name="'excludeChocolateyPackagesDuringUpgradeAll'" --limit-output
choco feature disable --name="'showNonElevatedWarnings'" --limit-output
choco feature enable --name="'useBackgroundService'" --limit-output
choco feature enable --name="'useBackgroundServiceWithNonAdministratorsOnly'" --limit-output
choco feature enable --name="'allowBackgroundServiceUninstallsFromUserInstallsOnly'" --limit-output
choco config set --name="'backgroundServiceAllowedCommands'" --value="'install,upgrade,uninstall'" --limit-output

# CCM Check-in Configuration
if ($ChocolateyCentralManagementUrl) {
    Write-Verbose "Configuring Central Management"
    choco config set CentralManagementServiceUrl $ChocolateyCentralManagementUrl
    choco feature enable --name="'useChocolateyCentralManagement'" --limit-output
    choco feature enable --name="'useChocolateyCentralManagementDeployments'" --limit-output
}

if ($ClientCommunicationSalt) {
    Write-Verbose "Adding Custom Client Communication Salt"
    choco config set centralManagementClientCommunicationSaltAdditivePassword $ClientCommunicationSalt --limit-output
}

if ($ServiceCommunicationSalt) {
    Write-Verbose "Adding Custom Service Communication Salt"
    choco config set centralManagementServiceCommunicationSaltAdditivePassword $ServiceCommunicationSalt --limit-output
}

if ($AdditionalConfiguration -or $AdditionalFeatures -or $AdditionalSources -or $AdditionalPackages) {
    Write-Host "Applying user supplied configuration"
}

if ($AdditionalConfiguration) {
    $AdditionalConfiguration.GetEnumerator().ForEach{
        & choco @(
            'config'
            'set'
            "--name='$($_.Key)'"
            "--value='$($_.Value)'"
            '--limit-output'
        )
    }
}

if ($AdditionalFeatures) {
    $AdditionalFeatures.GetEnumerator().ForEach{
        $State = switch ($_.Value) {
            ($_ -in @('true', 'enable', 'enabled') -or ($_ -is [bool] -and $_ -eq $true)) { 'enable' }
            ($_ -in @($false, 'false', 'disable', 'disabled')) { 'disable' }
            default { Write-Error "State of '$($_.Key)' should be either Enabled or Disabled" }
        }
        if ($State) {
            & choco @(
                'feature'
                $State
                "--name='$($_.Key)'"
                '--limit-output'
            )
        }
    }
}

if ($AdditionalSources) {
    foreach ($Source in $AdditionalSources) {
        & choco @(
            'source'
            'add'
            "--name='$($Source.Name)'"
            "--source='$($Source.Source)'"
            if ($Source.ContainsKey('Credentials')) {
                "--user='$($Source.Credentials.Username)'"
                "--password='$($Source.Credentials.GetNetworkCredential().Password)'"
            }
            if ($Source.AllowSelfService) { '--allow-self-service' }
            if ($Source.AdminOnly) { '--admin-only' }
            if ($Source.BypassProxy) { '--bypass-proxy' }
            if ($Source.Priority) { "--priority='$($Source.Priority)'" }
            if ($Source.Certificate) { "--cert='$($Source.Certificate)'" }
            if ($Source.CerfificatePassword) { "--certpassword='$($Source.CertificatePassword)'" }
            '--limit-output'
        )
    }
}

if ($AdditionalPackages) {
    foreach ($Package in $AdditionalPackages) {
        & choco @(
            'install'
            $Package.Id
            if ($Package.Version) { "--version='$($Package.Version)'" }
            if ($Package.Pin) { '--pin' }
            '--confirm'
            '--no-progress'
            '--limit-output'
        )
    }
}