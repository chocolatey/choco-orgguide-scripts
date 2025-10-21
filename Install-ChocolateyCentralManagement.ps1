<#
    .Synopsis
        Installs Chocolatey Central Management and associated packages.

    .Description
        Installs portions of Chocolatey Central Management, along with the Chocolatey Extension.

    .Example
        .\Install-ChocolateyCentralManagement.ps1 -Thumbprint $Thumbprint

        # Installs all of CCM with the certificate specified.
#>
[CmdletBinding()]
param(
    # The component of Chocolatey Central Management to install. Defaults to installing all components.
    [ValidateSet('Database', 'Service', 'Website')]
    [string]$Component,

    # A connection string for a SQL Server database, for the CCM services to store data.
    [string]$ConnectionString,

    # A credential to run the CCM website and service as.
    [PSCredential]$ServiceCredential,

    # The thumbprint of a certificate currently in LocalMachine/TrustedPeople for CCM to use.
    [Parameter(Mandatory)]
    [ArgumentCompleter({
            Get-ChildItem Cert:\LocalMachine\TrustedPeople | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new(
                    $_.Thumbprint,
                    $_.Thumbprint,
                    "ParameterValue",
                    ($_.Subject -replace "^CN=(?<FQDN>.+),?.*$", '${FQDN}')
                )
            }
        })]
    [string]$Thumbprint = $(
        Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Sort-Object {
            $_.Issuer -eq $_.Subject # Prioritise any certificates above self-signed
        } | Select-Object -ExpandProperty Thumbprint -First 1
    ),

    # The domain to use, if providing a wildcard certificate.
    [string]$CertificateDnsName
)
$DefaultEap, $ErrorActionPreference = $ErrorActionPreference, 'Stop'

try {
    # Bootstrap Chocolatey for Business
    if (Test-Path $PSScriptRoot\Packages.zip) {
        # We're an offline install.
        $TemporarySource = Join-Path $env:TEMP 'c4b-offline-bootstrap'
        Expand-Archive -Path $PSScriptRoot\Packages.zip -DestinationPath $TemporarySource
        $InstallScript = Join-Path $TemporarySource "ClientSetup.ps1"
    } else {
        $Downloader = [System.Net.WebClient]::new()
        $Downloader.Credentials = $RepositoryUser
        $InstallScript = $Downloader.DownloadString($BootstrapScript)
    }

    & ([Scriptblock]::Create($InstallScript)) -RepositoryCredential $RepositoryUser -AdditionalSources @(
        if ($TemporarySource) {
            @{
                Name     = "Bootstrap"
                Source   = $TemporarySource
                Priority = 1
            }
        }
    )

    & choco install c4b-environment.powershell --confirm --no-progress

    switch ($Component) {
        'Database' {
            try {
                if (-not $ConnectionString) {
                    # We need to install SQL Server
                    Invoke-Choco upgrade sql-server-express

                    $ConnectionString = "Localhost\SQLEXPRESS;Database=ChocolateyManagement;Trusted_Connection=true;"
                }

                # Dependencies
                Invoke-Choco install dotnet-8.0-runtime --version $(pv 'dotnet-8.0-runtime')
                Invoke-Choco install dotnet-8.0-aspnetruntime --version $(pv 'dotnet-8.0-aspnetruntime')

                # Main package
                Invoke-Choco install chocolatey-management-database --package-parameters-sensitive="/ConnectionString=$ConnectionString"

                Write-Host "Database component setup completed. It is now safe to move on to other components"
            } catch {
                $Error[0]
            }
        }

        'Service' {
            # Package parameters - build parameter string with all sensitive parameters
            $parameterParts = @("/ConnectionString=$ConnectionString")

            if ($ServiceCredential) {
                $parameterParts += "/Username=$($ServiceCredential.UserName)"
                $parameterParts += "/Password=$($ServiceCredential.GetNetworkCredential().Password)"
            }

            if ($CertificateThumbprint) {
                $parameterParts += "/CertificateThumbprint=$CertificateThumbprint"
                Write-Output "Using certificate with thumbprint: $CertificateThumbprint"
            } else {
                Write-Output 'No certificate information passed, will use a self-signed certificate'
            }

            if ($CertificateDnsName) {
                $parameterParts += "/CertificateDnsName=$CertificateDnsName"
            }

            $parameterString = $parameterParts -join ' '

            # Dependencies
            Invoke-Choco install dotnet-8.0-runtime dotnet-8.0-aspnetruntime

            # Main package
            Write-Output "Installing with: $parameterString"
            Invoke-Choco install chocolatey-management-service --package-parameters-sensitive="$parameterString"

            # Set the correct Service Url value
            if ($CertificateDnsName) {
                $config = @('config', 'set', 'centralManagementServiceUrl', $('https://{0}/ChocolateyManagementService:24020' -f $CertificateDnsName))
                Invoke-Choco @config
            }
        }

        'Website' {
            # Base arguments for all choco commands
            $baseArgs = @('-y', '--no-progress')

            # Windows Features
            Invoke-Choco install IIS-WebServer --source='windowsfeatures'
            Invoke-Choco install IIS-ApplicationInit --source='windowsfeatures'

            # Package Dependencies
            Invoke-Choco install dotnet-aspnetcoremodule-v2 --version $(pv 'dotnet-aspnetcoremodule-v2')
            Invoke-Choco install dotnet-8.0-runtime --version $(pv 'dotnet-8.0-runtime')
            Invoke-Choco install dotnet-8.0-aspnetruntime --version $(pv 'dotnet-8.0-aspnetruntime')

            # Package parameters - build parameter string with all sensitive parameters
            $parameterParts = @("/ConnectionString=$ConnectionString")

            if ($ServiceCredential) {
                $parameterParts += "/Username=$($ServiceCredential.UserName)"
                $parameterParts += "/Password=$($ServiceCredential.GetNetworkCredential().Password)"
            }

            $parameterString = $parameterParts -join ' '

            # Main package installation
            Invoke-Choco install chocolatey-management-web --package-parameters-sensitive="$parameterString"

            if ($CertificateThumbprint) {
                Set-CCMCertificate -CertificateThumbprint $CertificateThumbprint
            }
        }

        '' {
            # Windows Features
            Invoke-Choco install IIS-WebServer --source='windowsfeatures'
            Invoke-Choco install IIS-ApplicationInit --source='windowsfeatures'

            # Package Dependencies
            Invoke-Choco install dotnet-aspnetcoremodule-v2 --version $(pv 'dotnet-aspnetcoremodule-v2')
            Invoke-Choco install dotnet-8.0-runtime --version $(pv 'dotnet-8.0-runtime')
            Invoke-Choco install dotnet-8.0-aspnetruntime --version $(pv 'dotnet-8.0-aspnetruntime')

            # Package parameters - build parameter string with all sensitive parameters
            $parameterParts = @("/ConnectionString=$ConnectionString")

            if ($ServiceCredential) {
                $parameterParts += "/Username=$($ServiceCredential.UserName)"
                $parameterParts += "/Password=$($ServiceCredential.GetNetworkCredential().Password)"
            }

            if ($CertificateThumbprint) {
                $parameterParts += "/CertificateThumbprint=$CertificateThumbprint"
            }

            if ($CertificateDnsName) {
                $parameterParts += "/CertificateDnsName=$CertificateDnsName"
            }

            $parameterString = $parameterParts -join ' '

            # Install all components with SkipDatabasePermissionCheck
            Invoke-Choco install chocolatey-management-database --package-parameters-sensitive="/SkipDatabasePermissionCheck $parameterString"
            Invoke-Choco install chocolatey-management-service --package-parameters-sensitive="/SkipDatabasePermissionCheck $parameterString"
            Invoke-Choco install chocolatey-management-web --package-parameters-sensitive="/SkipDatabasePermissionCheck $parameterString"

            Add-DatabaseUserAndRoles -Username 'IIS APPPOOL\ChocolateyCentralManagement' -DatabaseName ChocolateyManagement -DatabaseRoles @('db_datareader', 'db_datawriter')
        }
    }
} finally {
    if ($TemporarySource) {
        Invoke-Choco source remove --name='Bootstrap'
        Remove-Item $TemporarySource
    }
    $ErrorActionPreference = $DefaultEap
}