<#
    .Synopsis
        Installs an automation platform used with Chocolatey for Business

    .Description
        Install Jenkins, configures it, and adds a selection of useful jobs.

    .Example
        .\Install-AutomationPlatform-Jenkins.ps1 -ProductionRepositoryUrl https://repo.example.org/repository/ChocolateyInternal/index.json -RepositoryUser $Cred -RepositoryApiKey $ApiKey -Thumbprint $Thumbprint

        # Install with the Nexus defaults.
#>
[CmdletBinding()]
param(
    # The URL for your Chocolatey Core repository.
    [string]$ChocolateyCoreRepositoryUrl,

    # The URL for your production repository.
    [string]$ProductionRepositoryUrl,

    # The URL for your test repository.
    [string]$TestRepositoryUrl,

    # The credential used to access your repository.
    [Parameter(Mandatory)]
    [pscredential]$RepositoryUser,

    # An api key used to push to the NuGet repository.
    [securestring]$RepositoryApiKey,

    # The path to the bootstrap script you use to setup a client node.
    [string]$BootstrapScript = $($ProductionRepositoryUrl -replace '/(?<RepositoryName>[^\/]+?)/(index.json)?$', '/choco-install/ClientSetup.ps1'),

    # The repository type in use, for configuration of the jobs.
    [ValidateSet("nexus")]
    [string]$RepositorySolution = "nexus",

    # The thumbprint of a certificate currently in LocalMachine/TrustedPeople for Jenkins to use. Must be exportable.
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
Start-Transcript -Path "$PSScriptRoot\C4bJenkinsSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

try {
    # Bootstrap Chocolatey for Business
    if (Test-Path $PSScriptRoot\Packages.zip) {
        # We're an offline install.
        $TemporarySource = Join-Path $env:TEMP 'c4b-offline-bootstrap'
        Expand-Archive -Path $PSScriptRoot\Packages.zip -DestinationPath $TemporarySource
    }

    # We need to add each of the repositories so that we can use them in jobs
    foreach ($Repository in 'ChocolateyCore', 'Production', 'Test') {
        $Url = Get-Variable "$($Repository)RepositoryUrl" -ValueOnly
        $Name = if ($Url -match '/(?<RepositoryName>.+)/(?<v3>index.json)?$') {
            $Matches.RepositoryName
        } else {
            $Repository
        }

        if ($Url -and $Name) {
            if ($RepositoryUser) {
                Invoke-Choco source add --name="$($Name)" --source="$($Url)" --user="$($RepositoryUser.UserName)" --password="$([System.Net.NetworkCredential]::new($null, $RepositoryUser.Password).Password)"
            } else {
                Invoke-Choco source add --name="$($Name)" --source="$($Url)"
            }
        }

        if ($Repository -eq 'Test') {
            # We disable this repository when it's not being used in jobs
            Invoke-Choco source disable --name="$($Name)"
        }
    }

    # Install Java Runtime
    Invoke-Choco install temurin21jre --params='/ADDLOCAL=FeatureEnvironment,FeatureJavaHome' --confirm --no-progress
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1
        Update-SessionEnvironment
    }

    # Install Jenkins
    Invoke-Choco install jenkins --confirm --no-progress --params="/Java_Home=$(Convert-Path $env:ProgramFiles\*\jre-21*)"

    # First-run configuration for Jenkins
    $JenkinsHome = "C:\ProgramData\Jenkins\.jenkins"
    # Wait for Jenkins Home to exist, if it doesn't
    $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path $JenkinsHome/secrets/initialAdminPassword) -and $Timeout.Elapsed.TotalSeconds -lt 90) {
        Start-Sleep -Seconds 1
    }

    $JenkinsVersion = (choco.exe list jenkins --exact --limit-output).Split('|')[1]
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.UpgradeWizard.state -Encoding utf8
    $JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.InstallUtil.lastExecVersion -Encoding utf8

    $JenkinsCred = [pscredential]::new(
        "admin",
        (Get-Content $JenkinsHome/secrets/initialAdminPassword | ConvertTo-SecureString -AsPlainText -Force)
    )
    Set-ChocoEnvironmentProperty -Name JenkinsCredential -Value $JenkinsCred

    Stop-Service Jenkins

    $JenkinsScheme, $Port, $HostName = "http", "8080", $env:ComputerName
    if ($Thumbprint) {
        if ($CertificateDnsName) {
            Set-ChocoEnvironmentProperty CertSubject $CertificateDnsName
        }

        $null = Test-CertificateDomain -Thumbprint $Thumbprint

        $JenkinsScheme, $Port, $HostName = "https", "7443", $(
            Get-ChocoEnvironmentProperty CertSubject
        )

        Set-JenkinsCertificate -Thumbprint $Thumbprint -Port $Port
    }
    netsh advfirewall firewall add rule name="Jenkins-$($Port)" dir=in action=allow protocol=tcp localport=$Port

    # Set Jenkins location
    Set-JenkinsLocationConfiguration -Url "$($JenkinsScheme)://$($HostName):$($Port)"

    # Install Jenkins plugin

    try {
        Invoke-Choco install chocolatey-licensed-jenkins-plugins --confirm --no-progress @(
            # TODO: Remove when we've solved the sourcing issue
            if (Test-Path ~\Desktop\chocolatey-licensed-jenkins-plugins.*.nupkg) {
                Push-Location ~\Desktop
                "--source='$(Resolve-Path ~\Desktop)'"
            }
        )
    } finally {
        Pop-Location
    }

    switch ($RepositorySolution) {
        "nexus" {
            $RepositoryBaseUrl = $ProductionRepositoryUrl -replace '/repository/(?<RepositoryName>.+?)/(index.json)?$'
            Invoke-Choco install chocolatey-licensed-jenkins-jobs --params="/NexusUrl=$($ProductionRepositoryUrl) /NexusApiKey=$($RepositoryApiKey) /PackageUserName=$($RepositoryUser.UserName)" --package-parameters-sensitive="/PackageUserPassword=$($RepositoryUser.GetNetworkCredential().Password)" --confirm --no-progress

            Update-JenkinsJobParameters -Replacement @{
                # TODO: True up the parameter names in the package!
                "P_DST_URL"            = $TestRepositoryUrl
                "P_LOCAL_REPO_URL"     = $TestRepositoryUrl
                "P_TEST_REPO_URL"      = $TestRepositoryUrl
                "P_PROD_REPO_URL"      = $ProductionRepositoryUrl
                "P_LOCAL_REPO_API_KEY" = [System.Net.NetworkCredential]::new($null, $RepositoryApiKey).Password
                "P_PROD_REPO_API_KEY"  = [System.Net.NetworkCredential]::new($null, $RepositoryApiKey).Password
                "P_API_KEY"            = [System.Net.NetworkCredential]::new($null, $RepositoryApiKey).Password
                "Nexus_Username"       = $RepositoryUser.UserName
                "Nexus_Password"       = $RepositoryUser.GetNetworkCredential().Password
            }
        }
        "proget" {
            Invoke-Choco install chocolatey-licensed-jenkins-scripts --confirm --no-progress

            # TODO: Create new jobs to point at ProGet
        }
    }

    Start-Service Jenkins

    # Output useful values for the user
    $UsefulValues = @{
        JenkinsUri        = "$($JenkinsScheme)://$($HostName):$($Port)"
        JenkinsCredential = $JenkinsCred
    }

    Set-ChocoEnvironmentProperty -Name JenkinsUri -Value $UsefulValues.JenkinsUri

} finally {
    if ($TemporarySource) {
        Invoke-Choco source remove --name='Bootstrap'
        Remove-Item $TemporarySource
    }
    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}