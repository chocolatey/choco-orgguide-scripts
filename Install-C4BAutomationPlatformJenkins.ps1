<#
    .Synopsis
        Installs an automation platform used with Chocolatey for Business

    .Description
        Install Jenkins, configures it, and adds a selection of useful jobs.

    .Example
        .\Install-AutomationPlatform-Jenkins.ps1 -ProductionRepositoryUrl https://repo.example.com/repository/ChocolateyInternal/index.json -RepositoryUser $Cred -RepositoryApiKey $ApiKey -Thumbprint $Thumbprint

        # Install with the Nexus defaults.
#>
[CmdletBinding()]
param(
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

    # Thumbprint of the SSL certificate to use for the Jenkins service.
    [ArgumentCompleter({
        Get-ChildItem Cert:\LocalMachine\TrustedPeople | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_.Thumbprint,
                $_.Thumbprint,
                "ParameterValue",
                ($_.Subject -replace "^CN=(?<FQDN>.+),?.*$",'${FQDN}')
            )
        }
    })]
    [string]$Thumbprint,

    [string]$CentralManagementAddress,

    [string]$CentralManagementServiceSalt,

    [string]$CentralManagementClientSalt
)
$ErrorActionPreference = "Stop"

# Bootstrap Chocolatey for Business from the repository
$Downloader = [System.Net.WebClient]::new()
$Downloader.Credentials = $RepositoryUser
$InstallScript = $Downloader.DownloadString($BootstrapScript)
& ([Scriptblock]::Create($InstallScript)) -RepositoryCredential $RepositoryUser -AdditionalSources @(
    @{
        Name = "ChocolateyTest"
        Source = $TestRepositoryUrl
        Credentials = $RepositoryUser
    }
)

# We disable this repository when it's not being used in jobs
choco source disable --name=ChocolateyTest

if ($CentralManagementAddress) {
    choco config set CentralManagementServiceUrl $CentralManagementAddress
}

if ($CentralManagementServiceSalt) {
    choco config set centralManagementServiceCommunicationSaltAdditivePassword $CentralManagementServiceSalt
}

if ($CentralManagementClientSalt) {
    choco config set centralManagementClientCommunicationSaltAdditivePassword $CentralManagementClientSalt
}

# Install Java Runtime
choco install temurin21jre --params='/ADDLOCAL=FeatureEnvironment,FeatureJavaHome' --confirm --no-progress
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1
    Update-SessionEnvironment
}

# Install Jenkins
choco install jenkins --confirm --no-progress --params="/Java_Home=$(Convert-Path $env:ProgramFiles\*\jre-21*)"

# First-run configuration for Jenkins
$JenkinsHome = "C:\ProgramData\Jenkins\.jenkins"

$JenkinsVersion = (choco.exe list jenkins --exact --limit-output).Split('|')[1]
$JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.UpgradeWizard.state -Encoding utf8
$JenkinsVersion | Out-File -FilePath $JenkinsHome\jenkins.install.InstallUtil.lastExecVersion -Encoding utf8

$JenkinsCred = [pscredential]::new(
    "admin",
    (Get-Content $JenkinsHome/secrets/initialAdminPassword)
)

Stop-Service Jenkins

$JenkinsScheme, $Port, $HostName = "http", "8080", $env:ComputerName
if ($Thumbprint) {
    $JenkinsScheme, $Port, $HostName = "https", "7443", $(
        if ((Get-Item Cert:\LocalMachine\TrustedPeople\$Thumbprint).Subject -match 'CN\s?=\s?(?<Subject>[^,\s]+)') {
            $Matches.Subject
        }
    )

    $KeyStore = "$JenkinsHome\keystore.jks"
    $KeyTool = Convert-Path "C:\Program Files\Eclipse Adoptium\jre-*.*\bin\keytool.exe"  # Using Temurin jre package keytool
    $Passkey = [System.Net.NetworkCredential]::new(
        "JksPassword",
        "$(New-Guid)"
    ).Password

    if (Test-Path $KeyStore) {
        Remove-Item $KeyStore -Force
    }

    # Generate the Keystore file
    try {
        $CertificatePath = Join-Path $env:Temp "$($Thumbprint).pfx"
        $CertificatePassword = [System.Net.NetworkCredential]::new(
            "TemporaryCertificatePassword",
            "$(New-Guid)"
        )

        # Temporarily export the certificate as a PFX
        $null = Get-ChildItem Cert:\LocalMachine\TrustedPeople\ | Where-Object {$_.Thumbprint -eq $Thumbprint} | Export-PfxCertificate -FilePath $CertificatePath -Password $CertificatePassword.SecurePassword

        # Using a job to hide improper non-output streams
        $Job = Start-Job {
            $CurrentAlias = ($($using:CertificatePassword.Password | & $using:KeyTool -list -v -storetype PKCS12 -keystore $using:CertificatePath -J"-Duser.language=en") -match "^Alias.*").Split(':')[1].Trim()

            $null = & $using:KeyTool -importkeystore -srckeystore $using:CertificatePath -srcstoretype PKCS12 -srcstorepass $using:CertificatePassword.Password -destkeystore $using:KeyStore -deststoretype JKS -alias $currentAlias -destalias jetty -deststorepass $using:Passkey
            $null = & $using:KeyTool -keypasswd -keystore $using:KeyStore -alias jetty -storepass $using:Passkey -keypass $using:CertificatePassword.Password -new $using:Passkey
        } | Wait-Job
        if ($Job.State -eq 'Failed') {
            $Job | Receive-Job
        } else {
            $Job | Remove-Job
        }
    } finally {
        # Clean up the exported certificate
        Remove-Item $CertificatePath
    }

    # Update the Jenkins Configuration
    $XmlPath = "C:\Program Files\Jenkins\jenkins.xml"
    [xml]$Xml = Get-Content $XmlPath
    @{
        httpPort              = -1
        httpsPort             = $Port
        httpsKeyStore         = $KeyStore
        httpsKeyStorePassword = $Passkey
    }.GetEnumerator().ForEach{
        if ($Xml.SelectSingleNode("/service/arguments")."#text" -notmatch [Regex]::Escape("--$($_.Key)=$($_.Value)")) {
            $Xml.SelectSingleNode("/service/arguments")."#text" = $Xml.SelectSingleNode("/service/arguments")."#text" -replace "\s*--$($_.Key)=.+?\b", ""
            $Xml.SelectSingleNode("/service/arguments")."#text" += " --$($_.Key)=$($_.Value)"
        }
    }
    $Xml.Save($XmlPath)
}
netsh advfirewall firewall add rule name="Jenkins-$($Port)" dir=in action=allow protocol=tcp localport=$Port

# Set Jenkins location
@"
<?xml version='1.1' encoding='UTF-8'?>
<jenkins.model.JenkinsLocationConfiguration>
<adminAddress>address not configured yet &lt;nobody@nowhere&gt;</adminAddress>
<jenkinsUrl>$($JenkinsScheme)://$($HostName):$($Port)</jenkinsUrl>
</jenkins.model.JenkinsLocationConfiguration>
"@ | Out-File -FilePath "$JenkinsHome\jenkins.model.JenkinsLocationConfiguration.xml" -Encoding utf8

# Install Jenkins plugin
choco install chocolatey-licensed-jenkins-plugins --confirm --no-progress

switch ($RepositorySolution) {
    "nexus" {
        $RepositoryBaseUrl = $ProductionRepositoryUrl -replace '/repository/(?<RepositoryName>.+?)/(index.json)?$'
        choco install chocolatey-licensed-jenkins-jobs --params="/NexusUrl=$($RepositoryBaseUrl) /NexusApiKey=$($RepositoryApiKey) /PackageUserName=$($RepositoryUser.UserName)" --package-parameters-sensitive="/PackageUserPassword=$($RepositoryUser.GetNetworkCredential().Password)" --confirm --no-progress

        # TODO: Update jobs _again_ with custom repository names.
    }
    "proget" {
        choco install chocolatey-licensed-jenkins-scripts --confirm --no-progress

        # TODO: Create new jobs to point at ProGet
    }
}

Start-Service Jenkins

# Output useful values for the user
[PSCustomObject]@{
    JenkinsUri = "$($JenkinsScheme)://$($HostName):$($Port)"
    JenkinsUser = $JenkinsCred
}