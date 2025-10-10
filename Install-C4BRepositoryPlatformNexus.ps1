<#
.SYNOPSIS
C4B Organizational Deployment Guide Nexus setup script

.DESCRIPTION
- Performs the following Sonatype Nexus Repository setup steps
    - Install of Sonatype Nexus Repository Manager OSS instance
    - Binds Sonatype Nexus Repository instance with an SSL certificate
    - Setup of local windows TCP inbound firewall rule for repository access
    - Removal of all default Nexus repositories
    - Update of disk path for the default Nexus blob store if passed
    - Creates choco-core, production, and test NuGet hosted format repositories
    - Creates a choco-install raw hosted format repository, with a script for offline Chocolatey install
    - Setup of production and choco-core repositories as Chocolatey source on the Repository Server
    
#>
[CmdletBinding()]
param(
    # The certificate thumbprint that identifies the target SSL certificate in
    # the local machine certificate stores.
    [Parameter(Mandatory)]
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
    [ValidateScript({Test-CertificateDomain -Thumbprint $_})]
    [string]
    $Thumbprint = $(
        if ((Test-Path C:\choco-setup\clixml\chocolatey-for-business.xml) -and (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint) {
            (Import-Clixml C:\choco-setup\clixml\chocolatey-for-business.xml).CertThumbprint
         } else{
            Get-ChildItem Cert:\LocalMachine\TrustedPeople -Recurse | Sort-Object {
                $_.Issuer -eq $_.Subject # Prioritise any certificates above self-signed
            } | Select-Object -ExpandProperty Thumbprint -First 1
        }
    ),

    # Needed when using a wildcard SSL certificate
    # Must be a DNS resolvable FQDN for the server
    [string]
    $CertificateDnsName,

    # The TCP port used to host your Sonatype Nexus Repository instance over.
    # Default is TCP port '8443'
    [uint16]
    $NexusPort = 8443,

    # The name of the repository used to store trusted packages in.
    # This is the default repository your endpoints will have access to install packages from.
    # Defaults to 'ChocoProd'.
    [ValidateLength(1, 64)]
    [ValidatePattern("[A-Za-z0-9\-]+[A-Za-z0-9\.-_]")]
    [string]
    $ProdRepoName = 'choco-prod',

    # The name of the repository to store untested packages in, before promoting to the production repository.
    # Defaults to 'ChocoTest'.
    [ValidateLength(1, 64)]
    [ValidatePattern("[A-Za-z0-9\-]+[A-Za-z0-9\.-_]")]
    [string]
    $TestRepoName = 'choco-test',

    # The file path to associate to the default Nexus BlobStore for package storage on disk.
    # Defaults to packages being stored at C:\ProgramData\sonatype-work\nexus3\blobs\default if file path no passed.
    [ValidateScript({Test-Path $_})]
    [string]
    $PackageStoragePath


)
process {
    $DefaultEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    Start-Transcript -Path "$env:SystemDrive\choco-setup\logs\Start-C4bNexusSetup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    # Bootstrap Chocolatey for Business
    if (Test-Path $PSScriptRoot\Packages.zip) {
        # We're an offline install, despite Jenkins needing a repository and the internet to function.
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

    # Install base nexus-repository package
    Write-Host "Installing Sonatype Nexus Repository"
    $chocoArgs = @('install', 'nexus-repository', '-y' ,'--no-progress', "--package-parameters='/Fqdn:localhost'")
    & Invoke-Choco @chocoArgs

    $chocoArgs = @('install', 'nexushell', '-y' ,'--no-progress')
    & Invoke-Choco @chocoArgs

    $null = Set-NexusCert -Thumbprint $Thumbprint -Port $NexusPort
        
    if ($CertificateDnsName = Get-ChocoEnvironmentProperty CertSubject) {
        # Override the domain, so we don't get prompted for wildcard certificates
        Get-NexusLocalServiceUri -HostnameOverride $CertificateDnsName | Write-Verbose
    }
    
    # Add Nexus port access via firewall
    $FwRuleParams = @{
        DisplayName = "Nexus Repository access on TCP $NexusPort"
        Direction = 'Inbound'
        LocalPort = $NexusPort
        Protocol = 'TCP'
        Action = 'Allow'
    }
    $null = New-NetFirewallRule @FwRuleParams

    Wait-Site Nexus

    Write-Host "Configuring Sonatype Nexus Repository"

    # Build Credential Object, Connect to Nexus
    if (-not ($Credential = Get-ChocoEnvironmentProperty NexusCredential)) {
        Write-Host "Setting up admin account."
        $NexusDefaultPasswordPath = 'C:\programdata\sonatype-work\nexus3\admin.password'

        $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path $NexusDefaultPasswordPath) -and $Timeout.Elapsed.TotalMinutes -lt 3) {
            Start-Sleep -Seconds 5
        }

        $DefaultNexusCredential = [System.Management.Automation.PSCredential]::new(
            'admin',
            (Get-Content $NexusDefaultPasswordPath | ConvertTo-SecureString -AsPlainText -Force)
        )

        try {
            Connect-NexusServer -LocalService -Credential $DefaultNexusCredential -ErrorAction Stop

            $Credential = [PSCredential]::new(
                "admin",
                (New-ServicePassword)
            )

            Set-NexusUserPassword -Username admin -NewPassword $Credential.Password -ErrorAction Stop
            Set-ChocoEnvironmentProperty -Name NexusCredential -Value $Credential
        } finally {}

        if (Test-Path $NexusDefaultPasswordPath) {
            Remove-Item -Path $NexusDefaultPasswordPath
        }
    }
    Connect-NexusServer -LocalService -Credential $Credential

    # Disable anonymous authentication
    $null = Set-NexusAnonymousAuth -Disabled

    # Remove default repositories
    $null = Get-NexusRepository | Where-Object Name -NotLike "choco*" | Remove-NexusRepository -Force

    # Update Nexus Blob Storage location
    if ($PackageStoragePath) {
        $CurrentBlobStorePath = (Get-NexusBlobStore -Name default -Type File).path
        if ($CurrentBlobStorePath -eq 'default') {
            $CurrentBlobStorePath = Join-Path $env:ProgramData "sonatype-work\nexus3\blobs\default"
        }
        if ($PackageStoragePath -ne $CurrentBlobStorePath) {
            if (($InitialBlobStore = Get-NexusBlobStore).Where{$_.name -eq 'default'}.blobcount -ne 0 -and -not (Test-Path $PackageStoragePath)) {
                Write-Host "Migrating existing default blob store from '$($CurrentBlobStorePath)' to '$($PackageStoragePath)'"
                Copy-Item -Path $CurrentBlobStorePath -Destination $PackageStoragePath -Recurse
            }

            Update-NexusFileBlobStore -Name default -Path $PackageStoragePath -Confirm:$false

            if ($InitialBlobStore.blobcount -eq (Get-NexusBlobStore).Where{$_.name -eq 'default'}.blobcount) {
                Remove-Item $CurrentBlobStorePath -Recurse -Force
            }
        }
    }

    # Set a web interface warning when NexusBlob reaches less than 15GB of disk space
    Update-NexusFileBlobStore -Name default -SoftQuotaType Remaining -SoftQuotaLimit 15360 -Confirm:$false

    # Enable NuGet Auth Realm
    Enable-NexusRealm -Realm 'NuGet API-Key Realm'

    # Create Nexus repositories
    if (-not (Get-NexusRepository -Name choco-core)) {
        New-NexusNugetHostedRepository -Name choco-core -DeploymentPolicy Allow
    }

    if (-not (Get-NexusRepository -Name $ProdRepoName)) {
        New-NexusNugetHostedRepository -Name $ProdRepoName -DeploymentPolicy Allow
    }

    if (-not (Get-NexusRepository -Name $TestRepoName)) {
        New-NexusNugetHostedRepository -Name $TestRepoName -DeploymentPolicy Allow
    }

    if (-not (Get-NexusRepository -Name choco-install)) {
        New-NexusRawHostedRepository -Name choco-install -DeploymentPolicy Allow -ContentDisposition Attachment
    }


    # Create role for end user to pull from Nexus
    if (-not ($NexusRole = Get-NexusRole -Role 'chocorole' -ErrorAction SilentlyContinue)) {
        # Create Nexus role
        $RoleParams = @{
            Id          = "chocorole"
            Name        = "chocorole"
            Description = "Role for web enabled choco clients"
            Privileges  = @('nx-repository-view-nuget-*-browse', 'nx-repository-view-nuget-*-read', 'nx-repository-view-raw-*-read', 'nx-repository-view-raw-*-browse')
        }
        $NexusRole = New-NexusRole @RoleParams

        $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
        while ($Timeout.Elapsed.TotalSeconds -lt 30 -and -not (Get-NexusRole -Role $RoleParams.Id -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 3
        }
    }

    # Create new user for endpoint access
    if (-not (Get-NexusUser -User 'chocouser' -ErrorAction SilentlyContinue)) {
        # Create Nexus user
        $UserParams = @{
            Username     = 'chocouser'
            Password     = New-ServicePassword
            FirstName    = 'Choco'
            LastName     = 'User'
            EmailAddress = 'chocouser@example.com'
            Status       = 'Active'
            Roles        = $NexusRole.Id
        }
        $null = New-NexusUser @UserParams

        $Timeout = [System.Diagnostics.Stopwatch]::StartNew()
        while ($Timeout.Elapsed.TotalSeconds -lt 30 -and -not (Get-NexusUser -User $UserParams.Username -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 3
        }

        Set-ChocoEnvironmentProperty ChocoUserPassword $UserParams.Password
    }

    # Create role for task runner to push to Nexus
    if (-not ($PackageUploadRole = Get-NexusRole -Role "package-uploader" -ErrorAction SilentlyContinue)) {
        $PackageUploadRole = New-NexusRole -Name "package-uploader" -Id "package-uploader" -Description "Role allowed to push and list packages" -Privileges @(
            "nx-repository-view-nuget-*-edit"
            "nx-repository-view-nuget-*-read"
            "nx-apikey-all"
        )
    }

    # Create new user for package-upload - as this changes the usercontext, ensure this is the last thing in the script, or it's in a job
    if ($UploadUser = Get-ChocoEnvironmentProperty PackageUploadCredential) {
        Write-Verbose "Using existing PackageUpload credential '$($UploadUser.UserName)'"
    } else {
        $UploadUser = [PSCredential]::new(
            'chocoPackager',
            (New-ServicePassword -Length 64)
        )
    }

    if (-not (Get-NexusUser -User $UploadUser.UserName)) {
        $NewUser = @{
            Username     = $UploadUser.UserName
            Password     = $UploadUser.Password
            FirstName    = "Chocolatey"
            LastName     = "Packager"
            EmailAddress = "packager@$env:ComputerName.local"
            Status       = "Active"
            Roles        = $PackageUploadRole.Id
        }
        $null = New-NexusUser @NewUser

        Set-ChocoEnvironmentProperty -Name PackageUploadCredential -Value $UploadUser
    }

    # Retrieve the API Key to use with Automation Platform
    if ($NuGetApiKey = Get-ChocoEnvironmentProperty PackageApiKey) {
        Write-Verbose "Using existing Nexus Api Key for '$($UploadUser.UserName)'"
    } else {
        $NuGetApiKey = (Get-NexusNuGetApiKey -Credential $UploadUser).apiKey
        Set-ChocoEnvironmentProperty -Name PackageApiKey -Value $NuGetApiKey
    }

    # Push latest ChocolateyInstall.ps1 to raw repo
    $ScriptDir = "$env:SystemDrive\choco-setup\files\scripts"
    $ChocoInstallScript = "$ScriptDir\ChocolateyInstall.ps1"

    if (-not (Test-Path $ChocoInstallScript)) {
        Invoke-WebRequest -Uri 'https://chocolatey.org/install.ps1' -OutFile $ChocoInstallScript
    }

    $Signature = Get-AuthenticodeSignature -FilePath $ChocoInstallScript

    if ($Signature.Status -eq 'Valid' -and $Signature.SignerCertificate.Subject -eq 'CN="Chocolatey Software, Inc", O="Chocolatey Software, Inc", L=Topeka, S=Kansas, C=US') {
        $null = New-NexusRawComponent -RepositoryName 'choco-install' -File $ChocoInstallScript
    } else {
        Write-Error "ChocolateyInstall.ps1 script signature is not valid. Please investigate."
    }

    # Nexus NuGet V3 Compatibility
    Invoke-Choco feature disable --name="'usePackageRepositoryOptimizations'"

    # Add production repository as a Chocolatey source
    $LocalSource = "$((Get-NexusRepository -Name $ProdRepoName).url)/index.json"
    Invoke-Choco source add -n $ProdRepoName -s $LocalSource -u="$($UploadUser.UserName)" -p="$($UploadUser.GetNetworkCredential().Password)" --priority 1

    # Add Chocolatey Core repository as a Chocolatey source
    $LocalSource = "$((Get-NexusRepository -Name 'choco-core').url)/index.json"
    Invoke-Choco source add -n 'choco-core' -s $LocalSource -u="$($UploadUser.UserName)" -p="$($UploadUser.GetNetworkCredential().Password)" --priority 9 --admin-only

    # Push all packages from previous steps to NuGet repo
    Write-Host "Pushing C4B Environment Packages to 'choco-core'"
    Get-ChildItem -Path $TemporarySource -Filter *.nupkg | ForEach-Object {
        Invoke-Choco push $_.FullName --source $LocalSource --apikey $NugetApiKey --force
    }

    # Save useful params
    Update-Clixml -Properties @{
        NexusUri = Get-NexusLocalServiceUri
        NexusCredential = $Credential
        NexusProductionRepository = "$((Get-NexusRepository -Name $ProdRepoName).url)/index.json"
        NexusTestRepository = "$((Get-NexusRepository -Name $TestRepoName).url)/index.json"
        NexusChocolateyCoreRepository = "$((Get-NexusRepository -Name 'choco-core').url)/index.json"
        NuGetApiKey = $NugetApiKey | ConvertTo-SecureString -AsPlainText -Force
    }
}
end {
    if ($TemporarySource) {
    choco source remove --name='Bootstrap'
    Remove-Item $TemporarySource
    }
    $ErrorActionPreference = $DefaultEap
    Stop-Transcript
}