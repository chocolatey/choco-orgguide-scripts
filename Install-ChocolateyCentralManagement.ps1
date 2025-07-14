[CmdletBinding(DefaultParameterSetName = 'default')]
Param(
    [Parameter(ParameterSetName = 'default')]
    [String]
    [ValidateSet('Database', 'Service', 'Website')]
    $Component,

    [Parameter(Mandatory, ParameterSetName = 'default')]
    [String]
    $ConnectionString,

    [Parameter(ParameterSetName = 'default')]
    [PSCredential]
    $ServiceCredential,

    [Parameter(ParameterSetName = 'default')]
    [ValidateScript({ Test-Path $_ })]
    [String]
    $LicenseFile = $(
        if (Test-Path $PSScriptRoot\files\chocolatey.license.xml) {
            # Offline setup has been run, we should use that license.
            Join-Path $PSScriptRoot "files\chocolatey.license.xml"
        }
        elseif (Test-Path $env:ChocolateyInstall\license\chocolatey.license.xml) {
            # Chocolatey is already installed, we can use that license.
            Join-Path $env:ChocolateyInstall "license\chocolatey.license.xml"
        }
        else {
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

    [Parameter(ParameterSetName = 'offline')]
    [Switch]
    $IsOfflineInstall,

    [Parameter(ParameterSetName = 'offline')]
    [ValidateScript({
            if ((Test-Path $_) -and ((Get-Item $_).Name.EndsWith('.zip'))) {
                $true
            }
            else {
                throw 'File either does not exist or is not a .zip file'
            }
        })]
    [String]
    $OfflineInstallationMedia = 
    $(
        # Prompt the user for the license.
            $Wshell = New-Object -ComObject Wscript.Shell
            $null = $Wshell.Popup('You will need to provide the offline package archive. Please select the archive in the next file dialog.')
            $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = "$env:USERPROFILE\Downloads"
            $OpenFileDialog.filter = 'All Files (*.*)| *.*'
            $null = $OpenFileDialog.ShowDialog()

            $OpenFileDialog.filename
    ),

    [Parameter()]
    [String]
    $Certificate
)

begin {
    # Place the license file
    $licensePath = if (-not (Test-Path 'C:\ProgramData\chocolatey\license')) {
        New-Item 'C:\ProgramData\chocolatey\license' -ItemType Directory
    } 
    else {
        'C:\ProgramData\chocolatey\license'
    }

    Copy-Item $LicenseFile -Destination "$licensePath\chocolatey.license.xml" -Force

    function Set-SqlServerConfiguration {
        [CmdletBinding()]
        Param(
            [Parameter()]
            [String]
            $SqlTcpPort  = '1433',

            [Parameter()]
            [String]
            $SqlUdpPort = '1434',

            [Parameter()]
            [String]
            $SqlVersion = '16' 
        )
        # https://docs.microsoft.com/en-us/sql/tools/configuration-manager/tcp-ip-properties-ip-addresses-tab
        Write-Output "SQL Server: Configuring Remote Access on SQL Server Express."
        $assemblyList = 'Microsoft.SqlServer.Management.Common', 'Microsoft.SqlServer.Smo', 'Microsoft.SqlServer.SqlWmiManagement', 'Microsoft.SqlServer.SmoExtended'

        foreach ($assembly in $assemblyList) {
            $assembly = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
        }

        $wmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer # connects to localhost by default
        $instance = $wmi.ServerInstances | Where-Object { $_.Name -eq 'SQLEXPRESS' }

        $np = $instance.ServerProtocols | Where-Object { $_.Name -eq 'Np' }
        $np.IsEnabled = $true
        $np.Alter()

        $tcp = $instance.ServerProtocols | Where-Object { $_.Name -eq 'Tcp' }
        $tcp.IsEnabled = $true
        $tcp.Alter()

        $tcpIpAll = $tcp.IpAddresses | Where-Object { $_.Name -eq 'IpAll' }

        $tcpDynamicPorts = $tcpIpAll.IpAddressProperties | Where-Object { $_.Name -eq 'TcpDynamicPorts' }
        $tcpDynamicPorts.Value = ""
        $tcp.Alter()

        $tcpPort = $tcpIpAll.IpAddressProperties | Where-Object { $_.Name -eq 'TcpPort' }
        $tcpPort.Value = $SqlTcpPort
        $tcp.Alter()

        # TODO: THIS LINE IS VERSION DEPENDENT! Replace MSSQL16 with whatever version you have
        Write-Output "SQL Server: Setting Mixed Mode Authentication."
        New-ItemProperty $('HKLM:\Software\Microsoft\Microsoft SQL Server\MSSQL{0}.SQLEXPRESS\MSSQLServer\' -f $SqlVersion) -Name 'LoginMode' -Value 2 -Force
        # VERSION DEPENDENT ABOVE

        Write-Output "SQL Server: Forcing Restart of Instance."
        Restart-Service -Force 'MSSQL$SQLEXPRESS'

        Write-Output "SQL Server: Setting up SQL Server Browser and starting the service."
        Set-Service 'SQLBrowser' -StartupType Automatic
        Start-Service 'SQLBrowser'

        Write-Output "Firewall: Enabling SQLServer TCP port $SqlTcpPort."
        netsh advfirewall firewall add rule name="SQL Server $SqlTcpPort" dir=in action=allow protocol=TCP localport=1433 profile=any enable=yes service=any

        Write-Output "Firewall: Enabling SQL Server browser UDP port $SqlUdpPort."
        netsh advfirewall firewall add rule name="SQL Server Browser $SqlUdpPort" dir=in action=allow protocol=UDP localport=$SqlUdpPort profile=any enable=yes service=any
    }
    function Add-DatabaseUserAndRoles {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $Username,

            [Parameter(Mandatory = $true)]
            [string]
            $DatabaseName,

            [Parameter(Mandatory = $false)]
            [string]
            $DatabaseServer = 'localhost\SQLEXPRESS',

            [Parameter(Mandatory = $false)]
            [string[]]
            $DatabaseRoles = @('db_datareader'),

            [Parameter(Mandatory = $false)]
            [string]
            $DatabaseServerPermissionsOptions = 'Trusted_Connection=true;',

            [Parameter(Mandatory = $false)]
            [switch]
            $CreateSqlUser,

            [Parameter(Mandatory = $false)]
            [string]
            $SqlUserPassword
        )

        $LoginOptions = "FROM WINDOWS WITH DEFAULT_DATABASE=[$DatabaseName]"
        if ($CreateSqlUser) {
            $LoginOptions = "WITH PASSWORD='$SqlUserPassword', DEFAULT_DATABASE=[$DatabaseName], CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF"
        }

        $addUserSQLCommand = @"
USE [master]
IF EXISTS(SELECT * FROM msdb.sys.syslogins WHERE UPPER([name]) = UPPER('$Username'))
BEGIN
    DROP LOGIN [$Username]
END

CREATE LOGIN [$Username] $LoginOptions

USE [$DatabaseName]
IF EXISTS(SELECT * FROM sys.sysusers WHERE UPPER([name]) = UPPER('$Username'))
BEGIN
    DROP USER [$Username]
END

CREATE USER [$Username] FOR LOGIN [$Username]

"@

        foreach ($DatabaseRole in $DatabaseRoles) {
            $addUserSQLCommand += @"

ALTER ROLE [$DatabaseRole] ADD MEMBER [$Username]
"@
        }

        Write-Output "Adding $UserName to $DatabaseName with the following permissions: $($DatabaseRoles -Join ', ')"
        Write-Debug "running the following: \n $addUserSQLCommand"


        $Connection = New-Object System.Data.SQLClient.SQLConnection
        $Connection.ConnectionString = "server='$DatabaseServer';database='master';$DatabaseServerPermissionsOptions"
        $Connection.Open()
        $Command = New-Object System.Data.SQLClient.SQLCommand
        $Command.CommandText = $addUserSQLCommand
        $Command.Connection = $Connection
        $Command.ExecuteNonQuery()
        $Connection.Close()
    }

    # Complete the installation of Chocolatey
    switch ($PSCmdlet.ParameterSetName) {
        'offline' { 
            Write-Verbose -Message 'Using offline installation'
            # Create local Chocolatey source folder
            $localChocolateySource = if (-not (Test-Path 'C:\local_chocolatey')) {
                New-Item 'C:\local_chocolatey' -ItemType Directory
            }

            # Unzip required packages
            Expand-Archive $OfflineInstallationMedia -DestinationPath $localChocolateySource

            # Install Chocolatey
            $env:ChocolateyDownloadUrl = Convert-Path $localChocolateySource\chocolatey.*.nupkg
            $chocoInstallScript = Join-Path $localChocolateySource -ChildPath 'install.ps1'
            & $chocoInstallScript

            # Configure Chocolatey source            
            $ChocolateySource = $localChocolateySource

        }

        default {
            Write-Verbose 'Using online installation'
            # Install Chocolaetey
            Invoke-RestMethod https://ch0.co/go | Invoke-Expression
        }
    }
}
end {
    switch ($Component) {
        'Database' {
            try {
                # Base arguments for all choco commands
                $baseArgs = @('-y', '--no-progress')
                $sourceArgs = if ($ChocolateySource) { @("--source='$ChocolateySource'") } else { @() }

                # Dependencies
                & choco install chocolatey.extension dotnet-8.0-runtime dotnet-8.0-aspnetruntime @sourceArgs @baseArgs

                # Main package
                & choco install chocolatey-management-database @sourceArgs @baseArgs "--package-parameters-sensitive='/ConnectionString=$ConnectionString'"

                Write-Host "Database component setup completed. It is now safe to move on to other components"
            }
            catch {
                $Error[0]
            } 
        }

        'Service' {
            # Base arguments for all choco commands
            $baseArgs = @('-y', '--no-progress')
            $sourceArgs = if ($ChocolateySource) { @("--source='$ChocolateySource'") } else { @() }

            # Package parameters
            $parameterString = if ($ServiceCredential) {
                '/ConnectionString={0} /Username={1} /Password={2}' -f $ConnectionString, $ServiceCredential.UserName, $ServiceCredential.GetNetworkCredential().Password
            }
            else {
                '/ConnectionString={0}' -f $ConnectionString
            }

            # Dependencies
            & choco install chocolatey.extension dotnet-8.0-runtime dotnet-8.0-aspnetruntime @sourceArgs @baseArgs

            # Main package
            & choco install chocolatey-management-service @sourceArgs @baseArgs "--package-parameters-sensitive='$parameterString'"
        }

        'Website' {
            # Base arguments for all choco commands
            $baseArgs = @('-y', '--no-progress')
            $sourceArgs = if ($ChocolateySource) { @("--source='$ChocolateySource'") } else { @() }
            
            # Windows Features
            & choco install IIS-WebServer --source='windowsfeatures' @baseArgs
            & choco install IIS-ApplicationInit --source='windowsfeatures' @baseArgs
            
            # Package Dependencies
            & choco install chocolatey.extension @sourceArgs @baseArgs
            & choco install dotnet-aspnetcoremodule-v2 --version 18.0.25136 @sourceArgs @baseArgs
            & choco install dotnet-8.0-runtime @sourceArgs @baseArgs
            & choco install dotnet-8.0-aspnetruntime @sourceArgs @baseArgs

            # Package parameters
            $parameterString = if ($ServiceCredential) {
                '/ConnectionString={0} /Username={1} /Password={2}' -f $ConnectionString, $ServiceCredential.UserName, $ServiceCredential.GetNetworkCredential().Password
            }
            else {
                '/ConnectionString={0}' -f $ConnectionString
            }

            # Main package installation
            & choco install chocolatey-management-web @sourceArgs @baseArgs "--package-parameters-sensitive='$parameterString'"
        }

        default {
            # Base arguments for all choco commands
            $baseArgs = @('-y', '--no-progress')
            $sourceArgs = if ($ChocolateySource) { @("--source='$ChocolateySource'") } else { @() }

            # Windows Features
            & choco install IIS-WebServer --source='windowsfeatures' @baseArgs
            & choco install IIS-ApplicationInit --source='windowsfeatures' @baseArgs
            
            # Package Dependencies
            & choco install chocolatey.extension @sourceArgs @baseArgs
            & choco install dotnet-aspnetcoremodule-v2 --version 18.0.25136 @sourceArgs @baseArgs
            & choco install dotnet-8.0-runtime @sourceArgs @baseArgs
            & choco install dotnet-8.0-aspnetruntime @sourceArgs @baseArgs

            # Package parameters
            $parameterString = if ($ServiceCredential) {
                '/ConnectionString={0} /Username={1} /Password={2}' -f $ConnectionString, $ServiceCredential.UserName, $ServiceCredential.GetNetworkCredential().Password
            }
            else {
                '/ConnectionString={0}' -f $ConnectionString
            }

            # Install all components with SkipDatabasePermissionCheck
            & choco install chocolatey-management-database @sourceArgs @baseArgs "--package-parameters-sensitive='/SkipDatabasePermissionCheck $parameterString'"
            & choco install chocolatey-management-service @sourceArgs @baseArgs "--package-parameters-sensitive='/SkipDatabasePermissionCheck $parameterString'"
            & choco install chocolatey-management-web @sourceArgs @baseArgs "--package-parameters-sensitive='/SkipDatabasePermissionCheck $parameterString'"
            
            Add-DatabaseUserAndRoles -Username 'IIS APPPOOL\ChocolateyCentralManagement' -DatabaseName ChocolateyManagement -DatabaseRoles @('db_datareader', 'db_datawriter')
        }
    }

    if ($ChocolateySource) {
        Remove-Item $ChocolateySource -Recurse -Force
    }
}