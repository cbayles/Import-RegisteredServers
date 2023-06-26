<#
.SYNOPSIS
    Copy all registered servers from SQL Server Management Studio to Azure Data Studio settings.

.PARAMETER PathToSettingsFile
    File Path to the Azure Data Studio settings file. Defaults to $env:APPDATA + "\AzureDataStudio\User\settings.json".

.PARAMETER SaveTo
    File Path to save the new ADS settings.json file to.
    By default, the settings.json in $PathToSettingsFile is overwritten.
    The original settings.json file is backed up to settings.json.old.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)] [string] $PathToSettingsFile = $null,
    [Parameter(Mandatory=$false)] [string] $SaveTo = $null
)

begin {
    if (!(Get-Module -ListAvailable SqlServer)) {
        throw "The SqlServer powershell module is required. Run 'Install-Module SqlServer'. More details are here: https://www.powershellgallery.com/packages/SqlServer"
    } elseif (!(Get-Module SqlServer)) {
        $error.Clear()
        Import-Module SqlServer -ErrorAction SilentlyContinue
        if ($error) {
            Get-Module -ListAvailable SqlServer
            Write-Output "The SqlServer powershell module appears to be installed but could not be imported. Run 'Import-Module SqlServer' to try again."
            throw $error
        }
    }

    # Requires -module sqlserver
    if (!$PathToSettingsFile) {
        Write-Verbose "No path specified, defaulting to current APPDATA environment variable..."
        $PathToSettingsFile = ($env:APPDATA + "\AzureDataStudio\User\settings.json")
        $oldFile = "$PathToSettingsFile.old"
        if (Test-Path $oldFile) {
            if ("y" -ine (Read-Host "$oldFile already exists. Overwrite? (y/n)")) {
                $oldFileCount = (Get-ChildItem "$oldFile*").Count
                $oldFile = "$oldFile.$oldFileCount"
            }
        }
        Write-Verbose "Backing up existing settings file to $oldFile ..."
        Copy-Item -Path $PathToSettingsFile -Destination $oldFile
        Write-Verbose "Path to settings = $PathToSettingsFile"
    }

    Write-Verbose "Reading current settings file..."
    $UserSettings = (get-content -Path $PathToSettingsFile -Raw | ConvertFrom-Json)
}

process {
    $RegisteredServers = Get-ChildItem SQLSERVER:\SQLRegistration -Recurse | Where-Object {$_.ServerType -eq "DatabaseEngine"}
    $RegisteredServers.Refresh()
    $ServerGroups = $RegisteredServers | Where-Object { $_.GetType().Name -eq "ServerGroup" }
    $Servers = $RegisteredServers | Where-Object { $_.GetType().Name -eq "RegisteredServer" }
    $RootConnectionGroup = $UserSettings."datasource.connectionGroups" | Where-Object {$_.Name -eq "ROOT"}

    Write-Verbose "Getting server groups..."
    if ($null -eq ($UserSettings."datasource.connectionGroups" | Where-Object {$_.Name -eq "ROOT"})) {
        Write-Warning "No root level group detected. Let's fix that, shall we?"
        $rootLevel = @()
        $rootLevel += [pscustomobject] @{
            name = "ROOT"
            id = ([guid]::NewGuid()).ToString()
        }
        $UserSettings | Add-Member -Name 'datasource.connectionGroups' -MemberType NoteProperty -Value $rootLevel | Out-Null
    }

    $colors = @("#A1634D", "#7F0000", "#914576", "#6E9B59", "#5F82A5", "#4452A6", "#6A6599", "#515151")
    $colorIndex = 0
    $RootConnectionGroup = $UserSettings."datasource.connectionGroups" | Where-Object {$_.Name -eq "ROOT"}
    ForEach ($sg in $ServerGroups) {
        $ParentID = $RootConnectionGroup.id
        $ParentName = $RootConnectionGroup.name
        $ExistingParent = $UserSettings."datasource.connectionGroups" | Where-Object {$_.Name -eq $sg.Parent.DisplayName}
        if ($null -ne $ExistingParent) {
            # don't add Database Engine Server Group to avoid some nesting. treat it as ROOT
            if ($ExistingParent.Name -ne "Database Engine Server Group") {
                $ParentID = $ExistingParent.id
                $ParentName = $ExistingParent.Name
            }
        }
        $ExistingGroup = $UserSettings."datasource.connectionGroups" | Where-Object {$_.Name -eq $sg.DisplayName}
        if ($sg.DisplayName -eq "Database Engine Server Group") {
            Write-Verbose "Treating group '$($sg.DisplayName)' as ROOT to avoid nesting"
        } elseif ($null -eq $ExistingGroup) {
            Write-Verbose "Adding group '$($sg.DisplayName)' under '$ParentName' ($ParentID)..."
            $ConnectionGroup = [PSCustomObject] @{
                name = $sg.DisplayName
                id = ([guid]::NewGuid()).ToString()
                parentId = $ParentID
                color = $colors[$colorIndex++]
                description = "$($sg.DisplayName) database servers"
            }
            if ($colorIndex -ge $colors.Count) {
                $colorIndex = 0;
            }
            $UserSettings."datasource.connectionGroups" += $ConnectionGroup
        } else {
            $GroupName = $sg.DisplayName
            Write-Verbose "Ignoring group '$GroupName' because it already exists"
        }
    }

    Write-Verbose "Getting servers..."
    if ($null -eq $UserSettings."datasource.connections") {
        Write-Warning "No connections defined in settings file. Let's fix that, shall we?"
        $UserSettings | Add-Member -Name 'datasource.connections' -MemberType NoteProperty -Value @() | Out-Null
    }

    ForEach ($s in $Servers) {
        $ParentGroup = $UserSettings."datasource.connectionGroups" | Where-Object {$_.Name -eq $s.parent.displayname}
        if ($null -eq $ParentGroup) {
            $ParentGroup = $RootConnectionGroup
        }
        if ($null -eq ($UserSettings."datasource.connections" | Where-Object {$_.options.server -eq $s.ServerName -and $_.groupID -eq $ParentGroup.id})) {
            $dbUser = "";
            $dbPassword = "";
            $AuthenticationType = "Integrated"
            if ($s.authenticationType -eq 1)
            {
                $AuthenticationType = "SqlLogin"
                $ConnectionString = $s.ConnectionString
                $dbUser = $ConnectionString.replace(" ","").split(";")[1].split("=")[1]
                $dbPassword = $ConnectionString.replace(" ","").split(";")[2].split("=")[1]
            }
            elseif ($s.authenticationType -eq 5)
            {
                $AuthenticationType = "AzureMFA"
                $ConnectionString = $s.ConnectionString
                $dbUser = $s.ActiveDirectoryUserId
            }
            $Connection = [PSCustomObject] @{
                options = [PSCustomObject] @{
                    server=$s.ServerName
                    connectionName=$s.Name
                    # database=""
                    # databaseDisplayName=""
                    authenticationType=$AuthenticationType
                    user=$dbUser
                    password=$dbPassword
                    # applicationName="AzureDataStudio"
                    trustServerCertificate=$true
                }
                groupId = $ParentGroup.id
                providerName = "MSSQL"
                savePassword = $true
                id = ([guid]::NewGuid()).ToString()
            }
            $UserSettings."datasource.connections" += $Connection
        } else {
            $ServerName = $s.ServerName
            $GroupName = ($UserSettings."datasource.connectionGroups" | Where-Object {$_.Name -eq $s.parent.displayname}).Name
            Write-Verbose "Already a connection to $ServerName in $GroupName, skipping..."
        }
    }
}

end {
    if (!$SaveTo) {
        Write-Verbose "Writing new settings file to $PathToSettingsFile ..."
        $UserSettings | ConvertTo-Json -Depth 99 | Out-File -FilePath $PathToSettingsFile -Encoding "UTF8"
    } else {
        Write-Verbose "Writing new settings file to $SaveTo ..."
        $UserSettings | ConvertTo-Json -Depth 99 | Out-File -FilePath $SaveTo -Encoding "UTF8"
    }
}
