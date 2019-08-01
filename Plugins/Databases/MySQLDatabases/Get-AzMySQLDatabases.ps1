#Plugin extract about MySQL Databases from Azure
[cmdletbinding()]
    Param (
            [Parameter(HelpMessage="Background Runspace ID")]
            [int]
            $bgRunspaceID,

            [Parameter(HelpMessage="Not used in this version")]
            [HashTable]
            $SyncServer,

            [Parameter(HelpMessage="Azure Object with valuable data")]
            [Object]
            $AzureObject,

            [Parameter(HelpMessage="Object to return data")]
            [Object]
            $ReturnPluginObject,

            [Parameter(HelpMessage="Verbosity Options")]
            [System.Collections.Hashtable]
            $Verbosity,

            [Parameter(Mandatory=$false, HelpMessage="Save message in log file")]
	        [Bool] $WriteLog

        )
    Begin{
        #Import Azure API
        $LocalPath = $AzureObject.LocalPath
        $API = $AzureObject.AzureAPI
        $Utils = $AzureObject.Utils
        . $API
        . $Utils

        #Import Localized data
        $LocalizedDataParams = $AzureObject.LocalizedDataParams
        Import-LocalizedData @LocalizedDataParams;
        #Import Global vars
        $LogPath = $AzureObject.LogPath
        Set-Variable LogPath -Value $LogPath -Scope Global
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AzureMySQLConfig = $AzureObject.AzureConfig.AzureMySQLDatabases
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "MySQL Database", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                            -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Manager Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $ResourceGroups = $AzureObject.ResourceGroups
        #List All Databases
        $DatabaseServers = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                           -Provider $AzureMySQLConfig.Provider -Objectype "servers" -APIVersion $AzureMySQLConfig.APIVersion `
                           -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllMySQLServers = @()
        $AllMySQLDatabases = @()
        $AllMySQLServerConfigurations = @()
        if($DatabaseServers){
            foreach($Server in $DatabaseServers){
                if($Server.name -AND $Server.id){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for databases in {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, ($server.id).subString(1), "databases", $AzureMySQLConfig.APIVersion)
                    #Get database info
                    $Databases = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #######Get Server Threat Detection Policy########
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Get Server Threat Detection Policy for {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "securityAlertPolicies/Default", $AzureMySQLConfig.APIVersion)
                    $ThreatDetectionPolicy = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #Get MySQL server Configuration
                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "configurations", $AzureMySQLConfig.APIVersion)
                    $MySQLServerConfiguration = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #Add Server to Array
                    $AzureMySqlServer = New-Object -TypeName PSCustomObject
                    $AzureMySqlServer | Add-Member -type NoteProperty -name serverName -value $server.name
                    $AzureMySqlServer | Add-Member -type NoteProperty -name serverLocation -value $server.location
                    $AzureMySqlServer | Add-Member -type NoteProperty -name resourceGroupName -value $server.id.Split("/")[4]
                    $AzureMySqlServer | Add-Member -type NoteProperty -name fullyQualifiedDomainName -value $server.properties.fullyQualifiedDomainName
                    $AzureMySqlServer | Add-Member -type NoteProperty -name earliestRestoreDate -value $server.properties.earliestRestoreDate
                    $AzureMySqlServer | Add-Member -type NoteProperty -name sslEnforcement -value $server.properties.sslEnforcement
                    $AzureMySqlServer | Add-Member -type NoteProperty -name administratorLogin -value $server.properties.administratorLogin
                    $AzureMySqlServer | Add-Member -type NoteProperty -name userVisibleState -value $server.properties.userVisibleState
                    $AzureMySqlServer | Add-Member -type NoteProperty -name backupRetentionDays -value $server.properties.storageProfile.backupRetentionDays
                    $AzureMySqlServer | Add-Member -type NoteProperty -name geoRedundantBackup -value $server.properties.storageProfile.geoRedundantBackup
                    $AzureMySqlServer | Add-Member -type NoteProperty -name storageAutoGrow -value $server.properties.storageProfile.storageAutoGrow
                    $AzureMySqlServer | Add-Member -type NoteProperty -name replicationRole -value $server.properties.replicationRole
                    $AzureMySqlServer | Add-Member -type NoteProperty -name masterServerId -value $server.properties.masterServerId
                    $AzureMySqlServer | Add-Member -type NoteProperty -name version -value $server.properties.version
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicy -value $ThreatDetectionPolicy.properties.state
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyDisabledAlerts -value (@($ThreatDetectionPolicy.properties.disabledAlerts) -join ',')
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAddresses -value (@($ThreatDetectionPolicy.properties.emailAddresses) -join ',')
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAccountAdmins -value $ThreatDetectionPolicy.properties.emailAccountAdmins
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyRetentionDays -value $ThreatDetectionPolicy.properties.retentionDays  
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyStorageEndpoint -value $ThreatDetectionPolicy.properties.storageEndpoint  
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyStorageAccountAccessKey -value $ThreatDetectionPolicy.properties.storageAccountAccessKey  
                    $AzureMySqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyCreationTime -value $ThreatDetectionPolicy.properties.creationTime  
                    #Add to list
                    $AllMySQLServers+=$AzureMySqlServer
                    #Create object for each database found
                    foreach ($sql in $Databases){
                        $AzureMySQLDatabase = New-Object -TypeName PSCustomObject
                        $AzureMySQLDatabase | Add-Member -type NoteProperty -name serverName -value $server.name
                        $AzureMySQLDatabase | Add-Member -type NoteProperty -name databaseCharset -value $server.properties.charset
                        $AzureMySQLDatabase | Add-Member -type NoteProperty -name resourceGroupName -value $server.id.Split("/")[4]
                        $AzureMySQLDatabase | Add-Member -type NoteProperty -name databaseName -value $sql.name
                        $AzureMySQLDatabase | Add-Member -type NoteProperty -name databaseCollation -value $sql.properties.collation
                        #Add to list
                        $AllMySQLDatabases+=$AzureMySQLDatabase
                    }
                    #Create object for each server configuration found
                    foreach ($SingleConfiguration in $MySQLServerConfiguration){
                        $AzureMySQLServerConfiguration = New-Object -TypeName PSCustomObject
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name serverName -value $server.name
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterName -value $SingleConfiguration.name
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterDescription -value $SingleConfiguration.properties.description
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterValue -value $SingleConfiguration.properties.value
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterDefaultValue -value $SingleConfiguration.properties.defaultValue
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterDefaultValue -value $SingleConfiguration.properties.defaultValue
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterDataType -value $SingleConfiguration.properties.dataType
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterSource -value $SingleConfiguration.properties.source
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterIsConfigPendingRestart -value $SingleConfiguration.properties.isConfigPendingRestart
                        $AzureMySQLServerConfiguration | Add-Member -type NoteProperty -name parameterIsDynamicConfig -value $SingleConfiguration.properties.isDynamicConfig
                        #Add to list
                        $AllMySQLServerConfigurations+=$AzureMySQLServerConfiguration
                    }
                }
            }
        }
    }
    End{
        if($AllMySQLServers -AND $AllMySQLDatabases -AND $AllMySQLServerConfigurations){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllMySQLServers
            $AllMySQLServers.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzureMySQLServer')
            #Create custom object for store data
            $AzureMySQLServers = New-Object -TypeName PSCustomObject
            $AzureMySQLServers | Add-Member -type NoteProperty -name Section -value $Section
            $AzureMySQLServers | Add-Member -type NoteProperty -name Data -value $AllMySQLServers
            #Add MySQL data to object
            if($AzureMySQLServers){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_mysql_servers -value $AzureMySQLServers
            }
            #Add Databases to list
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllMySQLDatabases
            $AllMySQLDatabases.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzureMySQLDatabases')
            #Create custom object for store data
            $AzureMySQL = New-Object -TypeName PSCustomObject
            $AzureMySQL | Add-Member -type NoteProperty -name Section -value $Section
            $AzureMySQL | Add-Member -type NoteProperty -name Data -value $AllMySQLDatabases
            #Add MySQL data to object
            if($AzureMySQL){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_mysql_databases -value $AzureMySQL
            }
            #Add Server configuration to list
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllMySQLServerConfigurations
            $AllMySQLServerConfigurations.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzureMySQLSingleConfiguration')
            #Create custom object for store data
            $AzureMySQLConfiguration = New-Object -TypeName PSCustomObject
            $AzureMySQLConfiguration | Add-Member -type NoteProperty -name Section -value $Section
            $AzureMySQLConfiguration | Add-Member -type NoteProperty -name Data -value $AllMySQLServerConfigurations
            #Add MySQL server configuration to object
            if($AzureMySQLConfiguration){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_mysql_configuration -value $AzureMySQLConfiguration
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "MySQL Database", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }