#Plugin extract about Databases from Azure
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
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AzurePostgreSQLConfig = $AzureObject.AzureConfig.AzurePostgreSQLDatabases
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "PostgreSQL Database", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Manager Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $ResourceGroups = $AzureObject.ResourceGroups
        #List All Databases
        $DatabaseServers = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                           -Provider $AzurePostgreSQLConfig.Provider -Objectype "servers" -APIVersion $AzurePostgreSQLConfig.APIVersion `
                           -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllPostgreSQLServers = @()
        $AllPostgreSQLDatabases = @()
        $AllPostgreSQLServerConfigurations = @()
        if($DatabaseServers){
            foreach($Server in $DatabaseServers){
                if($Server.name -AND $Server.id){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for databases in {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, ($server.id).subString(1), "databases", $AzurePostgreSQLConfig.APIVersion)
                    #Get database info
                    $Databases = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #######Get Server Threat Detection Policy########
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Get Server Threat Detection Policy for {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "securityAlertPolicies/Default", "2017-12-01")
                    $ThreatDetectionPolicy = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #Get PostgreSQL server Configuration
                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "configurations", "2017-12-01")
                    $PostgreSQLServerConfiguration = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #Add Server to Array
                    $AzurePostgreSqlServer = New-Object -TypeName PSCustomObject
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name serverName -value $server.name
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name serverLocation -value $server.location
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name resourceGroupName -value $server.id.Split("/")[4]
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name fullyQualifiedDomainName -value $server.properties.fullyQualifiedDomainName
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name earliestRestoreDate -value $server.properties.earliestRestoreDate
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name sslEnforcement -value $server.properties.sslEnforcement
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name administratorLogin -value $server.properties.administratorLogin
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name userVisibleState -value $server.properties.userVisibleState
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name backupRetentionDays -value $server.properties.storageProfile.backupRetentionDays
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name geoRedundantBackup -value $server.properties.storageProfile.geoRedundantBackup
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name version -value $server.properties.version
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicy -value $ThreatDetectionPolicy.properties.state
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyDisabledAlerts -value $ThreatDetectionPolicy.properties.disabledAlerts
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAddresses -value $ThreatDetectionPolicy.properties.emailAddresses
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAccountAdmins -value $ThreatDetectionPolicy.properties.emailAccountAdmins
                    $AzurePostgreSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyRetentionDays -value $ThreatDetectionPolicy.properties.retentionDays  
                    #Add to list
                    $AllPostgreSQLServers+=$AzurePostgreSqlServer
                    #Create object for each database found
                    foreach ($sql in $Databases){
                        $AzurePostgreSQLDatabase = New-Object -TypeName PSCustomObject
                        $AzurePostgreSQLDatabase | Add-Member -type NoteProperty -name serverName -value $server.name
                        $AzurePostgreSQLDatabase | Add-Member -type NoteProperty -name databaseCharset -value $server.properties.charset
                        $AzurePostgreSQLDatabase | Add-Member -type NoteProperty -name resourceGroupName -value $server.id.Split("/")[4]
                        $AzurePostgreSQLDatabase | Add-Member -type NoteProperty -name databaseName -value $sql.name
                        $AzurePostgreSQLDatabase | Add-Member -type NoteProperty -name databaseCollation -value $sql.properties.collation
                        #Add to list
                        $AllPostgreSQLDatabases+=$AzurePostgreSQLDatabase
                    }
                    #Create object for each server configuration found
                    foreach ($SingleConfiguration in $PostgreSQLServerConfiguration){
                        $AzurePostgreSQLServerConfiguration = New-Object -TypeName PSCustomObject
                        $AzurePostgreSQLServerConfiguration | Add-Member -type NoteProperty -name serverName -value $server.name
                        $AzurePostgreSQLServerConfiguration | Add-Member -type NoteProperty -name parameterName -value $SingleConfiguration.name
                        $AzurePostgreSQLServerConfiguration | Add-Member -type NoteProperty -name parameterDescription -value $SingleConfiguration.properties.description
                        $AzurePostgreSQLServerConfiguration | Add-Member -type NoteProperty -name parameterValue -value $SingleConfiguration.properties.value
                        $AzurePostgreSQLServerConfiguration | Add-Member -type NoteProperty -name parameterDefaultValue -value $SingleConfiguration.properties.defaultValue
                        #Add to list
                        $AllPostgreSQLServerConfigurations+=$AzurePostgreSQLServerConfiguration
                    }
                }
            }
        }
    }
    End{
        if($AllPostgreSQLServers -AND $AllPostgreSQLDatabases -AND $AllPostgreSQLServerConfigurations){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllPostgreSQLServers
            $AllPostgreSQLServers.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzurePostgreSQLServer')
            #Create custom object for store data
            $AzurePostgreSQLServers = New-Object -TypeName PSCustomObject
            $AzurePostgreSQLServers | Add-Member -type NoteProperty -name Section -value $Section
            $AzurePostgreSQLServers | Add-Member -type NoteProperty -name Data -value $AllPostgreSQLServers
            #Add SQL data to object
            if($AzurePostgreSQLServers){
                $ReturnPluginObject | Add-Member -type NoteProperty -name PostgreSQLServers -value $AzurePostgreSQLServers
            }
            #Add Databases to list
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllPostgreSQLDatabases
            $AllPostgreSQLDatabases.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzurePostgreSQLDatabases')
            #Create custom object for store data
            $AzurePostgreSQL = New-Object -TypeName PSCustomObject
            $AzurePostgreSQL | Add-Member -type NoteProperty -name Section -value $Section
            $AzurePostgreSQL | Add-Member -type NoteProperty -name Data -value $AllPostgreSQLDatabases
            #Add SQL data to object
            if($AzurePostgreSQL){
                $ReturnPluginObject | Add-Member -type NoteProperty -name PostgreSQLDatabases -value $AzurePostgreSQL
            }
            #Add Server configuration to list
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllPostgreSQLServerConfigurations
            $AllPostgreSQLServerConfigurations.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzurePostgreSQLSingleConfiguration')
            #Create custom object for store data
            $AzurePostgreSQLConfiguration = New-Object -TypeName PSCustomObject
            $AzurePostgreSQLConfiguration | Add-Member -type NoteProperty -name Section -value $Section
            $AzurePostgreSQLConfiguration | Add-Member -type NoteProperty -name Data -value $AllPostgreSQLServerConfigurations
            #Add SQL server configuration to object
            if($AzurePostgreSQLConfiguration){
                $ReturnPluginObject | Add-Member -type NoteProperty -name PostgreSQLServerConfiguration -value $AzurePostgreSQLConfiguration
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "PostgreSQL Database", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }