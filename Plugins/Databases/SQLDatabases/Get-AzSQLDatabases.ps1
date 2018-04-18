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
        $AzureSQLConfig = $AzureObject.AzureConfig.AzureSQLDatabases
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "SQL Database", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Manager Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $ResourceGroups = $AzureObject.ResourceGroups
        #List All Databases
        $DatabaseServers = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                           -Provider $AzureSQLConfig.Provider -Objectype "servers" -APIVersion $AzureSQLConfig.APIVersion `
                           -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllDatabaseServers = @()
        $AllDatabases = @()
        if($DatabaseServers){
            foreach($Server in $DatabaseServers){
                if($Server.name -AND $Server.id){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for databases in {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, ($server.id).subString(1), "databases", $AzureSQLConfig.APIVersion)
                    #Get database info
                    $Databases = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #######Get Server Threat Detection Policy########
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Get Server Threat Detection Policy for {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "securityAlertPolicies/Default", "2015-05-01-Preview")
                    $ThreatDetectionPolicy = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #######Get Server Auditing Policy########
                    #https://www.mssqltips.com/sqlservertip/5180/azure-sql-database-auditing-using-blob-storage/
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Get server auditing policy for {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                
                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "auditingSettings/Default", "2015-05-01-Preview")
                    $ServerAuditingPolicy = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    #Add Server to Array
                    $AzureSqlServer = New-Object -TypeName PSCustomObject
                    $AzureSqlServer | Add-Member -type NoteProperty -name serverName -value $server.name
                    $AzureSqlServer | Add-Member -type NoteProperty -name serverLocation -value $server.location
                    $AzureSqlServer | Add-Member -type NoteProperty -name serverKind -value $server.kind
                    $AzureSqlServer | Add-Member -type NoteProperty -name resourceGroupName -value $server.id.Split("/")[4]
                    $AzureSqlServer | Add-Member -type NoteProperty -name fullyQualifiedDomainName -value $server.properties.fullyQualifiedDomainName
                    $AzureSqlServer | Add-Member -type NoteProperty -name administratorLogin -value $server.properties.administratorLogin
                    $AzureSqlServer | Add-Member -type NoteProperty -name administratorLoginPassword -value $server.properties.administratorLoginPassword
                    $AzureSqlServer | Add-Member -type NoteProperty -name externalAdministratorLogin -value $server.properties.externalAdministratorLogin
                    $AzureSqlServer | Add-Member -type NoteProperty -name externalAdministratorSid -value $server.properties.externalAdministratorSid
                    $AzureSqlServer | Add-Member -type NoteProperty -name version -value $server.properties.version
                    $AzureSqlServer | Add-Member -type NoteProperty -name auditingPolicyState -value $ServerAuditingPolicy.properties.state
                    $AzureSqlServer | Add-Member -type NoteProperty -name auditingRetentionDays -value $ServerAuditingPolicy.properties.retentionDays
                    $AzureSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicy -value $ThreatDetectionPolicy.properties.state
                    $AzureSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyDisabledAlerts -value $ThreatDetectionPolicy.properties.disabledAlerts
                    $AzureSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAddresses -value $ThreatDetectionPolicy.properties.emailAddresses
                    $AzureSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAccountAdmins -value $ThreatDetectionPolicy.properties.emailAccountAdmins
                    $AzureSqlServer | Add-Member -type NoteProperty -name threatDetectionPolicyRetentionDays -value $ThreatDetectionPolicy.properties.retentionDays  
                    #Add to list
                    $AllDatabaseServers+=$AzureSqlServer
                    #Create object for each database found
                    foreach ($sql in $Databases){
                        $AzureSql = New-Object -TypeName PSCustomObject
                        $AzureSql | Add-Member -type NoteProperty -name serverName -value $server.name
                        $AzureSql | Add-Member -type NoteProperty -name serverStatus -value $server.properties.state
                        $AzureSql | Add-Member -type NoteProperty -name resourceGroupName -value $server.id.Split("/")[4]
                        $AzureSql | Add-Member -type NoteProperty -name databaseName -value $sql.name
                        $AzureSql | Add-Member -type NoteProperty -name databaseLocation -value $sql.location
                        $AzureSql | Add-Member -type NoteProperty -name databaseStatus -value $sql.properties.status
                        $AzureSql | Add-Member -type NoteProperty -name databaseEdition -value $sql.properties.edition
                        $AzureSql | Add-Member -type NoteProperty -name serviceLevelObjective -value $sql.properties.serviceLevelObjective
                        $AzureSql | Add-Member -type NoteProperty -name databaseCollation -value $sql.properties.collation
                        $AzureSql | Add-Member -type NoteProperty -name databaseMaxSizeBytes -value $sql.properties.maxSizeBytes
                        $AzureSql | Add-Member -type NoteProperty -name databaseCreationDate -value $sql.properties.creationDate
                        $AzureSql | Add-Member -type NoteProperty -name databaseSampleName -value $sql.properties.sampleName
                        $AzureSql | Add-Member -type NoteProperty -name databaseDefaultSecondaryLocation -value $sql.properties.defaultSecondaryLocation
                        $AzureSql | Add-Member -type NoteProperty -name databaseReadScale -value $sql.properties.readScale                  
                        if ($sql.name -ne "master"){
                            #######Get database Transparent Data Encryption Status########
                            Write-AzucarMessage -WriteLog $WriteLog -Message ("Get Transparent Data Encryption Status for {0}..." -f $sql.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                    
                            $uri = ("{0}{1}/databases/{2}/transparentDataEncryption/current?api-version={3}" -f $Instance.ResourceManager, $server.id, $sql.name, "2014-04-01")
                            $DTEPolicy = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                            #Add to PSOBJECT
                            $AzureSql | Add-Member -type NoteProperty -name databaseEncryptionStatus -value $DTEPolicy.properties.status
                        
                            #######Get Database Auditing Policy########
                            $uri = ("{0}{1}/databases/{2}/{3}?api-version={4}" -f $Instance.ResourceManager, $server.id, $sql.name, "auditingSettings/Default", "2015-05-01-preview")
                            $AuditingPolicy = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                            #Add Auditing Policy for SQL database
                            $AzureSql | Add-Member -type NoteProperty -name databaseAuditingState -value $AuditingPolicy.properties.state
                            $AzureSql | Add-Member -type NoteProperty -name databaseAuditActionsAndGroups -value (@($AuditingPolicy.properties.auditActionsAndGroups) -join ',')
                            $AzureSql | Add-Member -type NoteProperty -name databaseAuditStorageAccountAccessKey -value $AuditingPolicy.properties.storageAccountAccessKey
                            $AzureSql | Add-Member -type NoteProperty -name databaseAuditStorageAccountName -value $AuditingPolicy.properties.storageEndpoint.Split("/").split(".")[2]
                            $AzureSql | Add-Member -type NoteProperty -name databaseAuditRetentionDays -value $AuditingPolicy.properties.retentionDays
                            #######Get Database Threat Detection Policy########
                            $uri = ("{0}{1}/databases/{2}/{3}?api-version={4}" -f $Instance.ResourceManager, $server.id, $sql.name, "securityAlertPolicies/Default", "2014-04-01")
                            $DatabaseTDEPolicy = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                            if($DatabaseTDEPolicy){
                                $AzureSql | Add-Member -type NoteProperty -name threatDetectionPolicy -value $DatabaseTDEPolicy.properties.state
                                $AzureSql | Add-Member -type NoteProperty -name threatDetectionPolicyDisabledAlerts -value $DatabaseTDEPolicy.properties.disabledAlerts
                                $AzureSql | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAddresses -value $DatabaseTDEPolicy.properties.emailAddresses
                                $AzureSql | Add-Member -type NoteProperty -name threatDetectionPolicyEmailAccountAdmins -value $DatabaseTDEPolicy.properties.emailAccountAdmins
                                $AzureSql | Add-Member -type NoteProperty -name threatDetectionPolicyRetentionDays -value $DatabaseTDEPolicy.properties.retentionDays
                                $AzureSql | Add-Member -type NoteProperty -name threatDetectionPolicyStorageAccountName -value $DatabaseTDEPolicy.properties.storageEndpoint.Split("/").split(".")[2]
                            }
                        }
                        else{
                            #Add to PSOBJECT
                            #Database encryption operations cannot be performed for 'master', 'model', 'tempdb', 'msdb' or 'resource' databases.
                            $AzureSql | Add-Member -type NoteProperty -name databaseEncryptionStatus -value "None"
                        }
                        #Add to list
                        $AllDatabases+=$AzureSql
                    }
                }
            }
        }
    }
    End{
        if($AllDatabaseServers -AND $AllDatabases){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllDatabaseServers
            $AllDatabaseServers.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzureSQLServer')
            #Create custom object for store data
            $AllSQLServers = New-Object -TypeName PSCustomObject
            $AllSQLServers | Add-Member -type NoteProperty -name Section -value $Section
            $AllSQLServers | Add-Member -type NoteProperty -name Data -value $AllDatabaseServers
            #Add SQL data to object
            if($AllSQLServers){
                $ReturnPluginObject | Add-Member -type NoteProperty -name SQLServers -value $AllSQLServers
            }
            #Add Servers to list
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllDatabases
            $AllDatabases.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AzureSQLDatabases')
            #Create custom object for store data
            $AllSQL = New-Object -TypeName PSCustomObject
            $AllSQL | Add-Member -type NoteProperty -name Section -value $Section
            $AllSQL | Add-Member -type NoteProperty -name Data -value $AllDatabases
            #Add SQL data to object
            if($AllSQL){
                $ReturnPluginObject | Add-Member -type NoteProperty -name SQLDatabases -value $AllSQL
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "SQL Database", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }