#Plugin extract Firewall Rules from each MySQL Server from Azure
#https://docs.microsoft.com/en-us/rest/api/mysql/firewallrules/listbyserver
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "MySQL Database Firewall", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Databases
        $DatabaseServers = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                             -Provider $AzureMySQLConfig.Provider -Objectype "servers" `
                                             -APIVersion $AzureMySQLConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllMySQLFWRules = @()
        if($DatabaseServers){
            foreach($Server in $DatabaseServers){
                if($Server.name -AND $Server.id){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for firewall rules in {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
            
                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "firewallrules", $AzureMySQLConfig.APIVersion)
                    #Get database info
                    $MySQLFWRules = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    if($MySQLFWRules.properties){
                        foreach ($rule in $MySQLFWRules){
                            $AzureMySQLDBFWRule = New-Object -TypeName PSCustomObject
                            $AzureMySQLDBFWRule | Add-Member -type NoteProperty -name ServerName -value $server.name
                            $AzureMySQLDBFWRule | Add-Member -type NoteProperty -name Location -value $server.location
                            $AzureMySQLDBFWRule | Add-Member -type NoteProperty -name ResourceGroupName -value $server.id.Split("/")[4]
                            $AzureMySQLDBFWRule | Add-Member -type NoteProperty -name RuleName -value $rule.name
                            $AzureMySQLDBFWRule | Add-Member -type NoteProperty -name StartIpAddress -value $rule.properties.startIpAddress
                            $AzureMySQLDBFWRule | Add-Member -type NoteProperty -name EndIpAddress -value $rule.properties.endIpAddress
                            #Decorate object and add to list
                            $AzureDBFWRule.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.MySQLDatabaseFirewall')                               
                            $AllMySQLFWRules+= $AzureMySQLDBFWRule
                        }
                    }
                }                     
            }
        }
    }
    End{
        if($AllMySQLFWRules){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllMySQLFWRules
            $AllMySQLFWRules.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.MySQLDatabaseFirewall')
            #Create custom object for store data
            $MySQLDBFWRules = New-Object -TypeName PSCustomObject
            $MySQLDBFWRules | Add-Member -type NoteProperty -name Section -value $Section
            $MySQLDBFWRules | Add-Member -type NoteProperty -name Data -value $AllMySQLFWRules
            #Add data to object
            if($MySQLDBFWRules){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_mysql_database_firewall -value $MySQLDBFWRules
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "MySQL Database Firewall Rule", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }