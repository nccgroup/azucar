#Plugin extract Firewall Rules from each PostgreSQL Server from Azure
#https://docs.microsoft.com/en-us/rest/api/postgresql/firewallrules/listbyserver
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "PostgreSQL Database Firewall", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Databases
        $DatabaseServers = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                             -Provider $AzurePostgreSQLConfig.Provider -Objectype "servers" `
                                             -APIVersion $AzurePostgreSQLConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllPostgreSQLFWRules = @()
        if($DatabaseServers){
            foreach($Server in $DatabaseServers){
                if($Server.name -AND $Server.id){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for firewall rules in {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
            
                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "firewallrules", "2017-12-01")
                    #Get database info
                    $PostgreSQLFWRules = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    if($PostgreSQLFWRules.properties){
                        foreach ($rule in $PostgreSQLFWRules){
                            $AzurePostgreDBFWRule = New-Object -TypeName PSCustomObject
                            $AzurePostgreDBFWRule | Add-Member -type NoteProperty -name ServerName -value $server.name
                            $AzurePostgreDBFWRule | Add-Member -type NoteProperty -name Location -value $server.location
                            $AzurePostgreDBFWRule | Add-Member -type NoteProperty -name ResourceGroupName -value $server.id.Split("/")[4]
                            $AzurePostgreDBFWRule | Add-Member -type NoteProperty -name RuleName -value $rule.name
                            $AzurePostgreDBFWRule | Add-Member -type NoteProperty -name StartIpAddress -value $rule.properties.startIpAddress
                            $AzurePostgreDBFWRule | Add-Member -type NoteProperty -name EndIpAddress -value $rule.properties.endIpAddress
                            #Decorate object and add to list
                            $AzureDBFWRule.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.PostgreSQLDatabaseFirewall')                               
                            $AllPostgreSQLFWRules+= $AzurePostgreDBFWRule
                        }
                    }
                }                     
            }
        }
    }
    End{
        if($AllPostgreSQLFWRules){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllPostgreSQLFWRules
            $AllFWRules.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.PostgreSQLDatabaseFirewall')
            #Create custom object for store data
            $PostgreDBFWRules = New-Object -TypeName PSCustomObject
            $PostgreDBFWRules | Add-Member -type NoteProperty -name Section -value $Section
            $PostgreDBFWRules | Add-Member -type NoteProperty -name Data -value $AllPostgreSQLFWRules
            #Add data to object
            if($PostgreDBFWRules){
                $ReturnPluginObject | Add-Member -type NoteProperty -name PostgreSQLDatabaseFirewall -value $PostgreDBFWRules
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "PostgreSQL Database Firewall Rule", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }