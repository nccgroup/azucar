#Plugin extract Firewall Rules from each SQL Server from Azure
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
        $AzureSQLConfig = $AzureObject.AzureConfig.AzureSQLDatabases
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "SQL Database Firewall", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Databases
        $DatabaseServers = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                             -Provider $AzureSQLConfig.Provider -Objectype "servers" `
                                             -APIVersion $AzureSQLConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllFWRules = @()
        if($DatabaseServers){
            foreach($Server in $DatabaseServers){
                if($Server.name -AND $Server.id){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for firewall rules in {0}..." -f $Server.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
            
                    $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $server.id, "firewallrules", "2014-04-01")
                    #Get database info
                    $FWRules = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                    if($FWRules.properties){
                        foreach ($rule in $FWRules){
                            $AzureDBFWRule = New-Object -TypeName PSCustomObject
                            $AzureDBFWRule | Add-Member -type NoteProperty -name ServerName -value $server.name
                            $AzureDBFWRule | Add-Member -type NoteProperty -name Location -value $server.location
                            $AzureDBFWRule | Add-Member -type NoteProperty -name ResourceGroupName -value $server.id.Split("/")[4]
                            $AzureDBFWRule | Add-Member -type NoteProperty -name RuleLocation -value $rule.location
                            $AzureDBFWRule | Add-Member -type NoteProperty -name Kind -value $rule.kind
                            $AzureDBFWRule | Add-Member -type NoteProperty -name RuleName -value $rule.name
                            $AzureDBFWRule | Add-Member -type NoteProperty -name StartIpAddress -value $rule.properties.startIpAddress
                            $AzureDBFWRule | Add-Member -type NoteProperty -name EndIpAddress -value $rule.properties.endIpAddress
                            #Decorate object and add to list
                            $AzureDBFWRule.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.DatabaseFirewall')                               
                            $AllFWRules+= $AzureDBFWRule
                        }
                    }
                }                     
            }
        }
    }
    End{
        if($AllFWRules){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllFWRules
            $AllFWRules.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.DatabaseFirewall')
            #Create custom object for store data
            $DBFWRules = New-Object -TypeName PSCustomObject
            $DBFWRules | Add-Member -type NoteProperty -name Section -value $Section
            $DBFWRules | Add-Member -type NoteProperty -name Data -value $AllFWRules
            #Add data to object
            if($DBFWRules){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_sql_database_firewall -value $DBFWRules
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "SQL Database Firewall Rule", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }