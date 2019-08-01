#Plugin extract about Security alerts from Azure
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
        $AzureAlerts = $AzureObject.AzureConfig.Alerts
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Security Alerts", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Alerts
        $Alerts = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                           -Provider $AzureAlerts.Provider -Objectype "alerts" -APIVersion $AzureAlerts.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllAlerts = @()
        foreach($Alert in $Alerts){
            $Properties = $Alert.properties | Select @{Name='AlertName';Expression={$Alert.name}},`
                          vendorName, alertDisplayName, detectedTimeUtc, actionTaken,`
                          reportedSeverity, compromisedEntity, reportedTimeUtc, @{Name='ThreatName';Expression={$Alert.properties.extendedProperties.name}},`
                          @{Name='Path';Expression={$Alert.properties.extendedProperties.path}},@{Name='Category';Expression={$Alert.properties.extendedProperties.category}}
            $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityAlerts')
            $AllAlerts+=$Properties               
        }
    }
    End{
        if($AllAlerts){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllAlerts
            $AllAlerts.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityAlerts')
            #Create custom object for store data
            $MyAlerts = New-Object -TypeName PSCustomObject
            $MyAlerts | Add-Member -type NoteProperty -name Section -value $Section
            $MyAlerts | Add-Member -type NoteProperty -name Data -value $AllAlerts
            #Add data to object
            if($MyAlerts){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_security_alerts -value $MyAlerts
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Security Alerts", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }