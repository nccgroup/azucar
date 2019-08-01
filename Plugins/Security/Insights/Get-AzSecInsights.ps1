#Azure get Insights for every single resource group
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
        #Get pluginname and section
        $PluginName = $AzureObject.PluginName
        $Section = $AzureObject.AzureSection

    }
    Process{
        
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Azure Insights", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $URI = ("{0}{1}/providers/microsoft.insights/activityLogAlerts?api-Version={2}" `
                -f $Instance.ResourceManager,$AzureObject.Subscription.id,'2017-04-01')
        $configured_alerts = Get-AzSecRMObject -OwnQuery $URI -Manual -Authentication $RMAuth `
                                               -Verbosity $Verbosity -WriteLog $WriteLog
        $all_alerts = @();
        foreach($configured_alert in $configured_alerts){
            #Try to get operationName
            $operation_name = $configured_alert.properties.condition.allOf | Where-Object {$_.field -eq 'operationName'} | Select-Object -ExpandProperty equals
            #Get category
            $category_name = $configured_alert.properties.condition.allOf | Where-Object {$_.field -eq 'category'} | Select-Object -ExpandProperty equals
            $new_alert = New-Object -TypeName PSCustomObject
            $new_alert | Add-Member -type NoteProperty -name id -value $configured_alert.id
            $new_alert | Add-Member -type NoteProperty -name name -value $configured_alert.name
            $new_alert | Add-Member -type NoteProperty -name description -value $configured_alert.properties.description
            $new_alert | Add-Member -type NoteProperty -name location -value $configured_alert.location
            $new_alert | Add-Member -type NoteProperty -name scopes -value (@($configured_alert.properties.scopes) -join ',')
            $new_alert | Add-Member -type NoteProperty -name scopes -value (@($configured_alert.properties.scopes) -join ',')
            $new_alert | Add-Member -type NoteProperty -name operationName -value $operation_name
            $new_alert | Add-Member -type NoteProperty -name categoryName -value $category_name
            $new_alert | Add-Member -type NoteProperty -name enabled -value $configured_alert.properties.enabled
            $all_alerts+=$new_alert
        }
    }
    End{
        if($all_alerts){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$all_alerts
            $all_alerts.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.insights.alerts')
            #Create custom object for store data
            $monitor_alerts = New-Object -TypeName PSCustomObject
            $monitor_alerts | Add-Member -type NoteProperty -name Section -value $Section
            $monitor_alerts | Add-Member -type NoteProperty -name Data -value $all_alerts
            #Add data to object
            if($monitor_alerts){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_monitor_alerts -value $monitor_alerts
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure Insights", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }