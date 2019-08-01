#Azure WebApp
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

        $Section = $AzureObject.AzureSection
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AzureWebApps = $AzureObject.AzureConfig.AzureWebApps
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Azure Web Apps", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All WebApps within Azure Tenant
        $allWebApps = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                      -Provider $AzureWebApps.Provider -Objectype "sites" -APIVersion $AzureWebApps.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog

	    #Create array
        $AllMyWebApps = @()
        foreach ($app in $allWebApps){
            if ($app.id){
                $Properties = $app | Select @{Name='id';Expression={$app.id}},`
                                      @{Name='name';Expression={$app.name}},`
                                      @{Name='kind';Expression={$app.kind}},`
                                      @{Name='location';Expression={$app.location}},`
                                      @{Name='state';Expression={$app.properties.state}},`
                                      @{Name='enabled';Expression={$app.properties.enabled}},`
                                      @{Name='adminEnabled';Expression={$app.properties.adminEnabled}},`
                                      @{Name='availabilityState';Expression={$app.properties.availabilityState}},`
                                      @{Name='computeMode';Expression={$app.properties.computeMode}},`
                                      @{Name='clientAffinityEnabled';Expression={$app.properties.clientAffinityEnabled}},`
                                      @{Name='clientCertEnabled';Expression={$app.properties.clientCertEnabled}},`
                                      @{Name='hostNamesDisabled';Expression={$app.properties.hostNamesDisabled}},`
                                      @{Name='resourceGroup';Expression={$app.properties.resourceGroup}},`
                                      @{Name='defaultHostName';Expression={$app.properties.defaultHostName}},`
                                      @{Name='httpsOnly';Expression={$app.properties.httpsOnly}}
                #Retrieve Web app config
                $URI = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $app.id, "config","2016-08-01")
                $appConfiguration = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth `
                                    -Verbosity $Verbosity -Method "GET" -WriteLog $WriteLog
                #TODO ADD IP_RESTRICTIONS
                #$appConfiguration.properties.ipSecurityRestrictions -ForegroundColor Yellow
                $Properties | Add-Member -type NoteProperty -name ftpsState -value $appConfiguration.properties.ftpsState
                $Properties | Add-Member -type NoteProperty -name remoteDebuggingEnabled -value $appConfiguration.properties.remoteDebuggingEnabled
                $Properties | Add-Member -type NoteProperty -name httpLoggingEnabled -value $appConfiguration.properties.httpLoggingEnabled
                $Properties | Add-Member -type NoteProperty -name detailedErrorLoggingEnabled -value $appConfiguration.properties.detailedErrorLoggingEnabled
                $Properties | Add-Member -type NoteProperty -name http20Enabled -value $appConfiguration.properties.http20Enabled
                $Properties | Add-Member -type NoteProperty -name minTlsVersion -value $appConfiguration.properties.minTlsVersion
                $Properties | Add-Member -type NoteProperty -name siteAuthEnabled -value $appConfiguration.properties.siteAuthEnabled
            
                #Get Backup counts
                $URI = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $app.id, "backups","2016-08-01")
                $appBackup = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth `
                                    -Verbosity $Verbosity -Method "GET" -WriteLog $WriteLog
                #Add to object
                $Properties | Add-Member -type NoteProperty -name backupCount -value $appBackup.value.Count  
                #Get snapShot counts
                $URI = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $app.id, "config/web/snapshots","2016-08-01")
                $appSnapShots = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth `
                                    -Verbosity $Verbosity -Method "GET" -WriteLog $WriteLog
                #Add to object
                $Properties | Add-Member -type NoteProperty -name snapshotCount -value $appSnapShots.properties.Count  
                                    
                #Decorate object
                $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.WebApp')
                $AllMyWebApps+=$Properties
           }               	
       }
    }
    End{
        if($AllMyWebApps){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllMyWebApps
            $AllMyWebApps.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.WebApps')
            #Create custom object for store data
            $AzureWebApps = New-Object -TypeName PSCustomObject
            $AzureWebApps | Add-Member -type NoteProperty -name Section -value $Section
            $AzureWebApps | Add-Member -type NoteProperty -name Data -value $AllMyWebApps
            #Add data to object
            if($AzureWebApps){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_app_services -value $AzureWebApps
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure Web Apps", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }