#Azure get all managed disks in subscription
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
        $URI = ("{0}{1}/providers/Microsoft.Compute/disks?api-Version={2}" `
                -f $Instance.ResourceManager,$AzureObject.Subscription.id,'2018-06-01')
        $managed_disks = Get-AzSecRMObject -OwnQuery $URI -Manual -Authentication $RMAuth `
                                           -Verbosity $Verbosity -WriteLog $WriteLog
        $all_managed_disks = @();
        foreach($managed_disk in $managed_disks){
            $new_disk = New-Object -TypeName PSCustomObject
            $new_disk | Add-Member -type NoteProperty -name id -value $managed_disk.id
            $new_disk | Add-Member -type NoteProperty -name name -value $managed_disk.name
            $new_disk | Add-Member -type NoteProperty -name location -value $managed_disk.location
            $new_disk | Add-Member -type NoteProperty -name skuname -value $managed_disk.sku.name
            $new_disk | Add-Member -type NoteProperty -name skutier -value $managed_disk.sku.tier
            $new_disk | Add-Member -type NoteProperty -name ostype -value $managed_disk.properties.osType
            $new_disk | Add-Member -type NoteProperty -name disksize -value $managed_disk.properties.diskSizeGB
            $new_disk | Add-Member -type NoteProperty -name timecreated -value $managed_disk.properties.timeCreated
            $new_disk | Add-Member -type NoteProperty -name provisioningState -value $managed_disk.properties.provisioningState
            $new_disk | Add-Member -type NoteProperty -name diskState -value $managed_disk.properties.diskState
            #Get Encryption status
            if($managed_disk.properties.encryptionSettings.enabled){
                $new_disk | Add-Member -type NoteProperty -name encryptionsettingsenabled -value "Enabled"
            }
            else{
                $new_disk | Add-Member -type NoteProperty -name encryptionsettingsenabled -value "DisabledFromKeyVault"
            }
            $all_disks+=$new_disk
        }
    }
    End{
        if($all_disks){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$all_disks
            $all_disks.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.managed_disks')
            #Create custom object for store data
            $subscription_managed_disks = New-Object -TypeName PSCustomObject
            $subscription_managed_disks | Add-Member -type NoteProperty -name Section -value $Section
            $subscription_managed_disks | Add-Member -type NoteProperty -name Data -value $all_disks
            #Add data to object
            if($subscription_managed_disks){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_subscription_managed_disks -value $subscription_managed_disks
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure managed disks", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }