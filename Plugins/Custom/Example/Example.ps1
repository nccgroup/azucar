#Sample skeleton PowerShell plugin code
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

        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $AzureVMConfig = $AzureObject.AzureConfig.AzureVM
        $AllVMs = @()
        <#
        #List All Virtual Machines
        $VMs = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                 -Provider $AzureVMConfig.Provider -Objectype "virtualmachines" `
                                 -APIVersion $AzureVMConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        $myid =  $VMs.resources | Where-Object {$_.id -like '*2K8Test1/extensions/MicrosoftMonitoringAgent'} | Select-Object -ExpandProperty id
        $URI = ("{0}{1}?api-version={2}" -f $Instance.ResourceManager, $myid, "2018-06-01")
        $extension = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth -Verbosity $Verbosity -Method "GET" -WriteLog $WriteLog
        Write-Host $extension.properties.settings
        #>
    }
    Process{
        #Do things here
		$ReturnValue = [PSCustomObject]@{Name='myCustomType';Expression={"NCCGroup Labs"}}
		
    }
    End{
        if($ReturnValue){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$ReturnValue
            $ReturnValue.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.myDecoratedObject')
            #Create custom object for store data
            $MyVar = New-Object -TypeName PSCustomObject
            $MyVar | Add-Member -type NoteProperty -name Section -value $Section
            $MyVar | Add-Member -type NoteProperty -name Data -value $ReturnValue
            #Add data to object
            if($MyVar){
                $ReturnPluginObject | Add-Member -type NoteProperty -name Example -value $MyVar
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "My Super Plugin", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }