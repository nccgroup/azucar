#This is a sample plugin for Azucar. It extracts basic information about virtual machines disks over an Azure Tenant
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
        $AzureVM = $AzureObject.AzureConfig.AzureVM
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Virtual Machines V2 Disk Information", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Disks within Azure Tenant
        $allVMDisks = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                      -Provider $AzureVM.Provider -Objectype "disks" -APIVersion "2017-03-30" -Verbosity $Verbosity -WriteLog $WriteLog

        #Create array
        $AllDisks = @()
        foreach ($disk in $allVMDisks){
            $Properties = $disk | Select @{Name='osType';Expression={$disk.properties.osType}},`
                                  @{Name='diskSizeGB';Expression={$disk.properties.diskSizeGB}},`
                                  @{Name='timeCreated';Expression={$disk.properties.timeCreated}},`
                                  @{Name='provisioningState';Expression={$disk.properties.provisioningState}},`
                                  @{Name='diskState';Expression={$disk.properties.diskState}},`
                                  @{Name='location';Expression={$disk.location}},`
                                  @{Name='diskName';Expression={$disk.name}} 
                                   
                   
            #Decorate object
            $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.Disks')
            $AllDisks+=$Properties               
        }
    }
    End{
        if($AllDisks){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllDisks
            $AllDisks.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AllVM2Disks')
            #Create custom object for store data
            $MyDisks = New-Object -TypeName PSCustomObject
            $MyDisks | Add-Member -type NoteProperty -name Section -value $Section
            $MyDisks | Add-Member -type NoteProperty -name Data -value $AllDisks
            #Add data to object
            if($MyDisks){
                $ReturnPluginObject | Add-Member -type NoteProperty -name VirtualDisks -value $MyDisks
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Virtual Machine V2 Disk Information", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }