#Plugin extract users from AD
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

            [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	        [Bool] $WriteLog

        )
    Begin{
        #Import Azure API
        $LocalPath = $AzureObject.LocalPath
        $Utils = $AzureObject.Utils
        . $API
        . $Utils

        #Import Localized data
        $LocalizedDataParams = $AzureObject.LocalizedDataParams
        Import-LocalizedData @LocalizedDataParams;
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AADConfig = $AzureObject.AzureConfig.AzureActiveDirectory
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADUsersTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Active Directory Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        #Get users
        $AllUsers = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth -Objectype "users" `
                                       -APIVersion $AADConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
    }
    End{
        if ($AllUsers){
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADUserSearchReturn -f $AllUsers.Count) `
                                -Plugin $PluginName -Verbosity $Verbosity
            #$AllUsers| Select-Object $AADConfig.UsersFilter | ogv
            $TmpUsers = $AllUsers| Select-Object $AADConfig.UsersFilter
            $TmpUsers.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.Users')
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllUsers
            #Create custom object for store data
            $AllDomainUsers = New-Object -TypeName PSCustomObject
            $AllDomainUsers | Add-Member -type NoteProperty -name Section -value $Section
            $AllDomainUsers | Add-Member -type NoteProperty -name Data -value $TmpUsers
            #Add Users data to object
            if($TmpUsers){
                $ReturnPluginObject | Add-Member -type NoteProperty -name DomainUsers -value $AllDomainUsers
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADUsersQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }