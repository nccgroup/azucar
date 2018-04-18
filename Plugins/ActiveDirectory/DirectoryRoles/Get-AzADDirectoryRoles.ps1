#Plugin extract Directoryroles from Azure AD
#https://docs.microsoft.com/en-us/azure/active-directory/active-directory-assign-admin-roles
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
        $AADConfig = $AzureObject.AzureConfig.AzureActiveDirectory
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADDirectoryRoleTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Active Directory Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        #Get Directory Roles
        $AllDirectoryRoles = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth `
                                                -Objectype "directoryRoles" -APIVersion $AADConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        $TmpDirectoryRoles = @()
        $DirectoryRolesUsers = @()
        if ($AllDirectoryRoles){
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADDirectorySearchReturn -f $AllDirectoryRoles.Count) `
                                -Plugin $PluginName -Verbosity $Verbosity
            foreach ($dr in $AllDirectoryRoles){
                $UsersCount = Get-AzSecAADLinkedObject -Instance $Instance `
                            -Authentication $AADAuth -Objectype "directoryRoles" `
                            -ObjectId $dr.objectId -Relationship "members" `
                            -ObjectDisplayName $dr.displayName `
                            -APIVersion $AADConfig.APIVersion `
                            -GetLinks -Verbosity $Verbosity -WriteLog $WriteLog

                if($UsersCount.url){
                    $dr | Add-Member -type NoteProperty -name Members -Value $UsersCount.Count
                }
                else{
                    $dr | Add-Member -type NoteProperty -name Members -Value 0
                }
                $dr = $dr| Select-Object $AADConfig.DirectoryRolesFilter
                $TmpDirectoryRoles+=$dr
                #Retrieve users from Directory roles
                $Users = Get-AzSecAADLinkedObject -Instance $Instance `
                         -Authentication $AADAuth -Objectype "directoryRoles" `
                         -ObjectId $dr.objectId -Relationship "members" `
                         -ObjectDisplayName $dr.displayName `
                         -APIVersion $AADConfig.APIVersion `
                         -Verbosity $Verbosity -WriteLog $WriteLog
                #Add to Array
                $Users |%{$_ | Add-Member -type NoteProperty -name MemberOf -Value $dr.displayName}
                $Users = $Users| Select-Object $AADConfig.DirectoryRolesMembersFilter
                $DirectoryRolesUsers+=$Users
            }
        }
    }
    End{
        if($TmpDirectoryRoles){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$TmpDirectoryRoles
            $TmpDirectoryRoles.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.DirectoryRoles')
            #Create custom object for store data
            $AllDomainDirectoryRoles = New-Object -TypeName PSCustomObject
            $AllDomainDirectoryRoles | Add-Member -type NoteProperty -name Section -value $Section
            $AllDomainDirectoryRoles | Add-Member -type NoteProperty -name Data -value $TmpDirectoryRoles
            #Add Directoryroles data to object
            if($TmpDirectoryRoles){
                $ReturnPluginObject | Add-Member -type NoteProperty -name DirectoryRoles -value $AllDomainDirectoryRoles
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADRoleQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
        if($DirectoryRolesUsers){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$DirectoryRolesUsers
            $DirectoryRolesUsers.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.DirectoryRolesMembers')
            #Create custom object for store data
            $AllDomainDirectoryRolesMembers = New-Object -TypeName PSCustomObject
            $AllDomainDirectoryRolesMembers | Add-Member -type NoteProperty -name Section -value $Section
            $AllDomainDirectoryRolesMembers | Add-Member -type NoteProperty -name Data -value $DirectoryRolesUsers
            #Add Directoryroles data to object
            if($TmpDirectoryRoles){
                $ReturnPluginObject | Add-Member -type NoteProperty -name DirectoryRolesMembers -value $AllDomainDirectoryRolesMembers
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADRoleMemberQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }