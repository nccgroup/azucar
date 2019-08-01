#Plugin to extract Role assignments from Azure
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

        #Get Group Members
        Function Get-AzureGroupMembers{
            Param (
            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [Object]$Group,

            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [Object]$Role
            )
            #Get group members
            $GroupMembers = Get-AzSecAADLinkedObject -Instance $Instance `
                            -Authentication $AADAuth -Objectype "groups" `
                            -ObjectId $Group.objectId -Relationship "members" `
                            -ObjectDisplayName $Group.displayName `
                            -APIVersion "1.6" -Verbosity $Verbosity -WriteLog $WriteLog
                            
            $Allusers = @()
            foreach($member in $GroupMembers){
                if($member.objectType -eq "User"){
                  $user = $member | Select objectType, objectId, accountEnabled, @{Name='signInNames';Expression={@($_.signInNames) -join ','}}, @{Name='MemberOf';Expression={$Group.displayName}}, @{Name='RoleName';Expression={$Role.properties.roleName}}, @{Name='RoleDescription';Expression={$Role.properties.description}}, description, displayName, mailNickname, mailEnabled, securityEnabled
                  $Allusers+= $user
                }
                elseif($member.objectType -eq "Group"){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Found a group name {0} inside of {1}" -f $member.displayName, $Group.displayName) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                    Get-AzureGroupMembers -Group $member -Role $Role
                }
            }
            if($Allusers){
                return $Allusers
            }
        }
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AzureAuthConfig = $AzureObject.AzureConfig.Authorization
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Role Based Access Control", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #Retrieve Azure Graph Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        #Get Classic Administrators
        $ClassicAdministrators = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                                   -Provider $AzureAuthConfig.Provider -Objectype "classicAdministrators" `
                                                   -APIVersion $AzureAuthConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllClassicAdmins = @()
        foreach($Admin in $ClassicAdministrators){
            $role = $Admin.properties.role.split(";")
            foreach ($r in $role){
                #Create custom object for store data
                $ClassicAdmin = New-Object -TypeName PSCustomObject
                $ClassicAdmin | Add-Member -type NoteProperty -name emailaddress -value $Admin.properties.emailAddress
                $ClassicAdmin | Add-Member -type NoteProperty -name role -value $r
                #Decorate object and add to list
                $ClassicAdmin.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.ClassicAdministrators')                               
                $AllClassicAdmins+= $ClassicAdmin 
            }       
        }
        #Get RoleAssignments. Portal Ibiza only
        $RoleAssignments = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                             -Provider $AzureAuthConfig.Provider -Objectype "roleAssignments" `
                                             -APIVersion "2015-07-01" -Verbosity $Verbosity -WriteLog $WriteLog

        $AllRoleAssignmentsID = $RoleAssignments.properties | Select-Object -ExpandProperty principalId
        $Body = @{
                            "objectIds" = $AllRoleAssignmentsID;
                            "includeDirectoryObjectReferences" = "true"
        }

        $JsonData = $Body | ConvertTo-Json

        #POST Request
        $AllRoleAssignment = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth `
                                                -Objectype "getObjectsByObjectIds" -APIVersion "1.6-internal" -Method "POST" `
                                                -Data $JsonData -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Write-Verbose $JsonData @Verbosity
        #Get RoleAssignments at the specified scope and any of its child scopes. Portal Ibiza only
        #https://docs.microsoft.com/en-us/azure/active-directory/role-based-access-control-manage-access-rest
        $URI = ('{0}subscriptions/{1}/providers/Microsoft.Authorization/roleDefinitions?$filter=atScopeAndBelow()&api-version=2015-07-01' -f $Instance.ResourceManager, $RMAuth.subscriptionId)
        $RoleAssignmentsInScope = Get-AzSecRMObject -OwnQuery $URI -Manual -Authentication $RMAuth -Verbosity $Verbosity

        $RAObject = $AllRoleAssignment | Select objectType, objectId, accountEnabled, @{Name='signInNames';Expression={@($_.signInNames) -join ','}}, description, displayName, mailNickname, mailEnabled, securityEnabled
        $AllRBACUsers = @()
        foreach ($obj in $RAObject){
            $match = $RoleAssignments.properties | Where-Object {$_.principalId -eq $obj.objectId}
            if (($match -AND $obj.objectType -eq "User")){
                #Try to get the RoleDefinitionName
                $RoleID = $match.roleDefinitionId.split('/')[6]
                $RoleProperties = $RoleAssignmentsInScope | Where-Object {$_.name -eq $RoleID}
                #Add members to Object
                $obj | Add-Member -type NoteProperty -name scope -value $match.scope
                $obj | Add-Member -type NoteProperty -name roleName -value $RoleProperties.properties.roleName
                $obj | Add-Member -type NoteProperty -name roleDescription -value $RoleProperties.properties.description
                $obj | Add-Member -type NoteProperty -name createdOn -value $match.createdOn
                $obj | Add-Member -type NoteProperty -name updatedOn -value $match.updatedOn
                $obj | Add-Member -type NoteProperty -name createdBy -value $match.createdBy
                $obj | Add-Member -type NoteProperty -name updatedBy -value $match.updatedBy
                #Add to Object
                $AllRBACUsers+=$obj
            }
            elseif(($match -AND $obj.objectType -eq "Group")){
                #Try to get the RoleDefinitionName
                $RoleID = $match.roleDefinitionId.split('/')[6]
                $RoleProperties = $RoleAssignmentsInScope | Where-Object {$_.name -eq $RoleID}
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Found a group name {0} with a role of {1}" -f $obj.displayName, $RoleProperties.properties.roleName) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                $Members = Get-AzureGroupMembers -Group $obj -Role $RoleProperties
                $AllRBACUsers+=$Members
            }
        }
        #Write-Verbose ("Found {0} effective users" -f $AllRBACUsers.Count) -Verbose       
    }
    End{
        if($AllRBACUsers -or $AllClassicAdmins){
            if ($AllRBACUsers){
                #Work with SyncHash
                $SyncServer.$($PluginName)=$AllRBACUsers
                $AllRBACUsers.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AllRBACUsers')
                #Create custom object for store data
                $RBACUsers = New-Object -TypeName PSCustomObject
                $RBACUsers | Add-Member -type NoteProperty -name Section -value $Section
                $RBACUsers | Add-Member -type NoteProperty -name Data -value $AllRBACUsers
                #Add data to object
                if($RBACUsers){
                    $ReturnPluginObject | Add-Member -type NoteProperty -name azure_rbac_users -value $RBACUsers
                }
            }
            else{
                Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Role Based Access Control", $AzureObject.TenantID) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsWarning
            }
            if ($AllClassicAdmins){
                #Work with SyncHash
                $SyncServer.$($PluginName)=$AllClassicAdmins
                $AllClassicAdmins.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AllClassicAdmins')
                #Create custom object for store data
                $ClassicAdmins = New-Object -TypeName PSCustomObject
                $ClassicAdmins | Add-Member -type NoteProperty -name Section -value $Section
                $ClassicAdmins | Add-Member -type NoteProperty -name Data -value $AllClassicAdmins
                #Add data to object
                if($ClassicAdmins){
                    $ReturnPluginObject | Add-Member -type NoteProperty -name azure_classic_admins -value $ClassicAdmins
                }
            }
            else{
                Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Role Based Access Control", $AzureObject.TenantID) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsWarning
            }
        }
    }