Function Resolve-Tenant{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]$Username,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]$Domain

        )
        Begin{
            $URI_Domain = $null;
            $URI_Username = $null;
            if($Domain -and -NOT $Username){
                Write-AzucarMessage -Message ("Trying to resolve TenantID by using {0} domain" -f $Domain) -Plugin Resolve-Tenant -IsHost -Color Yellow
                $URI_Domain = ("https://login.windows.net/{0}/.well-known/openid-configuration" -f $Domain)                
            }
            elseif($Username -and -NOT $Domain){
                Write-AzucarMessage -Message ("Trying to resolve TenantID by using {0} username" -f $Username) -Plugin Resolve-Tenant -IsHost -Color Yellow
                $URI_Username = ("https://login.microsoftonline.com/getuserrealm.srf?login={0}&json=1" -f $Username)
            }
        }
        Process{
            if($URI_Domain -ne $null){
                $domain_metadata = New-WebRequest -Url $URI_Domain -Method Get -Encoding "application/json" `
                                                  -UserAgent "Azucar"
                if($domain_metadata){
                    $empty = [system.guid]::Empty
                    $fake_user = ("{0}@{1}" -f $empty, $Domain)
                    $URI_Fake_User = ("https://login.microsoftonline.com/getuserrealm.srf?login={0}&json=1" -f $fake_user)
                    $fake_metadata = New-WebRequest -Url $URI_Fake_User -Method Get -Encoding "application/json" `
                                                    -UserAgent "Azucar"
                    
                    #Generate object
                    $az_domain_metadata = @{
                        domainName = $fake_metadata.DomainName;
                        NameSpaceType = $fake_metadata.NameSpaceType;
                        FederationBrandName = $fake_metadata.FederationBrandName;
                        CloudInstanceName = $fake_metadata.CloudInstanceName;
                        TenantID = $domain_metadata.token_endpoint.Split(‘/’)[3]
                    }
                }
            }
            if($URI_Username -ne $null){
                $user_metadata = New-WebRequest -Url $URI_Username -Method Get -Encoding "application/json" `
                                                -UserAgent "Azucar"
                if ($user_metadata.DomainName){
                    $URI_tmp_domain = ("https://login.windows.net/{0}/.well-known/openid-configuration" -f $user_metadata.DomainName) 
                    $domain_metadata = New-WebRequest -Url $URI_tmp_domain -Method Get -Encoding "application/json" `
                                                      -UserAgent "Azucar"
                }
                #Generate object
                if($domain_metadata -AND $user_metadata){                    
                    $az_domain_metadata = @{
                        domainName = $user_metadata.DomainName;
                        NameSpaceType = $user_metadata.NameSpaceType;
                        FederationBrandName = $user_metadata.FederationBrandName;
                        CloudInstanceName = $user_metadata.CloudInstanceName;
                        TenantID = $domain_metadata.token_endpoint.Split(‘/’)[3]
                    }
                }
            }
            
        }
        End{
            if($az_domain_metadata){
                #return object
                [pscustomobject]$az_domain_metadata
            }
            else{
                Write-AzucarMessage -Message ("Unable to resolve TenantID") -Plugin Resolve-Tenant -IsHost -Color Yellow
            }
        }
}

Function Get-AzUserPermissions{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$RoleObjectId, #= "acdd72a7-3385-48ef-bd42-f606fba81ae7",

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Switch]$CurrentUser

        )
    Begin{
        $url = $null
        $AllRBACUsers = @()
        $UserObjectId= $null
        if($CurrentUser -AND $Global:AzureConnections -AND $AzureConnections.ActiveDirectory.UserInfo.UniqueId){
            Write-AzucarMessage -Message ($message.AzUserPermissions -f $AzureConnections.ActiveDirectory.UserInfo.DisplayableId) -Plugin "Get-AzUserPermissions" `
                                -IsDebug -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
            $UserObjectId = @($AzureConnections.ActiveDirectory.UserInfo.UniqueId)
        }
        if($Global:AzureConnections -AND $Global:Subscription){
            if($RoleObjectId){
                Write-AzucarMessage -Message ($message.AzRoleBasedPermissions -f $RoleObjectId) -Plugin "Get-AzUserPermissions" `
                                    -IsDebug -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                $url = ("https://management.azure.com/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments?$filter=principalId%20eq%20'{1}'&api-version=2018-01-01-preview" -f $AzureConnections.ResourceManager.SubscriptionId, $RoleObjectId)  
            }
            else{
                $url = ("https://management.azure.com/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments?&api-version=2018-01-01-preview" -f $AzureConnections.ResourceManager.SubscriptionId)                  
            }
        }
    }
    Process{
        if($url){
            $AuthHeader = ("Bearer {0}" -f $AzureConnections.ResourceManager.AccessToken)
                $requestHeader = @{"x-ms-version" = "2014-10-01";"Authorization" = $AuthHeader}
                $AllObjects = New-WebRequest -Url $url -Headers $requestHeader -Method Get -Encoding "application/json" `
                                             -UserAgent "Azucar" -Verbosity $Global:Verbosity -WriteLog $Global:WriteLog
                $UserObjects = $AllObjects.value | Where-Object {($_.properties.principalType -EQ "user" -AND $_.properties.scope -EQ ("/subscriptions/{0}" -f $Subscription.subscriptionId))}
            if(-NOT $UserObjectId){
                $UserObjectId = $UserObjects.properties | Select-Object -ExpandProperty PrincipalId
            }

            $Body = @{
                        "objectIds" = $UserObjectId;
                        "includeDirectoryObjectReferences" = "true"
            }
            $JsonData = $Body | ConvertTo-Json
            #Get Azure AD data
            $ADAuthHeader = ("Bearer {0}" -f $AzureConnections.ActiveDirectory.AccessToken)
            $requestHeader = @{"x-ms-version" = "2014-10-01";"Authorization" = $ADAuthHeader}
            $url = ("https://graph.windows.net/{0}/getObjectsByObjectIds?api-version=1.6" -f $Subscription.TenantID)
            $RAObjects = New-WebRequest -Url $url -Headers $requestHeader -Method Post -Data $JsonData `
                                        -Encoding "application/json" -UserAgent "Azucar" `
                                        -Verbosity $Global:Verbosity -WriteLog $Global:WriteLog
            #Get RoleDefinitions
            $URI = ('https://management.azure.com/{0}/providers/Microsoft.Authorization/roleDefinitions?$filter=atScopeAndBelow()&api-version=2015-07-01' -f $Subscription.id)
            $AuthHeader = ("Bearer {0}" -f $AzureConnections.ResourceManager.AccessToken)
            $requestHeader = @{"x-ms-version" = "2014-10-01";"Authorization" = $AuthHeader}
            $RoleAssignmentsInScope = New-WebRequest -Url $URI -Headers $requestHeader -Method Get `
                                                     -Encoding "application/json" `
                                                     -UserAgent "Azucar" -Verbosity $Global:Verbosity `
                                                     -WriteLog $Global:WriteLog

            foreach ($obj in $RAObjects.value){
                $match = $UserObjects.properties | Where-Object {$_.principalId -eq $obj.objectId}
                if($match){
                    #Try to get the RoleDefinitionName
                    $RoleID = $match.roleDefinitionId.split('/')[6]
                    $RoleProperties = $RoleAssignmentsInScope.value | Where-Object {$_.name -eq $RoleID}
                    $obj | Add-Member -type NoteProperty -name scope -value $match.scope
                    $obj | Add-Member -type NoteProperty -name roleName -value $RoleProperties.properties.roleName
                    $obj | Add-Member -type NoteProperty -name roleDescription -value $RoleProperties.properties.description
                    $obj | Add-Member -type NoteProperty -name createdOn -value $match.createdOn
                    $obj | Add-Member -type NoteProperty -name updatedOn -value $match.updatedOn
                    $obj | Add-Member -type NoteProperty -name createdBy -value $match.createdBy
                    $obj | Add-Member -type NoteProperty -name updatedBy -value $match.updatedBy
                    $AllRBACUsers += $obj
                }
            }
        }
    }
    End{
        return $AllRBACUsers
    }
}

Function Load-AzADAL{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Path

        )
    $ADAuthLibrary = ("{0}\{1}" -f $Path, "core\libs\Microsoft.IdentityModel.Clients.ActiveDirectory.dll")
    try{
        #Load Libraries
        $null = [System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes($ADAuthLibrary)) #[System.Reflection.Assembly]::LoadFrom($ADAuthLibrary)
    }
    catch{
        #unable to load ADAL Library
        Write-Warning -Message ("Unable to load ADAL library in {0}" -f $ADAuthLibrary)
    }
}

#Write .NET HTTP Request exception to a friendly message
Function Get-AzWebRequestException{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$ExceptionError,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [Bool] $WriteLog,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [String] $FunctionName,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [System.Collections.Hashtable]$Verbosity
    )
    Begin{
        #Get Exception Body
        $reader = [System.IO.StreamReader]::new($ExceptionError.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
    }
    Process{
        if($responseBody -AND $WriteLog -AND $Verbosity){
            Write-AzucarMessage -Message $responseBody -Plugin $FunctionName -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
        }
        else{
            Write-Warning -Message $responseBody 
        }
    }
    End{
        #Nothing to do here
    }
}

#Convert exception to a friendly message
#Notes for write http://9to5it.com/powershell-logging-function-library/
Function Convert-Exception{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$MyError,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$FunctionName,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [Bool] $WriteLog

        )

    Begin{
        #Convert error and save in PsObject
        $ErrorHandling = New-Object -TypeName PSCustomObject
        $ErrorHandling | Add-Member -type NoteProperty -name Message -value $MyError.Exception.Message
        $ErrorHandling | Add-Member -type NoteProperty -name FunctionName -value $FunctionName
        $ErrorHandling | Add-Member -type NoteProperty -name LineNumber -value $MyInvocation.ScriptLineNumber
    }
    Process{
        if($WriteLog){
            Write-Log ("[Exception][{0}][{1}]:{2}" -f $ErrorHandling.FunctionName,$ErrorHandling.LineNumber, $ErrorHandling.Message)
        }
        Write-Host ("[Exception][{0}][{1}]:{2}" -f $ErrorHandling.FunctionName,$ErrorHandling.LineNumber, $ErrorHandling.Message)`
                    -ForegroundColor Red
    }
    End{
        #Nothing to do here
    }

}

function Write-AzucarMessage {
    [CmdletBinding(DefaultParameterSetName = 'Verbose')]
    param (
        ## Message to send to the Verbose stream
        [Parameter(ValueFromPipeline, ParameterSetName = 'Verbose')]
        [Parameter(ValueFromPipeline, ParameterSetName = 'Warning')]
        [Parameter(ValueFromPipeline, ParameterSetName = 'Debug')]
        [Parameter(ValueFromPipeline, ParameterSetName = 'Host')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Message,

        ## Azucar Plugin name
        [Parameter(ValueFromPipelineByPropertyName)]
        [System.String] $Plugin,

        ## Redirect message to the Warning stream
        [Parameter(ParameterSetName = 'Warning')]
        [System.Management.Automation.SwitchParameter] $IsWarning,

        ## Redirect message to the Debug stream
        [Parameter(ParameterSetName = 'Debug')]
        [System.Management.Automation.SwitchParameter] $IsDebug,

        ## Redirect message to the Verbose stream
        [Parameter(ParameterSetName = 'Verbose')]
        [System.Management.Automation.SwitchParameter] $IsVerbose,

        ## Redirect message to the Host stream
        [Parameter(ParameterSetName = 'Host')]
        [System.Management.Automation.SwitchParameter] $IsHost,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [Bool] $WriteLog,

        ## Color
        [Parameter(ValueFromPipelineByPropertyName)]
        [System.String] $Color = "Magenta",

        ## Verbosity
        [Parameter(Mandatory=$false, HelpMessage="VerbosityOptions")]
        [System.Collections.Hashtable]$Verbosity = @{Verbose=$false}
    )
    process {

        if ([System.String]::IsNullOrEmpty($Plugin)) {
            $Plugin = 'UnkNown';
        }        
        $date = Get-Date;
        $formattedMessage = '[{0}] [{1}] - {2}' -f $date.ToString('HH:mm:ss:fff'), $Plugin, $Message;
        #Write to log file
        if($WriteLog){
            Write-Log -Message $formattedMessage
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Warning' { Write-Warning -Message $formattedMessage; }
            'Debug' {if ($Verbosity.Debug -eq $true){$DebugPreference = 'Continue'; Write-Debug -Message $formattedMessage;}}
            'Verbose' { Write-Verbose -Message $formattedMessage @Verbosity }
            'Host' { Write-Host $formattedMessage -ForegroundColor $Color }
            Default { Write-Host $formattedMessage -ForegroundColor $Color }
        }

    } #end process
} #end function WriteLog

#Create LOG folder
Function Create-LOGFolder{
    [cmdletbinding()]
    Param (
        [parameter()]
        [string]$RootPath

    )
    Begin{
        $target = ("{0}\LOG" -f $RootPath)
    }
    Process{
        if (!(Test-Path -Path $target)){
            $tmpdir = New-Item -ItemType Directory -Path $target
            Write-AzucarMessage -Message ($message.FolderCreatedMessage -f $target) -Color Magenta -Plugin Create-LOGFolder -WriteLog $Global:WriteLog
            return $target
        }
        else{
            Write-AzucarMessage -Message ($message.DirectoryAlreadyExistsMessage -f $target) -Plugin Create-LOGFolder -IsWarning -WriteLog $Global:WriteLog
            return $target
        }
    }
    End{
    }      
}
##End of function
#Start LOG file
Function Start-Logging{
    Begin{
        #Check if file exists
        $FullPath = $Global:LogPath+"\azurereview.log"
        if((Test-Path -Path $FullPath)){ 
            Remove-Item -Path $FullPath -Force -ErrorAction SilentlyContinue
        } 
    }
    Process{
        #Create file and start logging
        $null = New-Item -Path $FullPath -ItemType File -Force
        #Add start content
        Add-Content -Path $FullPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullPath -Value "Started processing at [$([DateTime]::Now)]." 
        Add-Content -Path $FullPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullPath -Value "" 
        Add-Content -Path $FullPath -Value "Running script Name [$($MyInvocation.ScriptName)]." 
        Add-Content -Path $FullPath -Value "" 
        Add-Content -Path $FullPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullPath -Value "" 

    }
    End{
        #Nothing to do here
    }
}
##End of function
#Write info into LOG file
Function Write-Log{
    [cmdletbinding()]
    Param (
        [parameter()]
        [string]$Message

    )
    Begin{
        #Map var to log file content   
        $FullLogPath = ("{0}\azurereview.log" -f $Global:LogPath)
    }
    Process{
        #Test if file exists
        if((Test-Path -Path $FullLogPath)){
            #Add content into log file
            #Add-Content -Path $FullLogPath -Value $Message
            try{
                [System.IO.File]::AppendAllText($FullLogPath,$Message+([Environment]::NewLine))
            }
            catch [System.IO.IOException]{
                Write-Host $_.Exception.Message -ForegroundColor Yellow
            }
            catch{
                Write-Host $_.Exception -ForegroundColor Yellow
            }
        }
    }
    End{
        #Nothing to do here
    }
}
##End of function
#Close LOG file
Function Stop-Logging{
    Begin{
        #Map var to log file content
        $FullLogPath = ("{0}\azurereview.log" -f $Global:LogPath)
    }
    Process{
        #Check that file exists
        if((Test-Path -Path $FullLogPath)){
            #Add start content
        Add-Content -Path $FullLogPath -Value ""
        Add-Content -Path $FullLogPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullLogPath -Value "Finished processing at  [$([DateTime]::Now)]." 
        Add-Content -Path $FullLogPath -Value "***************************************************************************************************" 
        }
    }
    End{
        #Nothing to do here
    }
}


#Azure Resources
$AzureResources = @{
    AzurePortal = '74658136-14ec-4630-ad9b-26e160ff0fc6';
    AzurePowerShell = '1950a258-227b-4e31-a9cf-717495945fc2';
    AADGraphAPI = "00000002-0000-0000-c000-000000000000";
    AzureGraph = '00000003-0000-0000-c000-000000000000';
    ServiceManagement = "797f4846-ba00-4fd7-ba43-dac1f8f63013";
    SecurityPortal = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c";
}

