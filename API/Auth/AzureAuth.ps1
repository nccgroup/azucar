#Azure API REST
#https://azure.microsoft.com/en-us/documentation/articles/resource-manager-rest-api/

#Clear cache
#https://social.msdn.microsoft.com/Forums/vstudio/en-US/76a38eee-3ef6-4993-a54d-3fecc4eb6cff/set-cookie-from-ie-hosted-windows-user-control?forum=csharpgeneral
Function Clear-AzAuth{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Switch]$ExitSession
    )
    Begin{
        $source=@"
                using System.Runtime.InteropServices;
                using System;
                namespace Cookies
                {
                    public static class setter
                    {
                        [DllImport("wininet.dll", CharSet = CharSet.Auto, SetLastError = true)]
                        private static extern bool InternetSetOption(int hinternet, int dwoption, string lpBuffer, int dwBufferLength);
                        public static bool DeleteSession(int hinternet, int dwoption, string lpBuffer, int dwBufferLength)
                        {
                            bool res = setter.InternetSetOption(hinternet, dwoption, lpBuffer, dwBufferLength);
                            if (!res)
                            {
                                throw new Exception("Exception setting cookie: Win32 Error code="+Marshal.GetLastWin32Error());
                            }else{
                                return res;
                            }
                        }
                    }
                }
"@
    }
    Process{
        $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
        $compilerParameters.CompilerOptions="/unsafe"
        #Add Type
        if (-not ([System.Management.Automation.PSTypeName]'Cookies.Setter').Type){
            Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $compilerParameters
        }
        #Get Date
        [DateTime]$dateTime = Get-Date
        $dateTime.AddDays(1)
        $str = $dateTime.ToString("R")
    }
    End{
        #Delete session
        # 0 means all internet handles in same process
        #42 call INTERNET_OPTION_END_BROWSER_SESSION - https://msdn.microsoft.com/en-us/library/aa385328(v=vs.85).aspx
        $null = [Cookies.setter]::DeleteSession(0,42,$null,0)

        #Catch Exit Session
        if($ExitSession){exit}
    }
    
}

#Get Subscription
Function Select-AzSecSubscription{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Authentication,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance
    )
    Begin{
        if($global:Subscription -eq $false){
            #Create Array for subscriptions
            $AllSubscriptions = @()
            foreach ($auth in $Authentication){
                $authHeader = $auth.CreateAuthorizationHeader()
                # Set HTTP request headers to include Authorization header | @marckean
                $requestHeader = @{
                            "x-ms-version" = "2014-10-01"; #'2014-10-01'
                            "Authorization" = $authHeader
                }
                #https://msdn.microsoft.com/en-us/library/azure/mt704050.aspx
                $uriSubscriptions = "{0}subscriptions?api-version=2016-06-01" -f $Instance.ResourceManager
                try{
                    $Response = New-WebRequest -Url $uriSubscriptions -Headers $requestHeader `
                                -Method Get -Encoding "application/json" -UserAgent "Azucar" `
                                -Verbosity $Global:VerboseOptions | select -ExpandProperty value

                    $Response | Add-Member -type NoteProperty -name TenantID -value $auth.TenantID -Force
                    $AllSubscriptions += $Response
                }
                catch{
                    Convert-Exception -MyError $_ -FunctionName "Select-AzSecSubscription" -WriteLog $Global:WriteLog
                    #exit
                }  
            }                  
        }
    }
    Process{
        if($AllSubscriptions){
            #Choose subscription and TenantID
            $MySubscription = $AllSubscriptions | Out-GridView -Title "Choose a Source Subscription ..." -PassThru  
            #Set Subscription var
            Set-Variable Subscription -Value $MySubscription -Scope Global -Force
            #Set TenantID var
            Set-Variable TenantID -Value $MySubscription.TenantID -Scope Global -Force
        }
        else{
            <#
            $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception("Unable to find a valid subscription with user $($Authentication.UserInfo.DisplayableId)....")),
                           $null,
                           [System.Management.Automation.ErrorCategory]::InvalidResult,
                           $null
                        )
             Convert-Exception -MyError $ErrorRecord -FunctionName "Select-AzSecSubscription" -WriteLog $Global:WriteLog
             exit
             #>
             #Nothing to do here           
        }
    }
    End{
        #Nothing to do here
    }
}

#Try to get authorization for Tenant
Function Authorize-Tenant{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$TenantID

     )
     Begin{
        # Client ID for Azure PowerShell
        $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
        # Set redirect URI for Azure PowerShell
        $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
        # Resource client ID for Azure PowerShell
        $resourceClientId = "00000002-0000-0000-c000-000000000000"
        $AuthResponses = @()
     }
     Process{
        try{
            foreach ($tenant in $TenantID){
                $AzureAuthority = "{0}/{1}" -f $Instance.Login, ("{0}/oauth2/authorize" -f $tenant)
                $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $AzureAuthority
                #Authenticate user against Azure Active Directory
                $AuthResult = $authContext.AcquireToken($Instance.ResourceManager, $clientId, $redirectUri,
                                            [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto)
                #Add Responses
                $AuthResponses += $AuthResult
            }
        }
        catch{
            Convert-Exception -MyError $_ -FunctionName "Get-AzureTenant" -WriteLog $Global:WriteLog
        }
     }
     End{
        if($AuthResponses){
            Select-AzSecSubscription -Authentication $AuthResponses -Instance $Instance
        }
     }
}

#Connect to Azure
Function ConnectTo-Azure{
     Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance,

        [Parameter(Mandatory=$false, HelpMessage="Force Authentication")]
        [Bool]
        $ForceAuth=$false

     )
    Begin{
        #Write-Host $Credential.Username
        #Load Libraries
        $ADAuthLibrary = ("{0}\{1}" -f $ScriptPath, "Libs\Microsoft.IdentityModel.Clients.ActiveDirectory.dll")
        $ADAuthForms = ("{0}\{1}" -f $ScriptPath, "Libs\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll") 
        $null = [System.Reflection.Assembly]::LoadFrom($ADAuthLibrary)
        $null = [System.Reflection.Assembly]::LoadFrom($ADAuthForms)
        # Client ID for Azure PowerShell
        $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
        # Set redirect URI for Azure PowerShell
        $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
        # Common Resource client ID for Azure PowerShell
        $resourceClientId = "00000002-0000-0000-c000-000000000000"
    }
    Process{
        $AzureAuthority = "{0}/{1}" -f $Instance.Login, "Common/oauth2/authorize"
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $AzureAuthority

        try{
            #Checking for Force Authentication
            if($ForceAuth){
                $AuthMethod = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
            }
            else{
                $AuthMethod = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
            }
            
            #Authenticate user against Azure Resource Manager
            $RMAuth = $authContext.AcquireToken($Instance.ResourceManager, $clientId, $redirectUri,$AuthMethod)
            #$RMAuth | fl
            $uri = ("{0}{1}?api-version={2}" -f $Instance.ResourceManager,"tenants", "2016-06-01")
            $Tenants = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth -OwnQuery $uri -Manual -Verbosity $Global:VerboseOptions
            $AllTenants = @()
            foreach ($tenant in $Tenants){
                $AllTenants += $tenant.tenantId
            }
            #Try to authorize subscription and tenantID
            Authorize-Tenant -TenantID $AllTenants
            <#
            #Try to authorize tenant
            foreach ($tenant in $AllTenants){
                Write-Verbose ("Check tenantID {0}" -f $tenant) @VerboseOptions
                Authorize-Tenant -TenantID $AllTenants
            } #>          
        }
        catch{
            Convert-Exception -MyError $_ -FunctionName "ConnectTo-Azure" -WriteLog $Global:WriteLog
        }
    }
    End{
        if($Global:TenantID -ne $false -and $Global:Subscription -ne $false){
            #Set TenantID
            $AzureAuthority = "{0}/{1}" -f $Instance.Login, ("{0}/oauth2/authorize" -f $Global:TenantID)
            $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $AzureAuthority
            #Authenticate user against Azure Active Directory
            try{
                Write-AzucarMessage -WriteLog $Global:WriteLog -Message ($message.LoginAzureTenantMesssage -f $Global:TenantID)`
                                    -Plugin ConnectTo-Azure -IsVerbose -Verbosity $Global:VerboseOptions
                $AADAuthResult = $authContext.AcquireToken($Instance.Graph, $clientId, $redirectUri,
                                                    [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto)
                #Add subscriptionid to object
                $AADAuthResult | Add-Member -type NoteProperty -name SubscriptionId -value $Global:Subscription.subscriptionId -Force
            }
            catch{
                 Convert-Exception -MyError $_ -FunctionName "ConnectTo-Azure" -WriteLog $Global:WriteLog
            }
            #Authenticate user to Azure Resource Manager
            try{
                Write-AzucarMessage -Message ($message.LoginAzureRMMesssage -f $Global:TenantID) `
                                    -Plugin ConnectTo-Azure -IsVerbose -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                $RMAuth = $authContext.AcquireToken($Instance.ResourceManager, $clientId, $redirectUri,
                                                    [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto)
                #Add subscriptionid to object
                $RMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Global:Subscription.subscriptionId -Force
            }
            catch{
                Convert-Exception -MyError $_ -FunctionName "ConnectTo-Azure" -WriteLog $Global:WriteLog
            }
            #Authenticate user against Azure Service Management
            try{
                Write-AzucarMessage -Message ($message.LoginAzureSMMesssage -f $Global:TenantID) `
                                    -Plugin ConnectTo-Azure -IsVerbose -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                $SMAuth = $authContext.AcquireToken($Instance.Servicemanagement, $clientId, $redirectUri,
                                                [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto)
                #Add subscriptionid to object
                $SMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Global:Subscription.subscriptionId -Force
            }
            catch{
                Convert-Exception -MyError $_ -FunctionName "ConnectTo-Azure" -WriteLog $Global:WriteLog
            }
            #Save all connections
            $connections = @{
                            "ActiveDirectory" = $AADAuthResult;
                            "ResourceManager" = $RMAuth;
                            "ServiceManagement" = $SMAuth;
            }
            Set-Variable AzureConnections -Value $connections -Scope Global -Force
        }
        else{
            #Catch TenantID error
            $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception("Unable to find a valid subscription....")),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                           )
            Convert-Exception -MyError $ErrorRecord  -FunctionName "ConnectTo-Azure" -WriteLog $Global:WriteLog
        }
    }
}

#Connect to Azure
Function ConnectTo-AzureAD{
     Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance,

        [Parameter(Mandatory=$false, HelpMessage="Force Authentication")]
        [Bool]
        $ForceAuth=$false

     )
    Begin{
        #Write-Host $Credential.Username
        #Load Libraries
        $ADAuthLibrary = ("{0}\{1}" -f $ScriptPath, "Libs\Microsoft.IdentityModel.Clients.ActiveDirectory.dll")
        $ADAuthForms = ("{0}\{1}" -f $ScriptPath, "Libs\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll") 
        $null = [System.Reflection.Assembly]::LoadFrom($ADAuthLibrary)
        $null = [System.Reflection.Assembly]::LoadFrom($ADAuthForms)
        # Client ID for Azure PowerShell
        $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
        # Set redirect URI for Azure PowerShell
        $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
        # Common Resource client ID for Azure PowerShell
        $resourceClientId = "00000002-0000-0000-c000-000000000000"
    }
    Process{
        $AzureAuthority = "{0}/{1}" -f $Instance.Login, "Common/oauth2/authorize"
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $AzureAuthority

        try{
            #Checking for Force Authentication
            if($ForceAuth){
                $AuthMethod = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
            }
            else{
                $AuthMethod = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
            }
            
            #Authenticate user against Azure Resource Manager
            $RMAuth = $authContext.AcquireToken($Instance.Graph, $clientId, $redirectUri,$AuthMethod)
            #$RMAuth | fl
            $uri = ("{0}{1}?api-version={2}" -f $Instance.Graph,"tenants", "2016-06-01")
            $Tenants = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth -OwnQuery $uri -Manual -Verbosity $Global:VerboseOptions
            $AllTenants = @()
            foreach ($tenant in $Tenants){
                $AllTenants += $tenant.tenantId
            }
            #Try to authorize tenant
            foreach ($tenant in $AllTenants){
                Write-AzucarMessage -Message ($message.CheckTenantIDMessage -f $tenant) `
                                    -Plugin ConnectTo-AzureAD -IsVerbose -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                Authorize-Tenant -TenantID $tenant
            }            
        }
        catch{
            Convert-Exception -MyError $_ -FunctionName "ConnectTo-AzureAD" -WriteLog $Global:WriteLog
        }
    }
    End{
        if($Global:TenantID -ne $false -and $Global:Subscription -ne $false){
            #Set TenantID
            $AzureAuthority = "{0}/{1}" -f $Instance.Login, ("{0}/oauth2/authorize" -f $Global:TenantID)
            $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $AzureAuthority
            #Set verbose option
            $VerboseOptions=@{Verbose=$true}
            #Authenticate user against Azure Active Directory
            try{
                Write-AzucarMessage -Message ($message.LoginAzureTenantMesssage -f $Global:TenantID)`
                                    -Plugin ConnectTo-AzureAD -IsVerbose -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                $AADAuthResult = $authContext.AcquireToken($Instance.Graph, $clientId, $redirectUri,
                                                    [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto)
                #Add subscriptionid to object
                $AADAuthResult | Add-Member -type NoteProperty -name SubscriptionId -value $Global:Subscription.subscriptionId -Force
            }
            catch{
                 Convert-Exception -MyError $_ -FunctionName "ConnectTo-AzureAD" -WriteLog $Global:WriteLog
            }
            #Authenticate user to Azure Resource Manager
            try{
                Write-AzucarMessage -Message ($message.LoginAzureRMMesssage -f $Global:TenantID)`
                                    -Plugin ConnectTo-AzureAD -IsVerbose -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                $RMAuth = $authContext.AcquireToken($Instance.ResourceManager, $clientId, $redirectUri,
                                                    [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto)
                #Add subscriptionid to object
                $RMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Global:Subscription.subscriptionId -Force
            }
            catch{
                Convert-Exception -MyError $_ -FunctionName "ConnectTo-AzureAD" -WriteLog $Global:WriteLog
            }
            #Authenticate user against Azure Service Management
            try{
                Write-AzucarMessage -Message ($message.LoginAzureSMMesssage -f $Global:TenantID)`
                                    -Plugin ConnectTo-AzureAD -IsVerbose -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                $SMAuth = $authContext.AcquireToken($Instance.Servicemanagement, $clientId, $redirectUri,
                                                [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto)
                #Add subscriptionid to object
                $SMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Global:Subscription.subscriptionId -Force
            }
            catch{
                Convert-Exception -MyError $_ -FunctionName "ConnectTo-AzureAD" -WriteLog $Global:WriteLog
            }
            #Save all connections
            $connections = @{
                            "ActiveDirectory" = $AADAuthResult;
                            "ResourceManager" = $RMAuth;
                            "ServiceManagement" = $SMAuth;
            }
            Set-Variable AzureConnections -Value $connections -Scope Global -Force
        }
        else{
            #Catch TenantID error
            $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception("Unable to find a valid subscription....")),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                           )
            Convert-Exception -MyError $ErrorRecord  -FunctionName "ConnectTo-AzureAD" -WriteLog $Global:WriteLog
        }
    }
}