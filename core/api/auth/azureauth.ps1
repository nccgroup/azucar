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
            Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $compilerParameters | Out-Null
        }
        #Get Date
        [DateTime]$dateTime = Get-Date
        $null = $dateTime.AddDays(1)
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

function Clear-AzADALATokenCacheForAllAuthorities
{

<# 
 .SYNOPSIS 
 Clear AccessToken local cache 
 
 .DESCRIPTION 
 The Clear-AzADALATokenCacheForAllAuthorities function lets you clear OAuth 2.0 AccessToken local cache for
 all authorities 
 
 .EXAMPLE 
 Clear-AzADALATokenCacheForAllAuthorities
 
 This example clear local accesstoken cache for all authorities. 
#>    
    # https://docs.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.clients.activedirectory.tokencache?view=azure-dotnet
    $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared
    #Clear cache    
    $null = $cache.Clear()

    Write-Verbose "Authentication Token Cache Cleared"
}

function Get-AzADALTokenCacheForTenantID{
<# 
 .SYNOPSIS 
 Get AccessToken local cache for Authority
 
 .DESCRIPTION 
 The Get-AzADALTokenCacheForTenantID function gets you the first OAuth 2.0 AccessToken for
 an authority from local cache 
 
 .EXAMPLE 
 Get-AzADALTokenCacheForTenantID -TenantID 00000000-0000-0000-0000-000000000000
 
 This example gets a local accesstoken cache for the 00000000-0000-0000-0000-000000000000 TenantID. 
#>    
    param
    (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$authContext,

        [Parameter(Mandatory=$True,HelpMessage = 'Please specify the Tenant ID')]
        [ValidateScript({
          $guid = [System.Guid]::Empty
          if ([System.Guid]::TryParse($_, [ref]$guid)){
            $true
          }
          else{
            Throw "The $_ is not a valid TenantID"
            $false
          }
        })]
        [String]$TenantID
    )
    if ($authContext -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]){
        return $authContext.TokenCache.ReadItems() | Where-Object { $_.TenantId -eq $TenantID } | Select-Object -First 1
    }
    else{
        Write-AzucarMessage -Message ("Invalid authentication context") -Plugin Get-AzADALTokenCacheForTenantID -IsVerbose `
                            -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
        return $null
    }
}

function Get-AzADALAuthenticationContext {
<# 
 .SYNOPSIS 
 Get Authentication context
 
 .DESCRIPTION 
 The Get-AzADALAuthenticationContext function gets you a valid ADAL Authentication Context. If no TenantID is passed
 a "Common" Authentication Context is returned
 
 .EXAMPLE 
 Get-AzADALAuthenticationContext -Login https://login.microsoft.conline.com -TenantID 00000000-0000-0000-0000-000000000000
 
 This example gets an AuthenticationContext object for the 00000000-0000-0000-0000-000000000000 TenantID. 
#>    
    param
    (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Login = "https://login.microsoftonline.com",

        [Parameter(Mandatory=$false,HelpMessage = 'Please specify the Tenant ID')]
        [ValidateScript({
          $guid = [System.Guid]::Empty
          if ([System.Guid]::TryParse($_, [ref]$guid)){
            $true
          }
          else{
            Throw "The $_ is not a valid TenantID"
            $false
          }
        })]
        [String]$TenantID


    )
    if($TenantID){
        $AzureAuthority = "{0}/{1}" -f $Login, $TenantID
    }
    else{
        $AzureAuthority = "{0}/{1}" -f $Login, "Common"
    }
    #Create authentication Context
    $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($AzureAuthority)
    if($authContext){
        return $authContext
    }
    else{
        return $null
    }
}

function New-AzADALClientCredential {
<# 
 .SYNOPSIS 
 Acquires OAuth AccessToken from Azure Active Directory
 
 .DESCRIPTION 
 The New-AzADALClientCredential function lets you acquire an ServicePrincipal OAuth AccessToken from Azure by using
 the Active Directory Authentication Library (ADAL). 
 
 There are three ways to get AccessToken 
  
 1. You can pass a PSCredential object with a ServicePrincipalID and ServicePrincipal password 
 2. You can pass an ApplicationID and Certificate in order to use the certificate credential flow.
 3. You can pass an ApplicationID, Certificate and Certificate password in order to use the certificate credential flow. 
 
 .PARAMETER InputObject
 PSCredential object
 
 .PARAMETER ApplicationID
 A registerered ApplicationID as application to the Azure Active Directory. 
 
 .PARAMETER ClientCertificate
 Client certificate of the application requesting the token.
 
 .PARAMETER CertFilePassword
 Secure password of the certificate
 
 .EXAMPLE 
 $Credential = Get-Credential -Message "Please, enter Service Principal Name and secret:"
 $ADALCredential = New-AzADALClientCredential -InputObject $Credential
 
 This example acquire accesstoken by using Service Principal.
 
 .EXAMPLE 
 $secure = $PlainTextPassword | ConvertTo-SecureString -AsPlainText -Force
 $ADALCredential = New-AzADALClientCredential -ClientCertificate C:\\Mycert.pfx -CertFilePassword $secure -ApplicationID 00000000-0000-0000-0000-000000000000
 
 This example acquire accesstoken by using Application Certificate credential 
 
#>
    param
    (
        # pscredential of the client requesting the token.
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $InputObject,
        # Identifier of the application requesting the token.
        [Parameter(Mandatory = $false)]
        [string] $ApplicationID,
        # Client certificate of the application requesting the token.
        [Parameter(Mandatory = $false, HelpMessage = 'Please specify the certificate file path')]
        [System.IO.FileInfo]$ClientCertificate,
        # Secure password of the certificate
        [Parameter(Mandatory = $false,HelpMessage = 'Please specify the certificate password')]
        [Security.SecureString] $CertFilePassword
    )

    ## Check inputObject
    if ($InputObject -is [pscredential]) {
        [string] $ServicePrincipalID = $InputObject.UserName
        [securestring] $ServicePrincipalPwd = $InputObject.Password
    }
    if ($ServicePrincipalID -AND $ServicePrincipalPwd) {
        [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential] $ClientCredential = (New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential -ArgumentList $ServicePrincipalID, ([Microsoft.IdentityModel.Clients.ActiveDirectory.SecureClientSecret]$ServicePrincipalPwd.Copy()))
    }
    if ($ClientCertificate -AND $ApplicationID) {
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        try{
            if($CertFilePassword){
                [IntPtr]$SecureToBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertFilePassword)
                $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureToBSTR)
                $Cert.Import($ClientCertificate,$Password,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($SecureToBSTR)
            }
            else{
                $Cert.Import($ClientCertificate,[String]::Empty,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
            }

            [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate] $ClientCredential = (New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate -ArgumentList $ApplicationID, $Cert)
        }
        catch{
            Write-Host $_.Exception.Message -ForegroundColor Yellow
            Exit
        }
    }
    if($ClientCredential){
        #Return client credential
        return $ClientCredential
    }
    else{
        return $null
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
        if($Global:Subscription -eq $false){
            #Create Array for subscriptions
            $AllSubscriptions = @()
            try{
                foreach ($auth in $Authentication){
                    if ($auth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult] -or $auth.AccessToken){
                        $authHeader = ("Bearer {0}" -f $auth.AccessToken)
                        # Set HTTP request headers to include Authorization header
                        $requestHeader = @{
                                    "x-ms-version" = "2014-10-01";
                                    "Authorization" = $authHeader
                        }
                        #https://msdn.microsoft.com/en-us/library/azure/mt704050.aspx
                        $uriSubscriptions = "{0}subscriptions?api-version=2016-06-01" -f $Instance.ResourceManager
                        Write-Host $uriSubscriptions -ForegroundColor Yellow
                        $Response = New-WebRequest -Url $uriSubscriptions -Headers $requestHeader `
                                    -Method Get -Encoding "application/json" -UserAgent "Azucar" `
                                    -Verbosity $Global:VerboseOptions | select -ExpandProperty value
                        
                        if($Response){
                            if($auth.tenant.displayName){
                                Write-AzucarMessage -Message ("A valid subscription was found for {0} tenant" -f $auth.tenant.displayName) `
                                                    -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                                    -WriteLog $Global:WriteLog
                            }
                            elseif ($auth.TenantId){
                                Write-AzucarMessage -Message ("A valid subscription was found for {0} tenant" -f $auth.TenantId) `
                                                    -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                                    -WriteLog $Global:WriteLog -Color Green                        
                            }
                            else{
                                Write-AzucarMessage -Message ("A valid subscription was found for {0} tenant" -f $TenantID) `
                                                    -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                                    -WriteLog $Global:WriteLog -Color Green
                            }
                            $Response | Add-Member -type NoteProperty -name TenantID -value $auth.TenantID -Force
                            $AllSubscriptions += $Response
                        }
                        else{
                            if($auth.tenant.displayName){
                                Write-AzucarMessage -Message ("No valid subscription was found for {0} tenant" -f $auth.tenant.displayName) `
                                                    -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                                    -WriteLog $Global:WriteLog
                            }
                            else{
                                Write-AzucarMessage -Message ("No valid subscription was found for {0} tenant" -f $auth.TenantId) `
                                                    -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                                    -WriteLog $Global:WriteLog
                            }
                        }
                    }
                    else{
                        Write-AzucarMessage -Message "An Invalid AuthenticationResult object was found" `
                                            -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                            -WriteLog $Global:WriteLog
                    }
                }
            }  
            catch{
                Convert-Exception -MyError $_ -FunctionName "Select-AzSecSubscription" -WriteLog $Global:WriteLog
            }  
        }
        else{
            Write-AzucarMessage -Message ("A valid subscription with name {0} was found in cache for {1} tenant" -f $Subscription.displayName, $Subscription.TenantId) `
                                -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                -WriteLog $Global:WriteLog
            break;
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
            Write-AzucarMessage -Message "No valid subscription were found" `
                                -Plugin Select-AzSecSubscription -IsVerbose -Verbosity $VerboseOptions `
                                -WriteLog $Global:WriteLog           
        }
    }
    End{
        #Nothing to do here
    }
}

#Get authorization for Tenant
Function Authorize-Tenant{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$TenantID,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Authentication

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
                $AzureAuthority = "{0}/{1}" -f $Instance.Login, $tenant.tenantId
                $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($AzureAuthority)
                $AuthResult = $authContext.AcquireTokenSilentAsync($Instance.ResourceManager, $clientId).GetAwaiter().GetResult();
                if($AuthResult -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                    Write-AzucarMessage -Message ("Adding {0} tenant displayName..." -f $tenant.displayName) `
                                        -Plugin Authorize-Tenant -IsVerbose -Verbosity $VerboseOptions `
                                        -WriteLog $Global:WriteLog
                    #Add tenant information to AuthResult object
                    $AuthResult | Add-Member -type NoteProperty -name Tenant -value $tenant -Force
                    $AuthResponses += $AuthResult
                }
            }
        }
        catch{
            Convert-Exception -MyError $_ -FunctionName "Authorize-Tenant" -WriteLog $Global:WriteLog
        }
     }
     End{
        if($AuthResponses){
            Select-AzSecSubscription -Authentication $AuthResponses -Instance $Instance
        }
     }
}

Function Get-AzADALToken{
    param
    (
        [parameter(Mandatory=$false, HelpMessage = 'Azure Endpoints')]
        [Object]$Environment,

        [parameter(Mandatory = $false, HelpMessage = 'PsCustomobject with cached credentials')]
        [pscustomobject]$cachedCredential,

        [Parameter(Mandatory=$false, HelpMessage = 'Please specify the Tenant ID')]
        [String]$TenantID,

        [Parameter(Mandatory = $false, HelpMessage = 'Please specify the Service Principal Application ID')]
        [String]$ApplicationId,

        [Parameter(Mandatory=$false, HelpMessage = 'Please specify the Service Principal PFX file')]
        [System.IO.FileInfo]$Certificate,

        [Parameter(Mandatory = $false, HelpMessage = 'Authentication Mode')]
        [String]$AuthMode,

        [Parameter(Mandatory = $false, HelpMessage = 'Please specify the certificate password')]
        [String]$CertFilePassword,

        [Parameter(Mandatory=$false, HelpMessage="Force Authentication Context. Only valid for user&password auth method")]
        [Switch]$ForceAuth
    )
    switch -Exact ($AuthMode) {
        "Interactive" {
            Write-AzucarMessage -Message ($message.AuthModeMessage -f "Interactive") `
                                -Plugin Get-AzADALToken -IsVerbose -Verbosity $VerboseOptions `
                                -WriteLog $Global:WriteLog
            if(-NOT $TenantID -or $TenantID -eq [System.Guid]::Empty){
                $authContext = Get-AzADALAuthenticationContext -Login $Environment.Login
            }
            else{
                $authContext = Get-AzADALAuthenticationContext -Login $Environment.Login -TenantID $TenantID
            }
            #https://docs.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.clients.activedirectory.promptbehavior?view=azure-dotnet
            $prompt = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior
            if($ForceAuth){
                $prompt.value__ = 1                
            }
            else{
                $prompt.value__ = 0
            }
            $platformParameters = new-object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $prompt
            $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
            # Set redirect URI for Azure PowerShell
            $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
            # Common Resource client ID for Azure PowerShell
            $resourceClientId = "00000002-0000-0000-c000-000000000000"
            try{
                if(-NOT $ForceAuth){
                    #$tmpToken = $authContext.TokenCache.ReadItems() | Select-Object -Last 1
                    $tmpToken = $authContext.TokenCache.ReadItems() | Where-Object { $_.Resource -eq "https://management.azure.com/" } | Select-Object -Last 1
                    #$authContext.TokenCache.ReadItems() | Select-Object * | ogv
                    if($tmpToken -is [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCacheItem] -AND $tmpToken.ExpiresOn -gt (Get-Date)){
                        Write-AzucarMessage -Message ("Using the last token in cache for {0} issued to {1}" -f $tmpToken.TenantId, $tmpToken.DisplayableId) -Plugin Get-AzADALToken -IsHost -Color Green
                        #$authContext = Get-AzADALAuthenticationContext -Login $Instance.Login -TenantID $tmpToken.TenantId
                        $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($tmpToken.Authority)              
                        $auth = $authContext.AcquireTokenSilentAsync($Environment.ResourceManager, $clientId).GetAwaiter().GetResult();
                    }
                    else{
                        Write-AzucarMessage -Message ("There was an error with TokenCache which expires on {0}. Trying to refresh token" -f $tmpToken.ExpiresOn) -Plugin Get-AzADALToken -IsHost -Color Yellow
                        $auth = $authContext.AcquireTokenAsync($Environment.ResourceManager, $clientId, $redirectUri, $platformParameters).GetAwaiter().GetResult();
                    } 
                }
                else{
                    $auth = $authContext.AcquireTokenAsync($Environment.ResourceManager, $clientId, $redirectUri, $platformParameters).GetAwaiter().GetResult();
                }
            }
            catch [Microsoft.IdentityModel.Clients.ActiveDirectory.AdalException]{
                Convert-Exception -MyError $_ -FunctionName "Get-AzADALToken" -WriteLog $Global:WriteLog
            }           
            if($auth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                $uri = ("{0}{1}?api-version={2}" -f $Environment.ResourceManager,"tenants", "2017-08-01")
                $Tenants = Get-AzSecRMObject -Instance $Environment -Authentication $auth -OwnQuery $uri -Manual -Verbosity $Global:VerboseOptions
                Authorize-Tenant -TenantID $Tenants -Instance $Environment -Authentication $auth
                if($Subscription){
                    #Silent Authentication
                    $prompt.value__ = 0
                    $platformParameters = new-object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $prompt
                    $authContext = Get-AzADALAuthenticationContext -Login $Environment.Login -TenantID $Subscription.TenantID
                    try{
                        $RMAuth = $authContext.AcquireTokenAsync($Environment.ResourceManager, $clientId, $redirectUri, $platformParameters).GetAwaiter().GetResult();
                        if($RMAuth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                            #Add subscriptionid to object
                            $RMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                            $RMAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                            $RMAuth | Add-Member -type NoteProperty -name AuthType -value "Interactive" -Force
                        }
                        #Authenticate against Azure Active Directory
                        $AADAuthResult = $authContext.AcquireTokenAsync($Environment.Graph, $clientId, $redirectUri, $platformParameters).GetAwaiter().GetResult();
                        if($AADAuthResult -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                            #Add subscriptionid to object
                            $AADAuthResult | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                            $AADAuthResult | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                            $AADAuthResult | Add-Member -type NoteProperty -name AuthType -value "Interactive" -Force
                        }
                        #Authenticate against Azure Service Management (Old APIs)
                        $SMAuth = $authContext.AcquireTokenAsync($Environment.Servicemanagement, $clientId, $redirectUri, $platformParameters).GetAwaiter().GetResult();
                        if($SMAuth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                            #Add subscriptionid to object
                            $SMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                            $SMAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                            $SMAuth | Add-Member -type NoteProperty -name AuthType -value "Interactive" -Force
                        }
                        #Authenticate against Storage endpoint
                        $StorageAuth = $authContext.AcquireTokenAsync($Environment.Storage, $clientId, $redirectUri, $platformParameters).GetAwaiter().GetResult();
                        if($StorageAuth){
                            $StorageAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                            $StorageAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                            $StorageAuth | Add-Member -type NoteProperty -name AuthType -value "Interactive" -Force
                        }
                        #Authenticate against Vault endpoint
                        $VaultAuth = $authContext.AcquireTokenAsync($Environment.Vaults, $clientId, $redirectUri, $platformParameters).GetAwaiter().GetResult();
                        if($VaultAuth){
                            $VaultAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                            $VaultAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                            $VaultAuth | Add-Member -type NoteProperty -name AuthType -value "Interactive" -Force
                        }
                    }
                    catch{
                        Convert-Exception -MyError $_ -FunctionName "Get-AzADALToken" -WriteLog $Global:WriteLog
                    }
                }
            }
            break
        }
        "UseCachedCredentials" {
            Write-AzucarMessage -Message ($message.AuthModeMessage -f "Cached credentials") `
                                -Plugin Get-AzADALToken -IsVerbose -Verbosity $VerboseOptions `
                                -WriteLog $Global:WriteLog
            if($cachedCredential){
                $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($cachedCredential.Authority)              
                $RMAuth = $cachedCredential
                Select-AzSecSubscription -Authentication $RMAuth -Instance $Environment
                if($Subscription){
                    $RMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                    $RMAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                    $RMAuth | Add-Member -type NoteProperty -name AuthType -value "CachedCredential" -Force
                    #Authenticate against Azure Active Directory
                    $AADAuthResult = $authContext.AcquireTokenSilentAsync($Environment.Graph, $RMAuth.ClientId).GetAwaiter().GetResult();
                    if($AADAuthResult -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                        #Add subscriptionid and TenantID to object
                        $AADAuthResult | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                        $AADAuthResult | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                        $AADAuthResult | Add-Member -type NoteProperty -name AuthType -value "CachedCredential" -Force
                    }
                    #Authenticate against Azure Service Management (Old APIs)
                    $SMAuth = $authContext.AcquireTokenSilentAsync($Environment.Servicemanagement, $RMAuth.ClientId).GetAwaiter().GetResult();
                    if($SMAuth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                        #Add subscriptionid and TenantID to object
                        $SMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                        $SMAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                        $SMAuth | Add-Member -type NoteProperty -name AuthType -value "CachedCredential" -Force
                    }
                    #Authenticate against Storage endpoint
                    $StorageAuth = $authContext.AcquireTokenAsync($Environment.Storage, $RMAuth.ClientId).GetAwaiter().GetResult();
                    if($StorageAuth){
                        $StorageAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                        $StorageAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                        $StorageAuth | Add-Member -type NoteProperty -name AuthType -value "CachedCredential" -Force
                    }
                    #Authenticate against Vault endpoint
                    $VaultAuth = $authContext.AcquireTokenAsync($Environment.Vaults, $RMAuth.ClientId).GetAwaiter().GetResult();
                    if($VaultAuth){
                        $VaultAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                        $VaultAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                        $VaultAuth | Add-Member -type NoteProperty -name AuthType -value "CachedCredential" -Force
                    }
                }
                break;                  
            }
        }
        "Client_Credentials" {
            Write-AzucarMessage -Message ($message.AuthModeMessage -f "Client credentials") `
                                -Plugin Get-AzADALToken -IsVerbose -Verbosity $VerboseOptions `
                                -WriteLog $Global:WriteLog
            if($TenantID -AND $TenantID -ne [System.Guid]::Empty){
                $Credential = Get-Credential -Message "Please, enter Service Principal Name and secret:"
                $ADALCredential = New-AzADALClientCredential -InputObject $Credential
                $authContext = Get-AzADALAuthenticationContext -Login $Environment.Login -TenantID $TenantID
                $RMAuth = $authContext.AcquireTokenAsync($Environment.ResourceManager, $ADALCredential).GetAwaiter().GetResult();
                if($RMAuth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                    Select-AzSecSubscription -Authentication $RMAuth -Instance $Environment
                    if($Subscription){
                        $RMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                        $RMAuth | Add-Member -type NoteProperty -name TenantId -value $TenantID -Force
                        $RMAuth | Add-Member -type NoteProperty -name AuthType -value "Client Credential" -Force
                        #Authenticate against Azure Active Directory
                        try{
                            $AADAuthResult = $authContext.AcquireTokenAsync($Environment.Graph, $ADALCredential).GetAwaiter().GetResult();
                            if($AADAuthResult -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                                #Add subscriptionid and TenantID to object
                                $AADAuthResult | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $AADAuthResult | Add-Member -type NoteProperty -name TenantId -value $TenantID -Force
                                $AADAuthResult | Add-Member -type NoteProperty -name AuthType -value "Client Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Active Directory with the client credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                        try{
                            #Authenticate against Azure Service Management (Old APIs)
                            $SMAuth = $authContext.AcquireTokenAsync($Environment.Servicemanagement, $ADALCredential).GetAwaiter().GetResult();
                            if($SMAuth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                                #Add subscriptionid and TenantID to object
                                $SMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $SMAuth | Add-Member -type NoteProperty -name TenantId -value $TenantID -Force
                                $SMAuth | Add-Member -type NoteProperty -name AuthType -value "Client Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Service Management with the client credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                        try{
                            #Authenticate against Storage endpoint
                            $StorageAuth = $authContext.AcquireTokenAsync($Environment.Storage, $ADALCredential).GetAwaiter().GetResult();
                            if($StorageAuth){
                                $StorageAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $StorageAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                                $StorageAuth | Add-Member -type NoteProperty -name AuthType -value "Client Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Storage Account endpoint with the client credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                        try{
                            #Authenticate against Vault endpoint
                            $VaultAuth = $authContext.AcquireTokenAsync($Environment.Vaults, $ADALCredential).GetAwaiter().GetResult();
                            if($VaultAuth){
                                $VaultAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $VaultAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                                $VaultAuth | Add-Member -type NoteProperty -name AuthType -value "Client Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Keyvault endpoint with the client credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                    }
                }
            }
            else{
                Write-AzucarMessage -Message ("Unable to connect to Azure without a valid TenantID") `
                                    -Plugin Get-AzADALToken -IsVerbose -Verbosity $VerboseOptions `
                                    -WriteLog $Global:WriteLog
                exit;                
            }
            break;
        }
        "Certificate_Credentials" {
            Write-AzucarMessage -Message ($message.AuthModeMessage -f "Certificate credentials") `
                                -Plugin Get-AzADALToken -IsVerbose -Verbosity $VerboseOptions `
                                -WriteLog $Global:WriteLog
            if($Certificate -AND $TenantID -AND $TenantID -ne [System.Guid]::Empty -AND $ApplicationId -AND $ApplicationId -ne [System.Guid]::Empty){
                if (-not ([string]::IsNullOrEmpty($CertFilePassword))){
                    $secure = $CertFilePassword | ConvertTo-SecureString -AsPlainText -Force
                    $ADALCredential = New-AzADALClientCredential -ClientCertificate $Certificate -CertFilePassword $secure -ApplicationID $ApplicationId
                }
                else{
                    $ADALCredential = New-AzADALClientCredential -ClientCertificate $Certificate -ApplicationID $ApplicationId
                }
                #Get Authentication Context
                $authContext = Get-AzADALAuthenticationContext -Login $Environment.Login -TenantID $TenantID
                $RMAuth = $authContext.AcquireTokenAsync($Environment.ResourceManager, $ADALCredential).GetAwaiter().GetResult();
                if($RMAuth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                    Select-AzSecSubscription -Authentication $RMAuth -Instance $Environment
                    if($Subscription){
                        #Add subscriptionid to object
                        $RMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force                        
                        $RMAuth | Add-Member -type NoteProperty -name TenantId -value $TenantID -Force
                        $RMAuth | Add-Member -type NoteProperty -name AuthType -value "Certificate Credential" -Force
                        try{
                            #Authenticate against Azure Active Directory
                            $AADAuthResult = $authContext.AcquireTokenAsync($Environment.Graph, $ADALCredential).GetAwaiter().GetResult();
                            if($AADAuthResult -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                                #Add subscriptionid to object
                                $AADAuthResult | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $AADAuthResult | Add-Member -type NoteProperty -name TenantId -value $TenantID -Force
                                $AADAuthResult | Add-Member -type NoteProperty -name AuthType -value "Certificate Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Active Directory with the certificate credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                        try{
                            #Authenticate against Azure Service Management (Old APIs)
                            $SMAuth = $authContext.AcquireTokenAsync($Environment.Servicemanagement, $ADALCredential).GetAwaiter().GetResult();
                            if($SMAuth -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                                #Add subscriptionid to object
                                $SMAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $SMAuth | Add-Member -type NoteProperty -name TenantId -value $TenantID -Force
                                $SMAuth | Add-Member -type NoteProperty -name AuthType -value "Certificate Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Service management with the client credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                        try{
                            #Authenticate against Storage endpoint
                            $StorageAuth = $authContext.AcquireTokenAsync($Environment.Storage, $ADALCredential).GetAwaiter().GetResult();
                            if($StorageAuth){
                                $StorageAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $StorageAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                                $StorageAuth | Add-Member -type NoteProperty -name AuthType -value "Certificate Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Storage account endpoint with the client credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                        try{
                            #Authenticate against Vault endpoint
                            $VaultAuth = $authContext.AcquireTokenAsync($Environment.Vaults, $ADALCredential).GetAwaiter().GetResult();
                            if($VaultAuth){
                                $VaultAuth | Add-Member -type NoteProperty -name SubscriptionId -value $Subscription.subscriptionId -Force
                                $VaultAuth | Add-Member -type NoteProperty -name TenantId -value $Subscription.tenantId -Force
                                $VaultAuth | Add-Member -type NoteProperty -name AuthType -value "Certificate Credential" -Force
                            }
                        }
                        catch{
                            Write-AzucarMessage -Message ("Unable to connect to Azure Vault endpoint with the client credential flow") -Plugin Get-AzADALToken -IsHost -Color Yellow    
                        }
                    }
                }
                break;
            }
            else{
                Write-AzucarMessage -Message ("Unable to connect to Azure without {0} TenantID, {1} ApplicationID and certificate" -f $TenantID, $ApplicationId)  `
                                    -Plugin Get-AzADALToken -IsVerbose -Verbosity $VerboseOptions `
                                    -WriteLog $Global:WriteLog
                exit; 
            }
        }

    }
    if($RMAuth -or $AADAuthResult -or $SMAuth -or $StorageAuth -or $VaultAuth){
        #Save all connections
        $connections = @{
                        "ActiveDirectory" = $AADAuthResult;
                        "ResourceManager" = $RMAuth;
                        "ServiceManagement" = $SMAuth;
                        "AzureStorage" = $StorageAuth;
                        "AzureVault" = $VaultAuth;
        }
        #Save connections within a global variable
        Set-Variable AzureConnections -Value $connections -Scope Global -Force  
    }
}