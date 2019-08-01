<#
.SYNOPSIS
Azucar is a multi-threaded plugin-based tool to help assess the security of Azure Cloud environment configurations.

The script will not change any asset deployed in the Azure subscription. This is done by using only GET & POST requests through API endpoints.

.DESCRIPTION
The main features included in this version are:

	    Return a number of attributes on computers, users, groups, contacts, events, etc... from an Azure Active Directory
	    Search for High level accounts in Azure Tenant, including Azure Active Directory, classic administrators and Directory Roles (RBAC)
	    Multi-Threading support
	    Plugin Support
        The following assets are supported by AZUCAR:
            Azure SQL Databases
            Azure Active Directory           
            Storage Accounts
            Classic Virtual Machines
            Virtual Machines V2
            Security Status
            Security Policies
            Role Assignments (RBAC)
            Security Patches
            Security Baseline
            Security Center
            Network Security Groups
            Classic Endpoints
            Azure Security Alerts
            Azure Web Application Firewall

    With AZUCAR, there is also support for exporting data driven to popular formats like CSV, XML or JSON.

    Office Support
        Support for exporting data driven to EXCEL format. The tool also support table style modification, chart creation, company logo or independent language support. At the moment Office Excel 2010, Office Excel 2013 and Office Excel 2016 are supported by the tool.
	
.NOTES
	Author		: Juan Garrido
    Twitter		: @tr1ana
    Company		: https://www.nccgroup.trust
    File Name	: Azucar.ps1
    Version     : 1.0

.LINK
    https://github.com/nccgroup/azucar

.EXAMPLE
	$assets = .\Azucar.ps1 -ExportTo PRINT

This example will retrieve information of an Azure Tenant and print results to a local variable. The script will try to connect using the ADAL library, and if no credential passed, the script will try to connect using the bearer token for logged user

.EXAMPLE
	$data = .\Azucar.ps1 -AuthMode UseCachedCredentials -Verbose -WriteLog -Debug -ExportTo PRINT

This example will retrieve information of an Azure Tenant and print results to a local variable. The script will try to connect by using the ADAL library and will try to connect by using a cached credential

.EXAMPLE
	$data = .\Azucar.ps1 -AuthMode Client_Credentials -Verbose -WriteLog -Debug -ExportTo PRINT

This example will retrieve information of an Azure Tenant and print results to a local variable. The script will try to connect by using the ADAL library and will try to connect by using the client credential flow
	
.EXAMPLE
	.\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\server.pfx -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000

This example will retrieve information of an Azure Tenant and export data driven to CSV, JSON, XML and Excel format into Reports folder. The script will try to connect by using the Azure Active Directory Application Certificate credential flow

.EXAMPLE
	.\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\server.pfx -CertFilePassword MySuperP@ssw0rd! -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000

This example will retrieve information of an Azure Tenant and export data driven to CSV, JSON, XML and Excel format into Reports folder. The script will try to connect by using the Azure Active Directory Application Certificate credential flow

.EXAMPLE
	.\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL

This example will retrieve information of an Azure Tenant and export data driven to CSV, JSON, XML and Excel format into Reports folder. The script will try to connect using the ADAL library, and if no credential passed, the script will try to connect using the bearer token for logged user
	
.EXAMPLE
	$Azure = .\Azucar.ps1 -ExportTo PRINT -Verbose -Analysis ActiveDirectory

This example will retrieve information of Active Directory in Azure Tenant and store all results in the $Azure var. 

.EXAMPLE
	.\Azucar.ps1 -ExportTo CSV -Verbose -Analysis ActiveDirectory,Databases,SecurityAlerts,Firewall

This example will retrieve information of various assets of an Azure Tenant, including Active Directory, SQL Server, Security Alerts and Firewall. All information will be exported to CSV format. 
	
.PARAMETER Instance
	Select an instance of Azure services. Valid options are AzureCloud, Preproduction, China, AzureUSGovernment. Default value is AzureCloud

.PARAMETER Analysis
	Collect data from specified assets. Accepted values are:
    
    Value                        Description
    ActiveDirectory              Retrieve information of Azure Active Directory, including users, groups, contacts, policies, reports, administrative users, etc..
    Databases                    Retrieve information of Azure SQL, including databases, Transparent Data Encryption or Threat Detection Policy
    VirtualMachines              Retrieve information of virtual machines deployed on classic mode and resource manager. 
    SecurityAlerts               Get Security Alerts from Microsoft Azure. 
    SecurityCenter               Get information about Security Center
    RoleAssignments              Retrieve information about RBAC Users and Groups
    StorageAccounts              Retrieve information about storage accounts deployed on Classic mode and resource manager
    MissingPatches               Retrieve information about missing patches by using the new Azure Log Analytics query language.
    SecurityBaseline             Retrieve information about missing security baseline policies by using the new Azure Log Analytics query language.
    All                          Extract all information about an Azure subscription

    Default value is All

.PARAMETER ExportTo
	Export data driven to specific formats. Accepted values are CSV, JSON, XML, PRINT, EXCEL. Default value is CSV

.PARAMETER Threads
	Change the threads settings. By default, a large number of requests will be made with five threads

.PARAMETER ForceAuth
	Force script to Authenticate. Only valid for legacy user & password authentication

.PARAMETER ClearCache
	Clear Token Cache

.PARAMETER ShowCache
	Open a new window with the Token Cache

.PARAMETER WriteLog
	Write events to a log file

.PARAMETER TenantID
	Force to authenticate against Azure by using specific tenant

.PARAMETER AuditorName
	Auditor Name. Used in Excel File

.PARAMETER ApplicationId
	Service Principal Application ID. Used in Certificate authentication flow

.PARAMETER Certificate
	PFX certificate file. Used in Certificate authentication flow 

.PARAMETER CertFilePassword
	PFX certificate password. Used in Certificate authentication flow

.PARAMETER AuthMode
    OAuth Authentication Flows. Accepted values are:

    Value                        Description
    Interactive                  Authenticate by using the legacy user & password flow
    Client_Credentials           Authenticate by using a Service Principal ID and Password 
    Certificate_Credentials      Authenticate by using an Application Certificate credential flow
    UseCachedCredentials         Authenticate by using cached credentials
 
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param
(	
    [parameter(Mandatory= $false, HelpMessage= "Select an instance of Azure services")]
    [ValidateSet("AzureCloud","Preproduction","China","AzureUSGovernment")]
    [String]$Instance= "AzureCloud",

    [parameter(Mandatory= $false, HelpMessage= "Analyze Azure services")]
    [ValidateSet("ActiveDirectory","DomainPolicies", "Databases","VirtualMachines", "SecurityAlerts", "SecurityCenter",
                 "RoleAssignments", "Firewall", "StorageAccounts","SecurityBaseline", "MissingPatches",
                 "Web Application Firewall", "SecurityPolicies", "SecurityContacts", "Custom", "AppServices", "DocumentDB", "All")]
    [Array]$Analysis=@("All"),

    [parameter(Mandatory= $false, HelpMessage= "Export data to multiple formats")]
    [ValidateSet("CSV","JSON","XML","PRINT","EXCEL")]
    [Array]$ExportTo=@(),

    [Parameter(Mandatory= $false, HelpMessage="Change the threads settings. Default is 5")]
    [int32]
    $Threads = 5,

    [Parameter(Mandatory= $false, HelpMessage="Force Authentication Context. Only valid for user&password auth method")]
    [Switch]
    $ForceAuth,

    [Parameter(HelpMessage="Clear token cache")]
    [Switch]
    $ClearCache,

    [Parameter(HelpMessage="Get token cache")]
    [Switch]
    $ShowCache,

    [Parameter(HelpMessage="Write Log file")]
    [Switch]
    $WriteLog=$false,

    [Parameter(Mandatory= $false, HelpMessage="Tenant name or ID")]
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
    [String]$TenantID = [System.Guid]::Empty,

    [Parameter(Mandatory= $false, HelpMessage="Auditor Name. Used in Excel File")]
	[String] $AuditorName = $env:username,

    [Parameter(Mandatory= $false, HelpMessage="Resolve Tenant domain name")]
	[String] $ResolveTenantDomainName,

    [Parameter(Mandatory= $false, HelpMessage="Resolve Tenant user name")]
	[String] $ResolveTenantUserName,

    [Parameter(Mandatory= $false, HelpMessage = 'Please specify the Service Principal Application ID')]
    [ValidateScript({
        $guid = [System.Guid]::Empty
        if ([System.Guid]::TryParse($_, [ref]$guid)){
        $true
        }
        else{
        Throw "The $_ is not a valid Service Principal Application ID"
        $false
        }
    })]
    [String]$ApplicationId = [System.Guid]::Empty,

    [Parameter(Mandatory= $false, HelpMessage = 'Please specify the Service Principal PFX file')]
    [ValidateScript({
                    if( -Not ($_ | Test-Path) ){
                        throw ("The certificate does not exist in {0}" -f (Split-Path -Path $_))
                    }
                    return $true
    })]
    [System.IO.FileInfo]$Certificate,

    [Parameter(Mandatory= $false, HelpMessage = 'Please specify the certificate password')]
    [ValidateNotNullOrEmpty()]
    [String]$CertFilePassword,

    [parameter(ParameterSetName='AuthMode', Mandatory= $false, HelpMessage= "Analyze Azure services")]
    [ValidateSet("Client_Credentials", "Certificate_Credentials", "Interactive", "UseCachedCredentials")]
    [String]$AuthMode="Interactive",

    [Parameter(ParameterSetName='Client_Credentials', Mandatory= $false, HelpMessage="Authenticate by using a Service Principal ID and Password")]
    [Switch]$ClientCredential,
    
    [Parameter(ParameterSetName='Certificate_Credentials', Mandatory= $false, HelpMessage="Authenticate by using an Application ID and Certificate Password")]
    [Switch]$CertificateCredentials,

    [Parameter(ParameterSetName='Interactive', Mandatory= $false, HelpMessage="Authenticate by using the legacy User and password flow")]
    [Switch]$Interactive,

    [Parameter(ParameterSetName='UseCachedCredentials', Mandatory= $false, HelpMessage="Authenticate by using cached credentials")]
    [Switch]$UseCachedCredentials
)

Begin{
    #Export AZURE data to multiple formats
    Function Export-ResultQuery{
        Param (
            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [Object]$Dataset,

            [parameter()]
            [ValidateSet("CSV","JSON","XML","Print","EXCEL")]
            [String]$ExportTo="CSV"

            )

        #Export data
        switch ($ExportTo) { 
            'CSV'
            {
                Generate-CSV -ObjectData $Dataset -RootPath $Report -TenantID $TenantID
            }
            'JSON'
            {
                Generate-Json -ObjectData $Dataset -RootPath $Report -TenantID $TenantID
            }
            'XML'
            {
                Generate-XML -ObjectData $Dataset -RootPath $Report -TenantID $TenantID
            }
            'EXCEL'
            {
                Generate-Excel -AzureData $Dataset -Settings $ExcelSettings `
                               -Formatting $TableFormatting -HeaderStyle $HeaderStyle -RootPath $Report -TenantID $TenantID
            }
            'Print'
            {
                $Dataset | %{
                    foreach ($node in $_.psobject.Properties){
                        [pscustomobject]@{$node.Name=$node.Value.Data}
                    }
                }
            }
        }    
    }
    #Function to create new ADObject
    Function New-AzureObject{
        try{
            #Create and return a new PsObject
            $AzureObject = New-Object -TypeName PSCustomObject
            $AzureObject | Add-Member -type NoteProperty -name Instance -value $Environment
            $AzureObject | Add-Member -type NoteProperty -name Subscription -value $Global:Subscription
            $AzureObject | Add-Member -type NoteProperty -name SubscriptionId -value $Global:Subscription.SubscriptionId
            $AzureObject | Add-Member -type NoteProperty -name TenantID -value $Global:TenantID
            $AzureObject | Add-Member -type NoteProperty -name AzureConnections -value $Global:AzureConnections
            $AzureObject | Add-Member -type NoteProperty -name Localpath -value $ScriptPath
            $AzureObject | Add-Member -type NoteProperty -name LogPath -value $Global:LogPath
            $AzureObject | Add-Member -type NoteProperty -name LogFilePath -value $Global:LogFilePath
            $AzureObject | Add-Member -type NoteProperty -name Report -value @()
            return $AzureObject
        }
        catch{
            throw ($message.UnableToCreateAzucarObject -f $_.Exception.Message)
        }
    }
    #Region Import Modules
    #---------------------------------------------------
    # Import Modules
    #---------------------------------------------------
    $MyParams = $PSBoundParameters	
    $ScriptPath = $PWD.Path #Split-Path $MyInvocation.MyCommand.Path -Parent
    . $ScriptPath\core\api\endpoints\endpoints.ps1
    . $ScriptPath\core\api\auth\azureauth.ps1
    . $ScriptPath\core\api\azure\api.ps1
    . $ScriptPath\common\getconfig.ps1
    . $ScriptPath\core\utils\utils.ps1
    . $ScriptPath\common\runspace.ps1
    . $ScriptPath\common\office\excel\excelobject.ps1
    . $ScriptPath\common\getconfig.ps1
    . $ScriptPath\common\functions.ps1
    . $ScriptPath\core\utils\csvreport.ps1
    . $ScriptPath\core\utils\jsonreport.ps1
    . $ScriptPath\core\utils\xmlreport.ps1
    . $ScriptPath\core\utils\excelreport.ps1


    ## Import localisation strings
    $LocalizedDataParams = @{
    BindingVariable = 'message';
    FileName = 'Localized.psd1';
    BaseDirectory = "{0}\{1}" -f $ScriptPath, "core\utils";
    }

    #Load ADAL library
    Load-AzADAL -Path $ScriptPath

    Import-LocalizedData @LocalizedDataParams;

    #Start Time
    $starttimer = Get-Date
    #Get Azure information of config file
    $AzureConfig = Get-AzSecConf -path "$($ScriptPath)\Config\Azucar.config" -Node "//AzureElements"
    #Get Azure Excel Settings
    $ExcelSettings = Get-AzSecConf -path "$($ScriptPath)\Config\Azucar.config" -Node "//excelSettings"
    $TableFormatting = Get-AzSecConf -path "$($ScriptPath)\Config\Azucar.config" -Node "//tableFormatting"
    $HeaderStyle = Get-AzSecConf -path "$($ScriptPath)\Config\Azucar.config" -Node "//HeaderStyle"
    #Retrieve Azure Endpoints
    $Environment = Get-AzSecEnvironment -Endpoint $Instance
    #Load API
    $AzureAPI = Get-ChildItem -Recurse "$ScriptPath\core\api\azure\*.ps1" | Select -ExpandProperty FullName
    #Load Utils
    $Utils = Get-ChildItem -Recurse "$ScriptPath\core\utils\utils.ps1" | Select -ExpandProperty FullName

    #Choose Token from Cache
    if($MyParams['AuthMode'] -eq 'UseCachedCredentials'){
        $authContext = Get-AzADALAuthenticationContext -Login "https://login.microsoftonline.com"
        if($authContext.TokenCache.Count -gt 0){
            #Choose cached credentials
            $TmpToken = $authContext.TokenCache.ReadItems() | `
                        Select-Object * | Out-GridView `
                        -Title "Choose a credential ..." -PassThru

            #$TmpToken = $authContext.TokenCache.ReadItems() | Where-Object {$_.UniqueId -eq $TmpToken.UniqueId} | Select-Object * -Last 1
            if($TmpToken -is [pscustomobject]){
                if($TmpToken.ExpiresOn -lt (Get-Date)){
                    Write-AzucarMessage -Message ($message.ExpiredTokenMessage -f $tmpToken.ExpiresOn) `
                                        -Plugin Get-AzADALToken -IsHost -Color Yellow
                    #Save ClientId
                    $clientId = $TmpToken.ClientId
                    $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($TmpToken.Authority)
                    $TmpToken = $authContext.AcquireTokenSilentAsync($Environment.ResourceManager, $TmpToken.ClientId).GetAwaiter().GetResult();
                    if($TmpToken -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult]){
                        $TmpToken | Add-Member -type NoteProperty -name ClientId -value $clientId -Force
                    }
                }
                else{
                    Write-AzucarMessage -Message ("Token issued for {0} resource looks good" -f $TmpToken.Resource) `
                                                 -Plugin Main -IsHost -Color Green
                }
            }
            else{
                Write-AzucarMessage -Message ("Invalid Authentication object. Exitting...") `
                                    -Plugin Get-AzADALToken -IsHost -Color Yellow
                exit                
            }
        }
        else{
            Write-AzucarMessage -Message "No Tokens were found in Cache" -Plugin Main -IsHost -Color Yellow
            exit
        } 
    }
    else{
        $TmpToken = $null
    }

    #Clearing cached Tokens
    if($MyParams['ClearCache']){
        Write-AzucarMessage -Message "Trying to clear the cache" -Plugin Main -IsHost -Color Yellow
        Clear-AzAuth
        Clear-AzADALATokenCacheForAllAuthorities
        Write-AzucarMessage -Message "Cache successfully deleted" -Plugin Main -IsHost -Color Green
        exit
    }
    #Resolve tenant
    if($MyParams['ResolveTenantDomainName']){
        Write-AzucarMessage -Message "Trying to resolve tenant" -Plugin Main -IsHost -Color Yellow
        Resolve-Tenant -Domain $ResolveTenantDomainName
        exit
    }
    if($MyParams['ResolveTenantUserName']){
        Write-AzucarMessage -Message "Trying to resolve tenant" -Plugin Main -IsHost -Color Yellow
        Resolve-Tenant -Username $ResolveTenantUserName
        exit
    }

    #Get Token Cache
    if($MyParams['ShowCache']){
        $authContext = Get-AzADALAuthenticationContext -Login "https://login.microsoftonline.com"
        if($authContext.TokenCache.Count -gt 0){
            $authContext.TokenCache.ReadItems() | Select-Object * | ogv
        }
        else{
            Write-AzucarMessage -Message "No Tokens were found in Cache" -Plugin Main -IsHost -Color Yellow
        }
        exit
    }

    #set the default connection limit 
    [System.Net.ServicePointManager]::DefaultConnectionLimit = 1000;
    [System.Net.ServicePointManager]::MaxServicePoints = 1000;
    try{
        #https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager.reuseport(v=vs.110).aspx
        [System.Net.ServicePointManager]::ReusePort = $true;
    }
    catch{
        #Nothing to do here
    }
    
    #Create LOG file if not exists
    if($MyParams['WriteLog']){
        #Add Global vars 
        Set-Variable WriteLog -Value $true -Scope Global -Force
        #Create Log Folder if not exists
        $LogPath = Create-LOGFolder -RootPath $ScriptPath
        $LogFilePath = ("{0}\azurereview.log" -f $LogPath)
        Set-Variable LogPath -Value $LogPath -Scope Global
        Set-Variable LogFilePath -Value $LogFilePath -Scope Global
        #If folder exists start logging
        if($LogPath){
            Start-Logging
        }
    }
    else{
        Set-Variable WriteLog -Value $false -Scope Global -Force        
    }
    #Check verbose options
    if($MyParams['Verbose']){
        $VerboseOptions=@{Verbose=$true}
    }
    else{
        $VerboseOptions=@{Verbose=$false}
    }
    #Check Debug options
    if($MyParams['Debug']){
        $VerboseOptions.Add("Debug",$true)
        $DebugPreference = 'Continue'
    }
    else{
        $VerboseOptions.Add("Debug",$false)
    }
    #Set global var
    Set-Variable VerboseOptions -Value $VerboseOptions -Scope Global -Force

    if($Analysis){
        #Declare array
        $Plugins=@()
        if ($Analysis.Contains("All")){
            $Plugins+= Get-ChildItem -Recurse ("{0}\{1}" -f $ScriptPath, "Plugins\*.ps1") `
                       | Where {$_.FullName -notlike "*\Custom\*"} | Select-Object FullName
        }
        else{
            foreach ($plugin in $Analysis){
                switch ($plugin) { 
                    'ActiveDirectory'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\ActiveDirectory\*.ps1" | Select-Object FullName
                    }
                    'DomainPolicies'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\ActiveDirectory\Policies\*.ps1" | Select-Object FullName
                    }
                    'Databases'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Databases\*.ps1" | Select-Object FullName
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\StorageAccounts\*.ps1" | Select-Object FullName
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Firewall\*.ps1" | Select-Object FullName
                    }
                    'VirtualMachines'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\VirtualMachines\*.ps1" | Select-Object FullName
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\ClassicVM\*.ps1" | Select-Object FullName
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\Patches\*.ps1" | Select-Object FullName
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\Baseline\*.ps1" | Select-Object FullName
                    }
                    'SecurityCenter'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\Patches\*.ps1" | Select-Object FullName
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\SecurityStatus\*.ps1" | Select-Object FullName
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\Baseline\*.ps1" | Select-Object FullName
                    }
                    'RoleAssignments'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\RoleAssignments\*.ps1" | Select-Object FullName
                    }
                    'Firewall'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Firewall\*.ps1" | Select-Object FullName
                    }
                    'SecurityPolicies'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\SecurityPolicies\*.ps1" | Select-Object FullName
                    }
                    'MissingPatches'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\Patches\*.ps1" | Select-Object FullName
                    }
                    'SecurityBaseline'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\Baseline\*.ps1" | Select-Object FullName
                    }
                    'SecurityContacts'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\SecurityContacts\*.ps1" | Select-Object FullName
                    }
                    'SecurityAlerts'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Alerts\*.ps1" | Select-Object FullName
                    }
                    'AppServices'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\AppServices\*.ps1" | Select-Object FullName
                    }
                    'DocumentDB'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\DocumentDB\*.ps1" | Select-Object FullName
                    }
                    'StorageAccounts'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\StorageAccounts\*.ps1" | Select-Object FullName
                    }
                    'Web Application Firewall'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Security\WAF\*.ps1" | Select-Object FullName
                    }
                    'Custom'
                    {
                        $Plugins+= Get-ChildItem -Recurse "$ScriptPath\Plugins\Custom\*.ps1" | Select-Object FullName
                    }
                }
            }
        }
    }
    #Force Auth. Only valid for legacy user and password flow
    if($MyParams['ForceAuth']){
        $ForceAuth = $true
        $Interactive = $true
        Clear-AzAuth
        Clear-AzADALATokenCacheForAllAuthorities
    }
    else{
        $ForceAuth = $false
        $MyParams['Interactive'] = $false
    }
    #---------------------------------------------------
    # Set Global Vars
    #---------------------------------------------------
    if($MyParams['TenantID']){
        Set-Variable TenantID -Value $MyParams['TenantID'] -Scope Global -Force
    }
    else{
        Set-Variable TenantID -Value $false -Scope Global -Force
    }
    Set-Variable Subscription -Value $false -Scope Global -Force
    Set-Variable LoggedInUser -Value $false -Scope Global -Force
    Set-Variable ScriptPath -Value $MyParams -Scope Global -Force
    Set-Variable AuditorName -Value $AuditorName -Scope Global
    #############################################################
    
    $getConfigArgs = @{Environment = $Environment;
                       AuthMode = $AuthMode;
                       cachedCredential =$TmpToken;
                       TenantID = $TenantID;
                       ApplicationID = $ApplicationId;
                       Certificate = $Certificate;
                       CertFilePassword = $CertFilePassword;
                       ForceAuth =$ForceAuth;}
    
    #$passOptions and connect to Azure
    Get-AzADALToken @getConfigArgs
    
    #Check for permissions
    $user_permissions = Get-AzUserPermissions -CurrentUser
    if($user_permissions){
        #Save user_permissions to a var
        Set-Variable LoggedInUser -Value $user_permissions -Scope Global
        $MyMessage = ("Executing Azucar with user {0} which has the role {1} and {2}" `
                    -f $user_permissions.displayName, $user_permissions.roleName.ToLower(), `
                    $user_permissions.roleDescription.ToLower())

        Write-AzucarMessage -Message $MyMessage `
                            -Plugin Main -IsVerbose -Verbosity $Global:VerboseOptions `
                            -WriteLog $Global:WriteLog
    }
    #Create an Azure Object and add elements
    $AzureObject = New-AzureObject
    #Add plugins path
    $AzureObject | Add-Member -type NoteProperty -name AzureAPI -value $AzureAPI
    #Add AADConfig
    $AzureObject | Add-Member -type NoteProperty -name AzureConfig -value $AzureConfig
    #Add utils
    $AzureObject | Add-Member -type NoteProperty -name Utils -value $Utils
    #Add verbose option
    $AzureObject | Add-Member -type NoteProperty -name Verbose -value $MyParams['Verbose']
    #Add Localized file
    $AzureObject | Add-Member -type NoteProperty -name LocalizedDataParams -value $LocalizedDataParams
    if($Global:AzureConnections.ResourceManager -ne $null -AND $Global:AzureConnections.ResourceManager.SubscriptionId -ne $null){
        Write-AzucarMessage -Message ($message.RetrieveResourceGroups -f $Global:Subscription.subscriptionId)`
                            -Plugin Main -IsVerbose -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
        $AllRG = Get-AzSecRMObject -Instance $Environment -Authentication $Global:AzureConnections.ResourceManager`
                 -Objectype "resourcegroups" -APIVersion "2014-01-01" -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
        
        #Resource groups with the following format:
        #@{id=/subscriptions/000000-00000-00000-0000/resourceGroups/myresourcename; name=myresourcename; location=westeurope; properties=}
        #$ResourceGroupNames = $AllRM | Select-Object -ExpandProperty Name
        if($AllRG){
            $AzureObject | Add-Member -type NoteProperty -name ResourceGroups -value $AllRG            
        }
        #Get all resources within subscription
        $All_Azure_Resources = Get-AzSecRMObject -Instance $Environment `
                                                 -Authentication $Global:AzureConnections.ResourceManager`
                                                 -Objectype "resources" -APIVersion "2015-01-01" `
                                                 -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
        if($All_Azure_Resources){
            $AzureObject | Add-Member -type NoteProperty -name AzureResources -value $All_Azure_Resources            
        }
    }
    else{
        $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception($message.ResourceGroupsRetrieveError)),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                        )
        Convert-Exception -MyError $ErrorRecord -FunctionName "Main" -WriteLog $Global:WriteLog
        continue
    }  
}
Process{
    if($Global:Subscription){
        #Populate jobs with plugins 
        $AllAzureData = Get-RunSpaceAzucarObject -Plugins $Plugins -AzureObject $AzureObject -Throttle $Threads

        #Prepare data and export results to multiple formats
        if($MyParams['ExportTo']){
            if($AllAzureData){
                if($ExportTo -ne "print"){
                    Write-AzucarMessage -Message $message.ReportFolderInitMessage -Plugin Main -IsVerbose -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
			        $ReportPath = New-Report $ScriptPath $Domain.name
			        Set-Variable -Name Report -Value $ReportPath -Scope Global
			        Write-AzucarMessage -Message ($message.ReportFolderMessageCreation -f $Report) -Plugin Main -IsVerbose -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
                }
                $ExportTo | %{$Output = $_.split(",");
                                Export-ResultQuery -Dataset $AllAzureData -ExportTo $Output[0]
                }                
            }
        }
    } 
}

End{
    #End main script. Remove Vars
    try{
        Remove-Variable -Name WriteLog -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name LogPath -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name LogFilePath -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name Subscription -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name TenantID -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name AADAuth -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name ResourceManager -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name ServiceManagement -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name Report -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name AzureConnections -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name LoggedInUser -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name VerboseOptions -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name Authentication -Force -ErrorAction SilentlyContinue -Scope Global
    }
    catch{
        #Nothing to do here
    }
    #If folder exists stop logging
    if($LogPath){
        Stop-Logging
    }
    #Back to DebugPreference
    $DebugPreference = 'SilentlyContinue';
    #Stop timer
    $stoptimer = Get-Date
    $elapsedTime =  [math]::round(($stoptimer – $starttimer).TotalMinutes , 2)
    Write-AzucarMessage -Message ($message.TimeElapsedScript -f $elapsedTime) -Plugin Main -IsHost -Color Green
}
