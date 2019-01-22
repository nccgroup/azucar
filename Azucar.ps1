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

This example retrieve information of an Azure Tenant and print results to a local variable. The script will try to connect using the ADAL library, and if no credential passed, the script will try to connect using the bearer token for logged user
	
.EXAMPLE
	.\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL

This example retrieve information of an Azure Tenant and export data driven to CSV, JSON, XML and Excel format into Reports folder. The script will try to connect using the ADAL library, and if no credential passed, the script will try to connect using the bearer token for logged user
	
.EXAMPLE
	$Azure = .\Azucar.ps1 -ExportTo PRINT -Verbose -Analysis ActiveDirectory

This example retrieve information of Active Directory in Azure Tenant and store all results in the $Azure var. 

.EXAMPLE
	.\Azucar.ps1 -ExportTo CSV -Verbose -Analysis ActiveDirectory,Databases,SecurityAlerts,Firewall

This example retrieve information of various assets of an Azure Tenant, including Active Directory, SQL Server, Security Alerts and Firewall. All information will be exported to CSV format. 
	
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

.PARAMETER WriteLog
	Write events to a log file

.PARAMETER ForceAuth
	Force script to Authenticate 

.PARAMETER ClearCache
	Clear Token Cache

.PARAMETER Threads
	Change the threads settings. By default, a large number of requests will be made with five threads
#>

[CmdletBinding()] 
param
(	

    [parameter(ValueFromPipelineByPropertyName=$true, Mandatory= $false, HelpMessage= "Select an instance of Azure services")]
    [ValidateSet("AzureCloud","Preproduction","China","AzureUSGovernment")]
    [String]$Instance= "AzureCloud",

    [parameter(ValueFromPipelineByPropertyName=$true, Mandatory= $false, HelpMessage= "Analyze Azure services")]
    [ValidateSet("ActiveDirectory","Databases","VirtualMachines", "SecurityAlerts", "SecurityCenter",
                 "RoleAssignments", "Firewall", "StorageAccounts","SecurityBaseline", "MissingPatches",
                 "Web Application Firewall", "SecurityPolicies", "SecurityContacts", "Custom", "AppServices", "DocumentDB", "All")]
    [Array]$Analysis=@("All"),

    [parameter(ValueFromPipelineByPropertyName=$true, Mandatory= $false, HelpMessage= "Export data to multiple formats")]
    [ValidateSet("CSV","JSON","XML","PRINT","EXCEL")]
    [Array]$ExportTo=@(),

    [Parameter(Mandatory=$false, HelpMessage="Change the threads settings. Default is 5")]
    [int32]
    $Threads = 5,

    [Parameter(Mandatory=$false, HelpMessage="Force Authentication Context")]
    [Switch]
    $ForceAuth,

    [Parameter(Mandatory=$false, HelpMessage="Clear token cache")]
    [Switch]
    $ClearCache,

    [Parameter(Mandatory=$false, HelpMessage="Write Log file")]
    [Switch]
    $WriteLog=$false,

    [Parameter(Mandatory=$false, HelpMessage="Auditor Name. Used in Excel File")]
	[String] $AuditorName = $env:username
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
    . $ScriptPath\Common\Office\Excel\ExcelObject.ps1
    . $ScriptPath\API\EndPoints\EndPoints.ps1
    . $ScriptPath\API\Auth\AzureAuth.ps1
    . $ScriptPath\API\Azure\API.ps1
    . $ScriptPath\Utils\Utils.ps1
    . $ScriptPath\Common\Runspace.ps1
    . $ScriptPath\Common\getconfig.ps1
    . $ScriptPath\Common\Functions.ps1
    . $ScriptPath\Utils\CsvReport.ps1
    . $ScriptPath\Utils\JsonReport.ps1
    . $ScriptPath\Utils\XmlReport.ps1
    . $ScriptPath\Utils\ExcelReport.ps1


    ## Import localisation strings
    $LocalizedDataParams = @{
    BindingVariable = 'message';
    FileName = 'Localized.psd1';
    BaseDirectory = "{0}\{1}" -f $ScriptPath, "Utils";
    }

    Import-LocalizedData @LocalizedDataParams;

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
        Set-Variable LogPath -Value $LogPath -Scope Global
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
    ###Check Internet Explorer Version
    #http://stackoverflow.com/questions/26024168/how-to-check-the-version-number-of-internet-explorer-com-object
    $IEVersion = New-Object -TypeName System.Version -ArgumentList (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer').Version
    $ieVersion = New-Object -TypeName System.Version -ArgumentList (
                                                                    # switch major and minor
                                                                   $ieVersion.Minor, $ieVersion.Major, $ieVersion.Build, $ieVersion.Revision)

    if ($ieVersion.Major -lt 11){
        $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception($message.InvalidIEVersion -f $ieVersion)),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                        )
        Convert-Exception -MyError $ErrorRecord -FunctionName "Main" -WriteLog $Global:WriteLog
        #Exit script
        exit
    }

    ####Check Powershell and .NET Version
    #Get PS and .NET version of config file
    if($PSVersionTable.PSVersion.Major -le 2){
        $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception($message.InvalidPowerShellVersion)),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                        )
        Convert-Exception -MyError $ErrorRecord -FunctionName "Main" -WriteLog $Global:WriteLog
        #Exit script
        exit
    }
    $Requirements = Get-AzSecConf -path "$($ScriptPath)\Config\Azucar.config" -Node "//requirements"
    if($PSVersionTable.PSVersion.Major -lt $Requirements.requirements.psversion){
        $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception($message.GenericPowerShellErrorVersion)),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                        )
        Convert-Exception -MyError $ErrorRecord -FunctionName "Main" -WriteLog $Global:WriteLog
        #Exit script
        exit
    }
    #Check .NET 4.5 Version
    $Version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue
    if($version.Release -lt $Requirements.requirements.netversion){
        $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception($message.InvalidNETVersion)),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                        )
        Convert-Exception -MyError $ErrorRecord -FunctionName "Main" -WriteLog $Global:WriteLog
        #Exit script
        exit
    }
    #Check Default Browser
    $Browser = Get-DefaultBrowser
    #Set global var
    Set-Variable DefaultBrowser -Value $Browser -Scope Global -Force
    #Add IE to the Default Browser Choice
    Set-DefaultBrowser -IE
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
    #Check Token Bearer for cleaning
    if($MyParams['ForceAuth']){
        $ForceAuth = $true
    }
    else{
        $ForceAuth = $false
    }
    #---------------------------------------------------
    # Set Global Vars
    #---------------------------------------------------
    Set-Variable Subscription -Value $false -Scope Global -Force
    Set-Variable TenantID -Value $false -Scope Global -Force
    Set-Variable LoggedUser -Value $false -Scope Global -Force
    Set-Variable ScriptPath -Value $MyParams -Scope Global -Force
    Set-Variable AuditorName -Value $AuditorName -Scope Global
    #############################################################
    
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
    $AzureAPI = Get-ChildItem -Recurse "$ScriptPath\API\Azure\*.ps1" | Select -ExpandProperty FullName
    #Load Utils
    $Utils = Get-ChildItem -Recurse "$ScriptPath\Utils\Utils.ps1" | Select -ExpandProperty FullName
    #Connect to Azure
    ConnectTo-Azure -Instance $Environment -ForceAuth $ForceAuth
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
    }
    else{
        $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception($message.ResourceGroupsRetrieveError -f $LoggedUser)),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                        )
        Convert-Exception -MyError $ErrorRecord -FunctionName "Main" -WriteLog $Global:WriteLog
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
    #> 
}

End{
    #End main script. Remove Vars
    try{
        Remove-Variable -Name $Global:WriteLog -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:LogPath -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:Subscription -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:TenantID -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:AADAuth -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:ResourceManager -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:ServiceManagement -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:TenantID -Force -ErrorAction SilentlyContinue -Scope Global -Scope Global
        Remove-Variable -Name $Global:Subscription -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:Report -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:AzureConnections -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:LoggedUser -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:VerboseOptions -Force -ErrorAction SilentlyContinue -Scope Global
        Remove-Variable -Name $Global:Authentication -Force -ErrorAction SilentlyContinue -Scope Global
    }
    catch{
        #Nothing to do here
    }

    #Get Token Cache clearing
    if($MyParams['ClearCache']){
        Clear-AzAuth
    }
    #If folder exists stop logging
    if($LogPath){
        Stop-Logging
    }
    #Back to the preferred browser
    Set-defaultBrowser -defaultBrowser $DefaultBrowser
    #Back to DebugPreference
    $DebugPreference = 'SilentlyContinue';
    #Stop timer
    $stoptimer = Get-Date
    $elapsedTime =  [math]::round(($stoptimer – $starttimer).TotalMinutes , 2)
    Write-AzucarMessage -Message ($message.TimeElapsedScript -f $elapsedTime) -Plugin Main -IsHost -Color Green
}
