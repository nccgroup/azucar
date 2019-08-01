#Plugin extract Network Security Rules from Azure
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
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AzureNSGConfig = $AzureObject.AzureConfig.NetworkSecurityGroup
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Network Security Rules", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All NSGs
        $NSGs= Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                 -Provider $AzureNSGConfig.Provider -Objectype "networkSecurityGroups" `
                                 -APIVersion $AzureNSGConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllNSGRules = @()
        if($NSGs){
            foreach($nsg in $NSGs){
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Getting security rules for {0}..." -f $nsg.name) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                #Getting all Security Rules
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Found {0} security rules for {1}..." -f $nsg.properties.securityrules.count, $nsg.name) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                foreach ($sr in $nsg.properties.securityrules){
                    $SecurityRule = New-Object -TypeName PSCustomObject
                    $SecurityRule | Add-Member -type NoteProperty -name name -value $nsg.name
                    $SecurityRule | Add-Member -type NoteProperty -name location -value $nsg.location
                    $SecurityRule | Add-Member -type NoteProperty -name ResourceGroupName -value $nsg.id.Split("/")[4]
                    #Getting interfaces names
                    $AllInterfaces =  @()
                    foreach($interface in $nsg.properties.networkinterfaces){
                        $Ifacename = $interface.id.Split("/")[8]
                        $AllInterfaces+=$Ifacename
                    }
                    if($AllInterfaces){
                        $SecurityRule | Add-Member -type NoteProperty -name RulesAppliedOn -value (@($AllInterfaces) -join ',')
                    }
                    $SecurityRule | Add-Member -type NoteProperty -name Rulename -value $sr.name
                    $SecurityRule | Add-Member -type NoteProperty -name RuleDescription -value $sr.properties.description
                    $SecurityRule | Add-Member -type NoteProperty -name Protocol -value $sr.properties.protocol
                    $SecurityRule | Add-Member -type NoteProperty -name SourcePortRange -value $sr.properties.sourcePortRange
                    $SecurityRule | Add-Member -type NoteProperty -name DestinationPortRange -value $sr.properties.DestinationPortRange
                    $SecurityRule | Add-Member -type NoteProperty -name SourceAddressPrefix -value $sr.properties.sourceAddressPrefix
                    $SecurityRule | Add-Member -type NoteProperty -name DestinationAddressPrefix -value $sr.properties.DestinationAddressPrefix
                    $SecurityRule | Add-Member -type NoteProperty -name Access -value $sr.properties.access
                    $SecurityRule | Add-Member -type NoteProperty -name Priority -value $sr.properties.priority
                    $SecurityRule | Add-Member -type NoteProperty -name direction -value $sr.properties.direction  
                
                    $AllNSGRules+=$SecurityRule              
                }
                #Getting all default security rules
                foreach ($dsr in $nsg.properties.defaultSecurityRules){
                    $DefaultSecurityRule = New-Object -TypeName PSCustomObject
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name name -value $nsg.name
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name location -value $nsg.location
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name ResourceGroupName -value $nsg.id.Split("/")[4]
                    #Getting interfaces names
                    $AllInterfaces =  @()
                    foreach($interface in $nsg.properties.networkinterfaces){
                        $Ifacename = $interface.id.Split("/")[8]
                        $AllInterfaces+=$Ifacename
                    }
                    if($AllInterfaces){
                        $DefaultSecurityRule | Add-Member -type NoteProperty -name RulesAppliedOn -value (@($AllInterfaces) -join ',')
                    }
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name Rulename -value $dsr.name
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name RuleDescription -value $dsr.properties.description
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name Protocol -value $dsr.properties.protocol
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name SourcePortRange -value $dsr.properties.sourcePortRange
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name DestinationPortRange -value $dsr.properties.DestinationPortRange
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name SourceAddressPrefix -value $dsr.properties.sourceAddressPrefix
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name DestinationAddressPrefix -value $dsr.properties.DestinationAddressPrefix
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name Access -value $dsr.properties.access
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name Priority -value $dsr.properties.priority
                    $DefaultSecurityRule | Add-Member -type NoteProperty -name direction -value $dsr.properties.direction
                
                    $AllNSGRules+=$DefaultSecurityRule                
                } 
            }
        }
    }
    End{
        if($AllNSGRules){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllNSGRules
            $AllNSGRules.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.NetworkSecurityRules')
            #Create custom object for store data
            $NSGRules = New-Object -TypeName PSCustomObject
            $NSGRules | Add-Member -type NoteProperty -name Section -value $Section
            $NSGRules | Add-Member -type NoteProperty -name Data -value $AllNSGRules
            #Add data to object
            if($NSGRules){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_network_security_rules -value $NSGRules
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Network Security Rules", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }