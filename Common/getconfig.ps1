Function Get-AzSecConf{
    Param (
        [parameter(Mandatory=$true, HelpMessage="Path to Azucar config file")]
        [string]$Path,
        [parameter(Mandatory=$false, HelpMessage="Path to Azucar config file")]
        [string]$Node
    )
    Begin{
        Function Walk-AzSecNodes{
             Param (
                [parameter(Mandatory=$true, HelpMessage="Azucar xml config object")]
                [xml]$ConfigFile,

                [parameter(Mandatory=$true, HelpMessage="Azucar xml config object")]
                [string]$Xpath
            )
            Begin{
                #Declare PSCustomObject
                $AzureConfig = New-Object -TypeName PSCustomObject
                #$element = "AzureActiveDirectory"
            }
            Process{
                $AllElements = $ConfigFile.SelectNodes($Xpath.ToString()) | Select-Object -ExpandProperty ChildNodes
                if ($AllElements.haschildnodes -ne $false){
                    foreach ($Element in $AllElements){
                        #Declare HashTable
                        $appSettings = @{}
                        foreach ($subelelement in $Element.GetEnumerator()){
                            if ($subelelement.Value.Contains(‘,’)){
                                # Array case
                                $value = $subelelement.Value.Split(‘,’)
                                for ($i = 0; $i -lt $value.length; $i++){ 
                                    $value[$i] = $value[$i].Trim() 
                                }
                            }
                            else{
                                # Scalar case
                                $value = $subelelement.Value
                            }
                            $appSettings[$subelelement.Key] = $value
                        }
                        $AzureConfig | Add-Member -type NoteProperty -name $Element.name -value $appSettings -Force
                    }
                }
                else{
                    #Declare HashTable
                    $appSettings = @{}
                    if ($AllElements.Length -ge 0){
                        $AzureElement =  $AllElements[0].ParentNode.Name
                    }
                    else{
                        $AzureElement = $AllElements.ParentNode.Name
                    }
                    foreach ($SubElement in $AllElements){
                        if ($SubElement.value.Contains(',')){
                            # Array case
                            $value = $SubElement.Value.Split(‘,’)
                            for ($i = 0; $i -lt $value.length; $i++){ 
                                $value[$i] = $value[$i].Trim() 
                            }
                        }
                        else{
                            # Scalar case
                             $value = $SubElement.Value
                        }
                        $appSettings[$SubElement.Key] = $value
                    }
                    $AzureConfig | Add-Member -type NoteProperty -name $AzureElement -value $appSettings -Force
                }               
                
            }
            End{
                return $AzureConfig
            }
        }
        
    }
    Process{
        try{
            [xml]$config = Get-Content $Path.ToString()
            $XmlDict = Walk-AzSecNodes -ConfigFile $config -Xpath $Node
        }
        catch{
            $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception("Unable to open a valid configuration file located in $($Path))....")),
                           $null,
                           [System.Management.Automation.ErrorCategory]::InvalidResult,
                           $null
                        )
             Convert-Exception -MyError $ErrorRecord -FunctionName "Get-AzSecConf" -Print -WriteLog $Global:WriteLog            
        }
    }
    End{
        if($XmlDict){
            return $XmlDict
        }
        
    }      
}