#Get correct endpoints
#Same as command Get-AzureRmEnvironment
Function Get-AzSecEnvironment{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Endpoint = "AzureCloud"

        )
    #Export data
    switch ($Endpoint) { 
        'AzureCloud'
        {
            $AzureEndPoint = New-Object -TypeName PSCustomObject
            $AzureEndPoint | Add-Member -type NoteProperty -name Login -value "https://login.microsoftonline.com"
            $AzureEndPoint | Add-Member -type NoteProperty -name Graph -value "https://graph.windows.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name ResourceManager -value "https://management.azure.com/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Servicemanagement -value "https://management.core.windows.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name LogAnalytics -value "https://api.loganalytics.io/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Storage -value "https://storage.azure.com/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Vaults -value "https://vault.azure.net"
        }
        'PreProduction'
        {
            $AzureEndPoint = New-Object -TypeName PSCustomObject
            $AzureEndPoint | Add-Member -type NoteProperty -name Login -value "https://login.windows-ppe.net"
            $AzureEndPoint | Add-Member -type NoteProperty -name Graph -value "https://graph.ppe.windows.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name ResourceManager -value "https://api-current.resources.windows-int.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Servicemanagement -value "https://management.core.windows.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name LogAnalytics -value "https://api.loganalytics.io/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Storage -value "https://storage.azure.com/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Vaults -value "https://vault.azure.net"
        }
        'China'
        {
            $AzureEndPoint = New-Object -TypeName PSCustomObject
            $AzureEndPoint | Add-Member -type NoteProperty -name Login -value "https://login.chinacloudapi.cn"
            $AzureEndPoint | Add-Member -type NoteProperty -name Graph -value "https://graph.chinacloudapi.cn/"
            $AzureEndPoint | Add-Member -type NoteProperty -name ResourceManager -value "https://management.chinacloudapi.cn/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Servicemanagement -value "https://management.core.chinacloudapi.cn/"
            $AzureEndPoint | Add-Member -type NoteProperty -name LogAnalytics -value "https://api.loganalytics.io/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Storage -value "https://storage.azure.com/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Vaults -value "https://vault.azure.net"
        }
        'Government'
        {
            $AzureEndPoint = New-Object -TypeName PSCustomObject
            $AzureEndPoint | Add-Member -type NoteProperty -name Login -value "https://login-us.microsoftonline.com"
            $AzureEndPoint | Add-Member -type NoteProperty -name Graph -value "https://graph.windows.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name ResourceManager -value "https://management.usgovcloudapi.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Servicemanagement -value "https://management.core.usgovcloudapi.net/"
            $AzureEndPoint | Add-Member -type NoteProperty -name LogAnalytics -value "https://api.loganalytics.io/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Storage -value "https://storage.azure.com/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Vaults -value "https://vault.azure.net"
        }
        'Germany'
        {
            $AzureEndPoint = New-Object -TypeName PSCustomObject
            $AzureEndPoint | Add-Member -type NoteProperty -name Login -value "https://login.microsoftonline.de"
            $AzureEndPoint | Add-Member -type NoteProperty -name Graph -value "https://graph.cloudapi.de/"
            $AzureEndPoint | Add-Member -type NoteProperty -name ResourceManager -value "https://management.microsoftazure.de/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Servicemanagement -value "https://management.core.cloudapi.de/"
            $AzureEndPoint | Add-Member -type NoteProperty -name LogAnalytics -value "https://api.loganalytics.io/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Storage -value "https://storage.azure.com/"
            $AzureEndPoint | Add-Member -type NoteProperty -name Vaults -value "https://vault.azure.net"
        }
        'Default'
        {
            $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception("EndPoint $($Endpoint) not found")),
                           $null,
                           [System.Management.Automation.ErrorCategory]::InvalidResult,
                           $null
                        )
            Convert-Exception -MyError $ErrorRecord -FunctionName "Get-AzSecEnvironment" -Print -WriteLog $Global:WriteLog
            exit
        }
    }
    return $AzureEndPoint
}





