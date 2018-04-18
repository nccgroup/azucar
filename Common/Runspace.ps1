Function Get-RunSpaceAzucarObject
{
    [CmdletBinding()]
    Param
    (

        [Parameter(HelpMessage="Plugin to retrieve data",
                   Position=1)]
        [Array]
        $Plugins = $false,

        [Parameter(HelpMessage="Object with Azucar object valuable data")]
        [Object]
        $AzureObject = $false,
        
        [Parameter(HelpMessage="Maximum number of concurrent threads")]
        [ValidateRange(1,65535)]
        [int32]
        $Throttle = 5,
 
        [Parameter(HelpMessage="Timeout before a thread stops trying to gather the information")]
        [ValidateRange(1,65535)]
        [int32]
        $Timeout = 120,

        [Parameter(HelpMessage="Increase Sleep Timer in seconds between child objects")]
        [ValidateRange(1,65535)]
        [int32]
        $SleepTimer = 5,

        [Parameter(HelpMessage="Set this if you want run Single Query")]
        [switch]
        $SingleQuery
    )

    Begin{

        #Function Get-RunSpaceData
        #http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
        Function Get-RunspaceData{
            [cmdletbinding()]
            param(
                [switch]$Wait,
                [String]$message = "Running Jobs"
            )
            Do {
                $more = $false
                $i = 0
                $total = $runspaces.Count        
                Foreach($runspace in $runspaces){
                    $StartTime = $runspacetimers[$runspace.ID]
                    $i++
                    If ($runspace.Runspace.isCompleted) {
                        #Write-Host $runspace.PluginName -ForegroundColor Yellow
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null                
                    } ElseIf ($runspace.Runspace -ne $null) {
                        $more = $true
                    }
                    If ($more -AND $PSBoundParameters['Wait']) {
                        Start-Sleep -Milliseconds 100
                    } 
                }  
                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash | Where {
                    $_.runspace -eq $Null
                } | ForEach {
                    $Runspaces.remove($_)
                }  
                #Write-Progress -Activity $message -Status "Percent Complete" -PercentComplete $(($i/$total) * 100) 
            } while ($more -AND $PSBoundParameters['Wait'])
        }

        #Inicializar variables
        $SyncServer = [HashTable]::Synchronized(@{})
        $Global:ReturnServer = New-Object -TypeName PSCustomObject
        $runspacetimers = [HashTable]::Synchronized(@{})
        $runspaces = New-Object -TypeName System.Collections.ArrayList
        $Counter = 0
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($EntryVars in ('runspacetimers')){
            $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $EntryVars, (Get-Variable -Name $EntryVars -ValueOnly), ''))
        }
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.ApartmentState = 'STA'
        $runspacepool.ThreadOptions = "ReuseThread"
        $runspacepool.Open()
    }
    Process{
        If($Plugins -ne $false){
            foreach ($Plugin in $Plugins){
                #Add plugin data to AzureObject
                $PluginFullPath = $Plugin.FullName
                $ParentPluginFullPath = Split-Path $Plugin.FullName -Parent
                $PluginName = [io.path]::GetFileNameWithoutExtension($Plugin.FullName)
                #Get Directory Name
                $path = [System.IO.Path];
                $DirectoryName = $path::GetFileName($path::GetDirectoryName($ParentPluginFullPath))
                Write-AzucarMessage -Message ($message.AddAzucarPluginNameMessage -f $PluginName) -Plugin "Get-RunSpaceAzucarObject" `
                                    -IsVerbose -Verbosity $Global:VerboseOptions -WriteLog $Global:WriteLog
                $NewPlugin = $AzureObject | Select-Object *
                $NewPlugin | Add-Member -type NoteProperty -name PluginName -value $PluginName -Force
                $NewPlugin | Add-Member -type NoteProperty -name AzureSection -value $DirectoryName -Force
                #End plugin work
                $ScriptBlockPlugin = [ScriptBlock]::Create($(Get-Content $PluginFullPath | Out-String))
                $Counter++
                $PowerShell = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlockPlugin)
                $null = $PowerShell.AddParameter('bgRunspaceID',$Counter)
                $null = $PowerShell.AddParameter('SyncServer',$SyncServer)
                $null = $PowerShell.AddParameter('AzureObject',$NewPlugin)
                $null = $PowerShell.AddParameter('ReturnPluginObject',$ReturnServer)
                $null = $PowerShell.AddParameter('Verbosity',$Global:VerboseOptions)
                $null = $PowerShell.AddParameter('WriteLog',$Global:WriteLog)
                $PowerShell.RunspacePool = $runspacepool

                [void]$runspaces.Add(@{
                    runspace = $PowerShell.BeginInvoke()
                    PowerShell = $PowerShell
                    PluginName = $PluginName
                    ID = $Counter
                    })
            }
        }
        Get-RunspaceData -Wait
    }
    End{
        Get-RunspaceData -Wait
        $runspacepool.Close()
        $runspacepool.Dispose()
        #$SyncServer
        return $ReturnServer
    }
}


