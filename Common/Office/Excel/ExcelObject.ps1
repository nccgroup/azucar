#---------------------------------------------------
# Release Excel Objects
#---------------------------------------------------
function Release-Reference(){
    
    #Release each Reference object
    foreach ( $reference in $args ) { 
        try{ 
            ([System.Runtime.InteropServices.Marshal]::ReleaseComObject( 
            [System.__ComObject]$reference) -gt 0) | Out-Null
            [System.GC]::Collect() | Out-Null
            [System.GC]::WaitForPendingFinalizers() |Out-Null
        }
        catch{
            Continue
        }  
    }  
}

#---------------------------------------------------
# Function to create OBJ Excel
#---------------------------------------------------

function Release-ExcelObject{
    Begin{
        $Excel.DisplayAlerts = $false
		$Excel.ActiveWorkBook.Close | Out-Null
		$Excel.Quit()
    }
    Process{
        #[System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$WorBook) | Out-Null
		[System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$WorkSheet) | Out-Null
		[System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$Excel) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$WorkBook) | Out-Null
    }
    End{
        $Excel = $null
		$WorkBook = $null
        #Remove vars
        remove-item -Path "variable:Excel" -Force -ErrorAction SilentlyContinue
        remove-item -Path "variable:WorkBook" -Force -ErrorAction SilentlyContinue
		[GC]::Collect() 
		[GC]::WaitForPendingFinalizers()
    }
}

#---------------------------------------------------
# Function to create OBJ Excel
#---------------------------------------------------

function Create-Excel{
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$false, HelpMessage="Excel Debug")]
        [Alias('OpenExcel')]
        [Bool]$ExcelDebugging = $false
    )
    Begin{
        try{
            #Add Types
		    Add-Type -AssemblyName Microsoft.Office.Interop.Excel -ErrorAction SilentlyContinue
            #Get PID for each Excel opened instance
            $priorExcelProcesses = Get-Process -name "*Excel*" | % { $_.Id }
            #Create Excel 
	        [Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
	        $Excel = new-object -com Excel.Application
	        $Excel.visible = $ExcelDebugging
            $postExcelProcesses = Get-Process -name "*Excel*" | % { $_.Id }

        }
        catch{
            $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception("Unable to Create Excel COM Object....")),
                           $null,
                           [System.Management.Automation.ErrorCategory]::ReadError,
                           $null
                        )
            Convert-Exception -MyError $ErrorRecord -FunctionName "Create-Excel" -WriteLog $Global:WriteLog
        }
    }
    Process{
        $objWorkBook = $Excel.WorkBooks.Add()
        if($Excel.Version -le "14.0"){
            #Delete sheets for Office 2010
            1..2 | ForEach {
	            $objWorkbook.WorkSheets.Item($_).Delete()
		    }
        }
    }
    End{
        #Create global vars for Excel formatting
        Set-Variable Excel -Value $Excel -Scope Global -Force
        Set-Variable WorkBook -Value $objWorkBook -Scope Global -Force
        Set-Variable priorExcelProcesses -Value $priorExcelProcesses -Scope Global -Force
        Set-Variable postExcelProcesses -Value $postExcelProcesses -Scope Global -Force
    }	
}

#---------------------------------------------------
# Function to Get Excel Language settings
#---------------------------------------------------
function Get-ExcelLanguage{
    Begin{
        #Define constant
        $msoLanguageIDUI = 2
        $EnglishLanguage = 1033
    }
    Process{
        if($Excel){
            $LCID = $Excel.LanguageSettings.LanguageID($msoLanguageIDUI)
            if($LCID){
                return $LCID
            }
            else{
                Write-Host "No language detected... Try with English language...." -ForegroundColor Yellow
                return $EnglishLanguage
            }
        }
    }
    End{
        #Nothing to do here
    }
}

#---------------------------------------------------
# Function to create WorkSheet
#---------------------------------------------------

function Create-WorkSheet{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('SheetName')]
        [String]$Title
    )
    Begin{
        $WorkSheet = $WorkBook.Worksheets.Add()
	    $WorkSheet.Activate() | Out-Null
    }
    Process{
        $WorkSheet.Name = $Title
	    $WorkSheet.Select()
	    $Excel.ActiveWindow.Displaygridlines = $false 
    }
	End{
        Set-Variable WorkSheet -Value $WorkSheet -Scope Global -Force
    }
}

#---------------------------------------------------
# Function to create table through CSV data
#---------------------------------------------------

function Create-CSV2Table{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('MyData')]
        [Object]$Data,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('SheetName')]
        [String]$Title,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('TableName')]
        [String]$TableTitle,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Style')]
        [String]$TableStyle,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('ColumnName')]
        [String]$iconColumnName,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('TableIsFreeze')]
        [Bool]$isFreeze
    )
    Begin{
        if ($Data -ne $null){
            #Create tmp file and store all content
            $CSVFile = ($env:temp + "\" + ([System.Guid]::NewGuid()).ToString() + ".csv")
			$Data | Export-Csv -path $CSVFile -noTypeInformation
            #Create new Sheet in Excel
            Create-WorkSheet $Title
            #Define the connection string and where the data is supposed to go
			$TxtConnector = ("TEXT;" + $CSVFile)
			$CellRef = $worksheet.Range("A1")
            #Build, use and remove the text file connector
			$Connector = $worksheet.QueryTables.add($TxtConnector,$CellRef)
			$worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $True
			$worksheet.QueryTables.item($Connector.name).TextFileParseType  = 1
			$worksheet.QueryTables.item($Connector.name).Refresh()
			$worksheet.QueryTables.item($Connector.name).delete()
			$worksheet.UsedRange.EntireColumn.AutoFit()
            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange,`
                          $worksheet.UsedRange, $null,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes,$null) 
			$listObject.Name = $TableTitle
            if($TableStyle){
                # Style Cheat Sheet: https://msdn.microsoft.com/en-us/library/documentformat.openxml.spreadsheet.tablestyle.aspx
                # Table styles https://msdn.microsoft.com/en-us/library/office/dn535872.aspx
			    $listObject.TableStyle = $TableStyle
            }
            $worksheet.Activate();
			$worksheet.Application.ActiveWindow.SplitRow = 1;
			$worksheet.Application.ActiveWindow.FreezePanes = $isFreeze

        }
    }
    Process{
        #Remove Tmp file
        Remove-Item -Path $CSVFile -Force
        if($iconColumnName){
            #Add colors to ACL Column
            #Need to solve try catch
			Add-Icon -SheetName $Title -ColumnName $iconColumnName | Out-Null
        }
    }
    End{
        #Nothing to do here
    }
}

#---------------------------------------------------
# Function to release OBJ Excel
#---------------------------------------------------

function Release-ExcelObject{
    Begin{
        $Excel.DisplayAlerts = $false
		$Excel.ActiveWorkBook.Close | Out-Null
		$Excel.Quit()
    }
    Process{
        #[System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$WorBook) | Out-Null
		#[System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$WorkSheet) | Out-Null
		[System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$Excel) | Out-Null
    }
    End{
        $Excel = $null
		$WorkBook = $null
        #Remove vars
        remove-item -Path "variable:Excel" -Force -ErrorAction SilentlyContinue
        remove-item -Path "variable:WorkBook" -Force -ErrorAction SilentlyContinue
		[GC]::Collect() 
		[GC]::WaitForPendingFinalizers()
        #Clean up
        $postExcelProcesses | ? { $priorExcelProcesses -eq $null -or $priorExcelProcesses -notcontains $_ } | % { Stop-Process -Id $_ }
    }
}
		
#---------------------------------------------------
# Function to Save Excel
#---------------------------------------------------

function Save-Excel{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('RootPath')]
        [String]$Path
    )
    Begin{
        #Get Date
        $date = Get-Date -format "yyyyMMdd"
        $SaveExcelIn = "{0}\Azure_Report_{1}" -f $Path, $date
    }
    Process{
        # http://msdn.microsoft.com/en-us/library/bb241279.aspx 
        $WorkBook.SaveAs($SaveExcelIn,51) 
    }
    End{
        $WorkBook.Saved = $true
    }
}

#---------------------------------------------------
# Function Create Table
#---------------------------------------------------

function Create-Table{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Totals')]
        [Bool]$ShowTotals,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('MyData')]
        [Object]$Data,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddHeader')]
        [Object]$Header,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddSheetName')]
        [String]$SheetName,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddTableTitle')]
        [String]$TableTitle,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddFormatTable')]
        [String]$FormatTable,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddPosition')]
        [Object]$Position,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Headers')]
        [Bool]$ShowHeaders,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('isNewSheet')]
        [Bool]$NewSheet,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('isNewChart')]
        [Bool]$AddNewChart,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('NewchartType')]
        [String]$ChartType,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('MyHeaderStyle')]
        [String]$HeaderStyle,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('isDataTable')]
        [Bool]$HasDataTable,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('NewChartStyle')]
        [Int]$ChartStyle,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddChartTitle')]
        [String]$ChartTitle
    )
    Begin{
        
        if($NewSheet -and $SheetName){
            #Create new worksheet
            Create-WorkSheet -SheetName $SheetName
        }
        $Cells = $WorkSheet.Cells
		$Row=$Position[0]
		$InitialRow = $Row
		$Col=$Position[1]
		$InitialCol = $Col
        #Check for headers
        if ($Header){
            #insert column headings
			$Header | foreach{
    					$cells.item($row,$col)=$_
    					$cells.item($row,$col).font.bold=$True
    					$Col++
			}
		}
        # Add table content
		foreach ($Key in $Data.Keys){
            $Row++
	    	$Col = $InitialCol
	    	$cells.item($Row,$Col) = $Key
            $nbItems = $Data[$Key].Count
            for ( $i=0; $i -lt $nbItems; $i++ ){
				$Col++
	    		$cells.item($Row,$Col) = $Data[$Key][$i]
	    		$cells.item($Row,$Col).NumberFormat ="0"
			}
        }	
    }
    Process{
        # Apply Styles to table
		$Range = $WorkSheet.Range($WorkSheet.Cells.Item($InitialRow,$InitialCol),$WorkSheet.Cells.Item($Row,$Col))
		$listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $Range, $null,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes,$null) 
		$listObject.Name = $TableTitle
		$listObject.ShowTotals = $ShowTotals
		$listObject.ShowHeaders = $ShowHeaders
        # Style Cheat Sheet: https://msdn.microsoft.com/en-us/library/documentformat.openxml.spreadsheet.tablestyle.aspx
        # Table styles https://msdn.microsoft.com/en-us/library/office/dn535872.aspx
		$listObject.TableStyle = $FormatTable 

        # Sort data based on the 2nd column
        $MyPosition = $WorkSheet.Cells.Item($InitialRow+1,$InitialCol+1).Address($False,$False)
		$SortRange = $WorkSheet.Range($MyPosition) # address: Convert cells position 1,1 -> A:1
		$WorkSheet.Sort.SortFields.Clear()
		[void]$WorkSheet.Sort.SortFields.Add($SortRange,0,1,0)
		$WorkSheet.Sort.SetRange($Range)
		$WorkSheet.Sort.Header = 1 # exclude header
		$WorkSheet.Sort.Orientation = 1
		$WorkSheet.Sort.Apply()

        # Apply Styles to Title
		$cells.item(1,$InitialCol) = $TableTitle
		$RangeTitle = $WorkSheet.Range($WorkSheet.Cells.Item(1,$InitialCol),$WorkSheet.Cells.Item(1,$Col))
		#$RangeTitle.MergeCells = $true
		$RangeTitle.Style = $HeaderStyle
		# http://msdn.microsoft.com/en-us/library/microsoft.office.interop.excel.constants.aspx
		$RangeTitle.HorizontalAlignment = -4108
		$RangeTitle.ColumnWidth = 20
    }
    End{
        #Add chart
        if($AddNewChart -and $ChartType){
            Create-MyChart -DataRange $Range -ChartType $ChartType `
            -ChartTitle $ChartTitle -HasDataTable $HasDataTable `
            -Style $ChartStyle -ChartRange $Position | Out-Null
        }
    }
}
		
		
#---------------------------------------------------
# Create a chart in Excel
# http://www.alexwinner.com/articles/powershell/115-posh-excel-part4.html
#---------------------------------------------------
function Create-MyChart{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('MyDataRange')]
        [Object]$DataRange,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddChartType')]
        [String]$chartType,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddDataTable')]
        [Bool]$HasDataTable,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AddStyle')]
        [Int]$Style,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('MyTitle')]
        [String]$ChartTitle,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('ChartRange')]
        [Object]$Position
    )
    Begin{
        #Add Types
		Add-Type -AssemblyName Microsoft.Office.Interop.Excel
		$MyChartType=[Microsoft.Office.Interop.Excel.XLChartType]$chartType
        # Add the chart
	    $Chart = $WorkSheet.Shapes.AddChart().Chart
	    $Chart.ChartType = $MyChartType
	    #$Chart | gm
    }
    Process{
            # Apply a specific style for each type
	        If( $ChartType -like "xlPie" ){	
		        $Chart.ApplyLayout(2,$Chart.ChartType)
		        $Chart.Legend.Position = -4107
		        if ( $ChartTitle ){
				    $Chart.HasTitle = $true
				    $Chart.ChartTitle.Text = $ChartTitle
                }
		        # http://msdn.microsoft.com/fr-fr/library/microsoft.office.interop.excel._chart.setsourcedata(v=office.11).aspx
		        $Chart.SetSourceData($DataRange)
	        }
            else{	
		        $Chart.SetSourceData($DataRange,[Microsoft.Office.Interop.Excel.XLRowCol]::xlRows)
		
		        # http://msdn.microsoft.com/en-us/library/office/bb241345(v=office.12).aspx
		        $Chart.Legend.Position = -4107
		        $Chart.ChartStyle = $Style
		        $Chart.ApplyLayout(2,$Chart.ChartType)
		        if ($HasDataTable){
			        $Chart.HasDataTable = $true
			        $Chart.DataTable.HasBorderOutline = $true

                    $NbSeries = $Chart.SeriesCollection().Count
		
		            # Define data labels
		            for ( $i=1 ; $i -le $NbSeries; ++$i ){
			            $Chart.SeriesCollection($i).HasDataLabels = $true
			            $Chart.SeriesCollection($i).DataLabels(0).Position = 3
                    }
                }
		
		        $Chart.HasAxis([Microsoft.Office.Interop.Excel.XlAxisType]::xlCategory) = $false
		        $Chart.HasAxis([Microsoft.Office.Interop.Excel.XlAxisType]::xlValue) = $false
		        if ( $ChartTitle ){
			        $Chart.HasTitle = $true
			        $Chart.ChartTitle.Text = $ChartTitle
			    }
	        }
    }
    End{
        #Extract Row $ Col
        $Row=$Position[0]
        $Col = $Position[1]

        $ChartRange = $WorkSheet.Range($WorkSheet.Cells.Item(1,$col),$WorkSheet.Cells.Item(18,6))

        # Define the position of the chart
	    $ChartObj = $Chart.Parent

        $ChartObj.Height = $DataRange.Height * 4
	    $ChartObj.Width = $DataRange.Width + 100 

        $ChartObj.Top = $DataRange.Top
	    $ChartObj.Left = $DataRange.Left

        #Save image
        If($saveImage){
		    $ImageFile = ($env:temp + "\" + ([System.Guid]::NewGuid()).ToString() + ".png")
			$Chart.Export($ImageFile)
			return $ImageFile
		}
    }
}

#---------------------------------------------------
# Read Headers in Excel
# Return Hash Table of each cell
#---------------------------------------------------

Function Read-Headers{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Sheet')]
        [Object]$MyWorkSheet
    )
    Begin{
        $Headers =@{}
        $column = 1
    }
    Process{
        Do {
            $Header = $MyWorkSheet.cells.item(1,$column).text
            If ($Header) {
                $Headers.add($Header, $column)
                $column++
            }
        } until (!$Header)
    }
    End{
        return $Headers
    }
}

#---------------------------------------------------
# Format Cells
# Add Icon format for each ACL value
#---------------------------------------------------

Function Add-Icon{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Sheet')]
        [String]$SheetName,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Column')]
        [String]$ColumnName
    )
    Begin{
        #Charts Variables
		$xlConditionValues=[Microsoft.Office.Interop.Excel.XLConditionValueTypes]
		$xlIconSet=[Microsoft.Office.Interop.Excel.XLIconSet]
		$xlDirection=[Microsoft.Office.Interop.Excel.XLDirection]
		$MyWorkSheet = $Excel.WorkSheets.Item($SheetName)
		$Headers = Read-Headers $MyWorkSheet
    }
    Process{
        #Add Icons
        try{
		    $range = [char]($Headers[$ColumnName]+64)
		    $start=$WorkSheet.range($range+"2")
		    #get the last cell
		    $Selection=$WorkSheet.Range($start,$start.End($xlDirection::xlDown))
        }
        catch{
            Write-Host "[Azucar problem][Function Add-Icon]...$($_.Exception)" -ForegroundColor Red
            break
        }
    }
    End{
        #add the icon set
		$Selection.FormatConditions.AddIconSetCondition() | Out-Null
		$Selection.FormatConditions.item($($Selection.FormatConditions.Count)).SetFirstPriority()
		$Selection.FormatConditions.item(1).ReverseOrder = $True
		$Selection.FormatConditions.item(1).ShowIconOnly = $True
		$Selection.FormatConditions.item(1).IconSet = $xlIconSet::xl3TrafficLights1
		$Selection.FormatConditions.item(1).IconCriteria.Item(2).Type=$xlConditionValues::xlConditionValueNumber
		$Selection.FormatConditions.item(1).IconCriteria.Item(2).Value=60
		$Selection.FormatConditions.item(1).IconCriteria.Item(2).Operator=7
		$Selection.FormatConditions.item(1).IconCriteria.Item(3).Type=$xlConditionValues::xlConditionValueNumber
		$Selection.FormatConditions.item(1).IconCriteria.Item(3).Value=90
		$Selection.FormatConditions.item(1).IconCriteria.Item(3).Operator=7
    }

}

#---------------------------------------------------
# Create Report Index
# Function to create report index with HyperLinks
#---------------------------------------------------

Function Create-Index{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Settings')]
        [Object]$ExcelSettings
    )
    Begin{
        #Set Constants
        Set-Variable msoFalse 0 -Option Constant -ErrorAction SilentlyContinue
        Set-Variable msoTrue 1 -Option Constant -ErrorAction SilentlyContinue

        Set-Variable cellWidth 48 -Option Constant -ErrorAction SilentlyContinue
        Set-Variable cellHeight 15 -Option Constant -ErrorAction SilentlyContinue

        $CompanyLogo = ("{0}\{1}" -f $ScriptPath, $ExcelSettings.excelSettings.CompanyLogoFront)
        $CompanyLogoTopLeft = ("{0}\{1}" -f $ScriptPath, $ExcelSettings.excelSettings.CompanyUserTopLeft)
    }
    Process{
        try{
            #Main Report Index		
		    $row = 07
		    $col = 1
		    $WorkSheet = $WorkBook.WorkSheets.Add()
		    $WorkSheet.Name = "Index"
		    $WorkSheet.Tab.ColorIndex = 8
            foreach ($Sheet in $WorkBook.WorkSheets){
				#$v = $WorkSheet.Hyperlinks.Add($WorkSheet.Cells.Item($row,$col),"","'$($_.Name)'"+"!$($r)","","$($_.Name)")
                $v = $WorkSheet.Hyperlinks.Add($WorkSheet.Cells.Item($row,$col),"","'$($Sheet.Name)'"+"!A1","",$Sheet.Name)
				$row++
            }
            $CellRange = $WorkSheet.Range("A1:A40")
		    #$CellRange.Interior.ColorIndex = 9
		    $CellRange.Font.ColorIndex = 9
            $CellRange.Font.Size = 14
		    $CellRange.Font.Bold = $true
		    $WorkSheet.columns.item("A").EntireColumn.AutoFit() | out-null
		    $Excel.ActiveWindow.Displaygridlines = $false
        }
        catch{
            Write-Host "[Azucar Excel problem][Function Create-Index]...$($_.Exception)" -ForegroundColor Red
        }
        
        # add image to the Sheet
        #Image format and properties        
        $LinkToFile = $msoFalse
        $SaveWithDocument = $msoTrue
        $Left = 370
        $Top = 150
        $Width = 400
        $Height = 102
        $img = $WorkSheet.Shapes.AddPicture($CompanyLogo, $LinkToFile, $SaveWithDocument,
                                     $Left, $Top, $Width, $Height)

        # add image to the Sheet
        #Image format and properties        
        $LinkToFile = $msoFalse
        $SaveWithDocument = $msoTrue
        $Left = 0
        $Top = 0
        $Width = 70
        $Height = 70
        $img = $WorkSheet.Shapes.AddPicture($CompanyLogoTopLeft, $LinkToFile, $SaveWithDocument,
                                     $Left, $Top, $Width, $Height)

        #Add AuditorName
        $WorkSheet.Cells.Item(5,1).Value() = $AuditorName
        $WorkSheet.Cells.Item(5,1).Font.Bold = $true
		
        
    }
    End{
        #Nothing to do here
    }
}

#---------------------------------------------------
# Create About page
# Function to create About page with HyperLinks
#---------------------------------------------------
Function Create-About{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Settings')]
        [Object]$ExcelSettings
    )
    Begin{
        #Main Report Index
		[Void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
		$WorkSheet = $WorkBook.WorkSheets.Add()
		$WorkSheet.Name = "About"
		$WorkSheet.Cells.Item(1,1).Value() = $ExcelSettings["ReportName"]
		$WorkSheet.Cells.Item(1,1).Font.Size = 25
		$WorkSheet.Cells.Item(1,1).Font.Bold = $true
        $cnt = 1
        foreach ($webpage in $ExcelSettings.excelSettings.HyperLinkcompanyName){
		    $WorkSheet.Cells.Item(24+$cnt,4).Value() = $webpage
		    $r = $WorkSheet.Range("D"+(24+$cnt))
		    $v = $WorkSheet.Hyperlinks.Add($r,$webpage)
		    $WorkSheet.Cells.Item(24+$cnt,4).Font.Size = 14
		    $WorkSheet.Cells.Item(24+$cnt,4).Font.Bold = $true
            $cnt+=2
        }   
    }
    Process{
        #Set Constants
        Set-Variable msoFalse 0 -Option Constant -ErrorAction SilentlyContinue
        Set-Variable msoTrue 1 -Option Constant -ErrorAction SilentlyContinue

        Set-Variable cellWidth 48 -Option Constant -ErrorAction SilentlyContinue
        Set-Variable cellHeight 15 -Option Constant -ErrorAction SilentlyContinue

        $CompanyLogo = ("{0}\{1}" -f $ScriptPath,$ExcelSettings.excelSettings.CompanyLogo)
        #Image format and properties        
        $LinkToFile = $msoFalse
        $SaveWithDocument = $msoTrue
        $Left = 400
        $Top = 40
        $Width = 616
        $Height = 210

        # add image to the Sheet
        $img = $WorkSheet.Shapes.AddPicture($CompanyLogo, $LinkToFile, $SaveWithDocument,
                                     $Left, $Top, $Width, $Height)

        #Remove GridLines
        $Excel.ActiveWindow.Displaygridlines = $false
        $CellRange = $WorkSheet.Range("A1:G30")
        #Color palette
        #http://dmcritchie.mvps.org/excel/colors.htm
		#$CellRange.Interior.ColorIndex = 1
		$CellRange.Font.ColorIndex = 30
    }
    End{
        #Nothing to do here
    }
}