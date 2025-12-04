Function Get-MagicDeckStats {
<#
.SYNOPSIS
Calculates and displays statistics for MTG deck list.

.DESCRIPTION
Calculates and displays statistics for MTG deck list.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2025.11.25 by DS :: First revision. Needs work, but functions.
	V02: 2025.11.26 by DS :: Better decklist format handling (tabs and 'x').
	V03: 2025.11.27 by DS :: Added 'SampleHand' function.
	V04: 2025.12.04 by DS :: Added logic for .cod (cockatrice xml).
Call From:
    Windows PowerShell v5.1 or Microsoft PowerShell v7.x

.INPUTS
None

.OUTPUTS
None

.PARAMETER DeckList
Path to cockatrice *.cod file or plain text (*.dec, *.dek, *.txt) file ie;
	4 Lightning Bolt
	4x Shock
	4	Rift Bolt
	4x	Chain Lightning

.PARAMETER SuperTypes
Retain card supertypes of Basic, Legendary, and Snow.

.PARAMETER Percents
Display card types as percentages instead of counts.

.PARAMETER AutoSave
Automatically save charts in deck list directory rather than display.

.EXAMPLE
Get-MagicDeckStats -DeckList "~\zombies.txt"
Calculates and displays stat charts for decklist "~\zombies.txt".

.EXAMPLE
Get-MagicDeckStats -DeckList "~\red_deck_wins.txt" -AutoSave
Calculates and saves stat charts for decklist "~\red_deck_wins.txt".
#>
[CmdletBinding()]
param (
    # Path to cockatrice *.cod file or plain text (*.dec, *.dek, *.txt) file
    [Parameter(Mandatory=$True, Position=0)]
    [ValidateScript({Test-Path $_})]
    [string]$DeckList,
    
    # Include supertypes of Basic, Legendary, and Snow
    [Parameter(Mandatory=$False)]
    [switch]$SuperTypes = $false,

    # Display card types as percentages instead of counts
    [Parameter(Mandatory=$False)]
    [switch]$Percents = $false,

    # Automatically save charts rather than display
    [Parameter(Mandatory=$False)]
    [switch]$AutoSave = $false
)

# assemblies required for charts
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms.DataVisualization

# https://learn-powershell.net/2016/09/18/building-a-chart-using-powershell-and-chart-controls/
# subfunctions for charts
Function SaveDialog {
    $FileTypes = [enum]::GetNames('System.Windows.Forms.DataVisualization.Charting.ChartImageFormat') | ForEach-Object {
        $_.Insert(0,'*.')
    }
    $SaveFileDlg = New-Object System.Windows.Forms.SaveFileDialog
    $SaveFileDlg.DefaultExt='PNG'
    $SaveFileDlg.Filter="Image Files ($($FileTypes))|$($FileTypes)|All Files (*.*)|*.*"
    $return = $SaveFileDlg.ShowDialog()
    if ($Return -eq 'OK') {
        [pscustomobject]@{
            FileName = $SaveFileDlg.FileName
            Extension = $SaveFileDlg.FileName -replace '.*\.(.*)','$1'
        }
 
    }
}
Function PieChart {
	# chart objects
	$Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
	$ChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
	$Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
	$ChartTypes = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]
	
	# chart type, series, and chart area
	$Series.ChartType = $ChartTypes::Pie
	$Chart.Series.Add($Series)
	$Chart.ChartAreas.Add($ChartArea)
	
	# data points for chart
	$Chart.Series['Series1'].Points.DataBindXY($type.Keys, $type.Values)
	
	# chart style
	$Chart.Width = 700
	$Chart.Height = 400
	$Chart.Left = 10
	$Chart.Top = 10
	$Chart.BackColor = [System.Drawing.Color]::White
	$Chart.BorderColor = 'Black'
	$Chart.BorderDashStyle = 'Solid'
	
	# chart title
	$ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
	$ChartTitle.Text = "$($file.BaseName) - Card Types"
	$Font = New-Object System.Drawing.Font @('Microsoft Sans Serif','12', [System.Drawing.FontStyle]::Bold)
	$ChartTitle.Font = $Font
	$Chart.Titles.Add($ChartTitle)
	
	# chart labels
	$Chart.Series['Series1']['PieLineColor'] = 'Black'
	$Chart.Series['Series1']['PieLabelStyle'] = 'Outside'
	switch ($Percents) {
		$true {
			$Chart.Series['Series1'].Label = "#VALX (#VALY %)"
		}
		$false {
			$Chart.Series['Series1'].Label = "#VALX (#VALY)"
		}
	}
	
    if ($AutoSave) {
        $Chart.SaveImage("$($file.Directory)\$($file.BaseName)_types.jpeg", 'jpeg')
    }
    else {
        # windows form to display chart
		$AnchorAll = `
			[System.Windows.Forms.AnchorStyles]::Bottom -bor `
			[System.Windows.Forms.AnchorStyles]::Right -bor `
			[System.Windows.Forms.AnchorStyles]::Top -bor `
			[System.Windows.Forms.AnchorStyles]::Left
		$Form = New-Object Windows.Forms.Form
		$Form.Width = 740
		$Form.Height = 490
		$Form.controls.add($Chart)
		$Chart.Anchor = $AnchorAll
		
		# save button
		$SaveButton = New-Object Windows.Forms.Button
		$SaveButton.Text = "Save"
		$SaveButton.Top = 420
		$SaveButton.Left = 600
		$SaveButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
		$SaveButton.add_click({
			$Result = SaveDialog
			if ($Result) {
				$Chart.SaveImage($Result.FileName, $Result.Extension)
			}
		})
		$Form.controls.add($SaveButton)
		
		# display form
		$Form.Add_Shown({$Form.Activate()})
		[void]$Form.ShowDialog()
    }
}
Function ColumnChart {
	# chart objects
	$Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
	$ChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
	$Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
	$ChartTypes = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]
	
	# chart type, series, and chart area
	$Series.ChartType = $ChartTypes::Column
	$Chart.Series.Add($Series)
	$Chart.ChartAreas.Add($ChartArea)
	
	# data points for chart
	$Chart.Series['Series1'].Points.DataBindXY($cost.Keys, $cost.Values)
	
	# chart style
	$Chart.Width = 700
	$Chart.Height = 400
	$Chart.Left = 10
	$Chart.Top = 10
	$Chart.BackColor = [System.Drawing.Color]::White
	$Chart.BorderColor = 'Black'
	$Chart.BorderDashStyle = 'Solid'
	
	# chart title
	$ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
	$ChartTitle.Text = "$($file.BaseName) - Mana Curve"
	$Font = New-Object System.Drawing.Font @('Microsoft Sans Serif','12', [System.Drawing.FontStyle]::Bold)
	$ChartTitle.Font =$Font
	$Chart.Titles.Add($ChartTitle)
	
    if ($AutoSave) {
        $Chart.SaveImage("$($file.Directory)\$($file.BaseName)_curve.jpeg", 'jpeg')
    }
    else {
        # windows form to display chart
		$AnchorAll = `
			[System.Windows.Forms.AnchorStyles]::Bottom -bor `
			[System.Windows.Forms.AnchorStyles]::Right -bor `
			[System.Windows.Forms.AnchorStyles]::Top -bor `
			[System.Windows.Forms.AnchorStyles]::Left
		$Form = New-Object Windows.Forms.Form
		$Form.Width = 740
		$Form.Height = 490
		$Form.controls.add($Chart)
		$Chart.Anchor = $AnchorAll
		
		# save button
		$SaveButton = New-Object Windows.Forms.Button
		$SaveButton.Text = "Save"
		$SaveButton.Top = 420
		$SaveButton.Left = 600
		$SaveButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
		$SaveButton.add_click({
			$Result = SaveDialog
			if ($Result) {
				$Chart.SaveImage($Result.FileName, $Result.Extension)
			}
		})
		$Form.controls.add($SaveButton)
		
		# display form
		$Form.Add_Shown({$Form.Activate()})
		[void]$Form.ShowDialog()
    }
}

# subfunction for sample hand and draw
Function SampleHand {
	
	# remove existing full deck if it exists
	if (Test-Path "$path\$($file.BaseName)_full.txt") {
		Remove-Item "$path\$($file.BaseName)_full.txt" -Force -Confirm:$false
	}

	# 'unroll' deck using each card quantity
	foreach ($card in $deck) {
    	foreach ($copy in 1..$card.qty) {
        	$card.Name | Out-File "$path\$($file.BaseName)_full.txt" -Append | Out-Null
    	}
	}

	# full decklist and empty array for hand
	$full = Get-Content "$path\$($file.BaseName)_full.txt"
	$hand = New-Object -TypeName System.Collections.ArrayList

	do {
		# draw a card
		$draw = $null
		$draw = 0..$($full.Count - 1) | Get-Random
		
		# add card to hand unless it is already there
		if ($hand -notcontains $draw) {
			$hand.Add($draw) | Out-Null
		}
	}
	until (
		$hand.Count -eq 7
	)
	
	# output sample hand
	Write-Host "Sample opening hand:" -ForegroundColor Green
	$hand | ForEach-Object {
		$full[$_]
	} | Sort-Object
	Write-Verbose "$($hand)"

	Write-Host "Press [Enter] to draw a card. [Ctrl] + [c] to break." -ForegroundColor Green
	$i = 0
	do {
		$read = Read-Host
		
		if ($read -eq "") {
			do {
				$draw = $null
				$draw = 0..$($full.Count - 1) | Get-Random
			}
			until ($hand -notcontains $draw)
			$i++
			$hand.Add($draw) | Out-Null
			Write-Host "Draw #$($i): " -ForegroundColor Green -NoNewline
			Write-Host "$($full[$draw])"
			Write-Verbose "$($hand)"
		}
	}
	until ($hand.Count -eq $full.Count)
	Write-Warning "Your library is empty!"
}

# file and path info used for exports
$file = Get-Item -Path $DeckList
$path = "$env:TEMP\Get-MagicDeckStats"
if (!(Test-Path $path)) {
    mkdir $path
}

# deck w/ relevant card attributes added
switch ($file.Extension) {
	
	# .cod file (cockatrice xml)
	{$_ -eq '.cod'} {
		$xml = New-Object -TypeName xml
		$xml.Load((Convert-Path $file.FullName))
		$deck = $xml.cockatrice_deck.zone.card | Select-Object @{Name="qty";Expression={$_.number}},name,cmc,type
	}

	# any other file
	Default {
		$deck = Get-Content $DeckList -Encoding UTF8 | ForEach-Object {
			if ($_ -ne "" -and $_ -notlike "#*") {
				$card = "" | Select-Object qty,name,cmc,type
		
				# quantity and card name separated by tab
				if ($_ -like "*`t*") {
					$card.qty = ($_.Split("`t") | Select-Object -first 1)
					$card.name = $_.Replace("$($card.qty)`t",'')	
				}
			
				# quantity and card name separated by space
				else {
					$card.qty = ($_.Split(' ') | Select-Object -first 1)
					$card.name = $_.Replace("$($card.qty) ",'')
				}
			
				# trim 'x' from quantity if present
				if ($card.qty -like "*x") {
					$card.qty = $($card.qty).TrimEnd('x')
				}
				$card
			}
		}
	}
}

# download json for each card if needed
$i = 0
foreach ($card in $deck) {
    # progress bar
    $i++
    Write-Progress -Activity "Processing $($card.name)" -PercentComplete ($i / $deck.Count * 100)

    # check local
    if (Test-Path "$path\$($card.name).json") {
        Write-Verbose "$path\$($card.name).json exists"
    }
    else {
        # api call
        try {
			Write-Verbose "Downloading '$($card.name)' data from scryfall"
            $curl = $null
            $curl = curl https://api.scryfall.com/cards/named?exact=$(($card.name).Replace(' ','+')) --silent
        }
        catch {
            throw
        }    

        $json = $curl | ConvertFrom-Json
        if ($json.object -eq 'card') {
            $json | ConvertTo-Json | Out-File "$path\$($card.Name).json"
        }
        elseif ($json.object -eq 'error') {
            throw "Card '$($card.Name)' not found! Exiting."
        }

        # give the api a break
        Start-Sleep -Seconds 1
    }
}

# type_line split
$s = 'Γ'

# pull cmc and type for each card from json
foreach ($card in $deck) {
    $json = $null
    $json = get-content "$path\$($card.Name).json" | ConvertFrom-Json

    $card.cmc = $json.cmc
    $card.type = ($json.type_line.split($s) | Select-Object -first 1).TrimEnd(' ')
    
    # supertype replacements
    if ($SuperTypes -eq $false) {
        $card.type = $card.type.Replace('Basic ','')
        $card.type = $card.type.Replace('Legendary ','')
        $card.type = $card.type.Replace('Snow ','')
    }
}

# calc total deck size
$size = 0
$deck | Foreach-Object {
    $size += $_.qty
}

# card types (PieChart)
$type = foreach ($t in ($deck.type | Select-Object -Unique) ) {
    $p = 0
    ($deck | Where-Object {$_.type -eq $t}).qty | ForEach-Object { $p += $_ }

    switch ($Percents) {
        $true {
            @{
                [string]($t) = [math]::round([decimal]($p / $size * 100), 2)
            }
        }
        $false {
            @{
                [string]($t) = [int64]($p)
            }
        }
    }
}

# cmc (ColumnChart)
$cost = foreach ($c in ($($deck | Where-Object {$_.type -notlike "*land*"}).cmc | Select-Object -Unique | Sort-Object)) {
    $p = 0
    ($deck | Where-Object {$_.cmc -eq $c}).qty | ForEach-Object { $p += $_ }
    @{
        [int64]($c) = [int64]($p)
    }
}

# swing with everything
PieChart
ColumnChart
SampleHand
}