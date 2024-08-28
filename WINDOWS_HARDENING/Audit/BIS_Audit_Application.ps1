function NullCheck($arg1, $arg2)
{
    if($arg1 -eq "")
    {
        Write-Host "value of $arg2 could not be fetched" 
        exits
    }
    else
    {
        continue
    }
}
#------------------------------------------------------------------------
# Validating SqlAnyWhere Password Entered by user in configuration file 
#------------------------------------------------------------------------

function ValidateDbaPassword($pwd)
{
	PrintDateTime
   try
   {         		
        $conn = new-object system.data.odbc.odbcconnection
        $conn.connectionstring = "DSN=BI4_CMS_DSN;UID=dba;PWD=$pwd;HOST=localhost;PORT=2638;"        
        $conn.Open()        
        "SQL Anywhere dba Password: Valid" >>$log
		$conn.Close()        
		Remove-Variable conn		
    }
    catch
    {
        $_ 
		"----------------------------------------------- " >>$log
        "SQL Anywhere dba Password: Not Valid" >>$log
		"Execution of housekeeping script stopped" >>$log
		$conn.Close()
		Remove-Variable conn 
		Exit
    }
    
}

function DecryptingConfigFile()
{    
    $keyFile = "C:\ebid\install\key.txt"
    if(Test-Path $keyFile)
    {
        powershell -command ". C:\ebid\install_config\ebid_encryption_decryption.ps1; DecryptEBIDFile -path C:\ebid\install\*.ini -output 'C:\ebid\data_collector\tmp.txt' -type 'postinstall' ;"
        $script:InstallFile="C:\ebid\data_collector\tmp.txt"
    }
    else
    {
        "Key file not present in C:\ebid\install folder so exiting the script."  >>$log
        exit
    } 
    ReadingInputs
}

function ReadingInputs()
{         
	try
	{
		foreach($line in Get-Content "C:\Audit\audit_config.ini") 
		{        
			if($line -match "Logs")
			{            
				$LineSplit = "$line".split("=",2)
				$LogValue = $LineSplit[1].Trim()
				NullCheck $LogValue "Logs value"
			}			
		}
		foreach($line in Get-Content $script:InstallFile) 
		{        			
			if($line -match "sqlanywhereadminpassword=")
			{
				$LineSplit = "$line".split("=",2)
				$DbaPassword = $LineSplit[1].Trim()
				NullCheck $DbaPassword "DBA Password"
				ValidateDbaPassword $DbaPassword
			}
		}
		if(Test-Path -Path $script:InstallFile)
		{
			Remove-Item -Path $script:InstallFile
		}
	}
	catch
	{
		$_  >>$log
	}  
	SettingTimeStamp
}

function SettingTimeStamp()
{	
    $TimeStampFileName = Get-Date -format yyyyMMdd
    $TimeStamp =  Get-Date -format yyyy-MM-dd-HH:mm:ss
    $EndTime = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss.000')
    $StartTime = [DateTime]::UtcNow.AddDays(-1).ToString('yyyy-MM-dd HH:mm:ss.000')   	        
	FetchLogs
}

function FetchLogs()
{
	$DBsqlDirectory = "C:\Sybase\IQ-16_1"
	foreach($Log in $LogValue.split(","))
	{
		$LogName = $Log.Trim()			
		$FileName = $LogName+$TimeStampFileName	
		if($LogName -match "Auditing")		
		{
			$FileName = "Auditing_Modification"+$TimeStampFileName
		}
		elseif($LogName -match "Custom Access Level Modified")
		{
			$FileName = "Custom_Access_Level_Modified"+$TimeStampFileName
		}
		elseif($LogName -match "Rights Modification")		
		{
			$FileName = "Rights_Modification"+$TimeStampFileName
		}
		$ReportFile = New-Item C:\Audit\temp\BIS_Application_Events\"$FileName".txt -ItemType File	
		& "$DBsqlDirectory\Bin64\dbisql.exe" -nogui -c "DSN=BI4_Audit_DSN" -onerror continue "Select ae.Start_Time,ae.Event_ID,ae.User_Name, aed.Event_Detail_Value, aets.Event_Type_Name, ass.Status_Name, ae.Object_Name, aots.Object_Type_Name from ADS_EVENT ae left outer join ADS_EVENT_DETAIL aed on aed.Event_ID=ae.Event_ID left outer join ADS_EVENT_DETAIL_TYPE_STR aedts on aedts.Event_Detail_Type_ID=aed.Event_Detail_Type_ID left outer join ADS_EVENT_TYPE aet on aet.Event_Type_ID=ae.Event_Type_ID left outer join ADS_EVENT_TYPE_STR aets on aets.Event_Type_ID=aet.Event_Type_ID left outer join ADS_EVENT_CATEGORY_STR aecs on aecs.Event_Category_ID=aet.Event_Category_ID left outer join ADS_STATUS_STR ass on ass.Event_Type_ID=ae.Event_Type_ID and ass.Status_ID=ae.Status_ID left outer join ADS_OBJECT_TYPE_STR aots on aots.Object_Type_ID=ae.Object_Type_ID where aedts.Language='EN' and aets.Language='EN' and aecs.Language='EN' and aots.Language='EN' and ass.Language='EN' and aets.Event_Type_Name='$LogName' AND (ae.Start_Time BETWEEN '$StartTime' AND '$EndTime') ; OUTPUT TO $ReportFile FORMAT ASCII WITH COLUMN NAMES"		
	}		
	FetchEventViewerLogs
}

function FetchEventViewerLogs()
{	
	Get-EventLog -LogName Application -Source BusinessObjects_EventServer -After $limit -Before $CurrentDate | Export-Csv -LiteralPath ('C:\Audit\temp\BIS_Application_Events\EventViewerLogs.csv') -NoTypeInformation
}
$log = "C:\Audit\temp\Audit.log"
$CurrentDate = Get-Date
$limit = (Get-Date).AddDays(-1)
DecryptingConfigFile