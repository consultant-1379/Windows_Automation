#------------------------------------------------
# Function to print date and time in log file
#------------------------------------------------
function PrintDateTime()
{    
    "----------------------------------------------- " >>$global:FirewallLogFile 
    Get-Date -Format "dddd [MM/dd/yyyy] [HH:mm:ss]" >>$global:FirewallLogFile
    "----------------------------------------------- " >>$global:FirewallLogFile      
}

#--------------------------------------------
# Function to fetch values of all parameters
#--------------------------------------------
function FetchValue($Arg1)
{
    try
    {
        $ParameterFound = "False"
        foreach($SourceFolder in Get-Content  $InputFile)
        {            
            If($SourceFolder -match $Arg1)
            {                                
          	   	$line_split = "$SourceFolder".split("=",2)
                $Value = $line_split[1].Trim()
                $ParameterFound = "True"
            }
        }
        if($ParameterFound -eq "True")
        {
            if($Value -eq '')
            {
                Write-Host "`n [ERROR]: $Arg1 Value is null. Please provide value as per documentation and run script again" -ForegroundColor Red
                $global:ErrorCount = $global:ErrorCount + 1
            }
            else
            {
                return $Value
            }            
        }
        else
        {
            Write-Host "`n [ERROR]: $Arg1 Parameter is missing from input file. Please add the paramater, value and run the script again" -ForegroundColor Red
            $global:ErrorCount = $global:ErrorCount + 1
        }
        
    }
    catch
    {
        $_ >>$global:FirewallLogFile
    }

}

#--------------------------------------------------------------
# Function to check port values defined in configuration file
#--------------------------------------------------------------

function CheckPortValues($BISPortValues)
{
    $PortValues = "$BISPortValues".split(",")
    foreach($Values in $PortValues)
    {
        $Values = $Values.Trim()
        if($Values -eq '')
        {
            Write-Host "`n Null value is not a valid port. Please check if extra ',' is added in configuration file for portvalue parameters" -ForegroundColor Red
        }
        else
        {            
            try
            {
                $IntegerCheck = [int]$Values  
                if(($IntegerCheck -lt 0) -OR ($IntegerCheck -gt 65535))
                {
                    Write-Host "`n $IntegerCheck is an invalid port and Port value must be between 0-65535" -ForegroundColor Red
                    "`n $IntegerCheck is an Invalid Port" >>$global:FirewallLogFile
                    $global:ErrorCount = $global:ErrorCount+1
                }
                else
                {
                    $global:ValidPorts.Add($IntegerCheck)
                    "`n $Values is a Valid Port" >>$global:FirewallLogFile
                }                                                        
            }
            catch
            {                
                if($Values.contains("-"))
                {
                    if($Values -match '^[a-zA-Z]')
                    {               
                        Write-Host "`n $Values is an Invalid port" -ForegroundColor Red
                        "`n $Values is an Invalid port" >>$global:FirewallLogFile   
                        $global:ErrorCount = $global:ErrorCount+1
                    }
                    else
                    {               
                        "`n $Values is a Valid port" >>$global:FirewallLogFile
                        $global:ValidPorts.Add($Values)  
                    }
                }
                else
                {
                    Write-Host "`n $Values is an Invalid Port" -ForegroundColor Red
                    "`n $Values is an Invalid Port" >>$global:FirewallLogFile   
                    $global:ErrorCount = $global:ErrorCount+1                
                }
            }            
        }
    }    
}

#--------------------------------------------
# Function to fetch all BIS parameters
#--------------------------------------------

function readBISParameters()
{
    PrintDateTime
    $global:BISRuleName = FetchValue "RuleName"  
    if($global:firewall_argument -eq "EnableFirewall") 
    {
        $global:BISPortValues = FetchValue "BIS_Port_Values"
        CheckPortValues $BISPortValues 
    }   
    if($global:ErrorCount -gt 0)        
    {
        Write-Host "`n [ERROR]: There are error/errors in the configuration file and please make above mentioned changes and run the script" -ForegroundColor Red
        exit
    }
}

#--------------------------------------------
# Function to fetch all OCS parameters
#--------------------------------------------

function readOCSParameters()
{
    PrintDateTime
    $global:OCSRuleName = FetchValue "RuleName"  
    if($global:firewall_argument -eq "EnableFirewall") 
    {  
        $global:OCSPortValues = FetchValue "OCS_Port_Values" 
        CheckPortValues $OCSPortValues 
    }      
    if($global:ErrorCount -gt 0)        
    {
        Write-Host "`n [ERROR]: There are error/errors in the configuration file and please make above mentioned correction" -ForegroundColor Red
        exit
    } 
}

#--------------------------------------------
# Function to fetch all OCS_withoutCitrix parameters
#--------------------------------------------

function readOCSwithoutCitrixParameters()
{
    PrintDateTime
    $global:OCSwithoutCitrixRuleName = FetchValue "RuleName"  
    if($global:firewall_argument -eq "EnableFirewall") 
    {  
        $global:OCSwithoutCitrixPortValues = FetchValue "OCS_withoutCitrix_Port_Values" 
        CheckPortValues $OCSwithoutCitrixPortValues 
    }      
    if($global:ErrorCount -gt 0)        
    {
        Write-Host "`n [ERROR]: There are error/errors in the configuration file and please make above mentioned correction" -ForegroundColor Red
        exit
    } 
}

#--------------------------------------------
# Function to fetch all NetAn parameters
#--------------------------------------------
function readNetAnParameters()
{
	PrintDateTime
	$global:NetAnRuleName = FetchValue "RuleName"  
    if($global:firewall_argument -eq "EnableFirewall") 
    {  
        $global:NetAnPortValues = FetchValue "NetAn_Values" 
        CheckPortValues $NetAnPortValues 
    }      
    if($global:ErrorCount -gt 0)        
    {
        Write-Host "`n [ERROR]: There are error/errors in the configuration file and please make above mentioned correction" -ForegroundColor Red
        exit
    } 
}
#-----------------------------
# Turning on the firewall
#-----------------------------

function TurnOnFirewall()
{
    PrintDateTime
    try
    {
        $FirewallValues =  Get-NetFirewallProfile -All
        foreach($FirewallProfile in $FirewallValues)
        {
            $FirewallName = $FirewallProfile.Name
            $FirewallEnable = $FirewallProfile.Enabled
            "$FirewallName = $FirewallEnable" >>$global:FirewallBackUp
            if($FirewallProfile.Enabled -ne "True")
            {                
                "$FirewallName firewall profile is Not Enabled and Turning on the profile" >>$global:FirewallLogFile
                try
                {
                    Set-NetFirewallProfile -Name $FirewallName -Enabled True
                    Write-Host "`n Enabling of $FirewallName profile is successful"
                    "Enabling of $FirewallName profile is successful" >>$global:FirewallLogFile 
                }
                catch
                {
                    Write-Host "`n Enabling of $FirewallName profile is failed and hence exiting from the script. Check log file for more details" -ForegroundColor Red
                    "Enabling of $FirewallName profile is failed and hence exiting from the script" >>$global:FirewallLogFile 
                    $_ >>$global:FirewallLogFile
					return "Failed"
                    exit
                }
            }
            else
            {
                "$FirewallName is Enabled" >>$global:FirewallLogFile
            }
        } 
    }
    catch
    {
        Write-Host "`n Eror occured while enabling the firewall and hence exiting from the script. Check log file for more details" -ForegroundColor Red
        "Eror occured while enabling the firewall and hence exiting from the script" >>$global:FirewallLogFile
		return "Failed"		
        exit
    }
}

function TurnFileShareRuleOn()
{
    try
    {
         Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True
    }
    catch
    {
        $_ >>$global:FirewallLogFile
        Write-Host "Unable to turn on 'File and Printer Sharing (Echo Request - ICMPv4-In)' firewall rule. Please turn on Firewall rule manually "
    }

    try
    {
         Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv6-In)" -Enabled True
    }
    catch
    {
        $_ >>$global:FirewallLogFile
        Write-Host "Unable to turn on 'File and Printer Sharing (Echo Request - ICMPv6-In)' firewall rule. Please turn on Firewall rule manually "
    }
}

function TurnFileShareRuleOff()
{
    try
    {
         Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled False
    }
    catch
    {
        $_ >>$global:FirewallLogFile
        Write-Host "Unable to turn off 'File and Printer Sharing (Echo Request - ICMPv4-In)' firewall rule. Please turn off Firewall rule manually "
    }

    try
    {
         Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv6-In)" -Enabled False
    }
    catch
    {
        $_ >>$global:FirewallLogFile
        Write-Host "Unable to turn off 'File and Printer Sharing (Echo Request - ICMPv6-In)' firewall rule. Please turn off Firewall rule manually "
    }
}

#-------------------------------------------------------------
# Turning off the firewall based on the Firewall Backupfile
#-------------------------------------------------------------

function TurnOffFirewall()
{
    PrintDateTime
    if(Test-Path -Path $global:FirewallBackUp)
    {        
        foreach($SourceFolder in Get-Content  $global:FirewallBackUp)
        {   
            try
            {        
                If($SourceFolder -match "Domain")
                {                                
          	       	$LineSplit = "$SourceFolder".split("=",2)
                    $Value = $LineSplit[1].Trim()                
                    Set-NetFirewallProfile -Profile Domain -Enabled $Value  
                    Write-Host "`n Rollback of Domain profile to $Value is successful"
					"`nRollback of Domain profile to $Value is successful" >>$global:FirewallLogFile
                }
                elseif($SourceFolder -match "Private")
                {
                    $LineSplit = "$SourceFolder".split("=",2)
                    $Value = $LineSplit[1].Trim()
                    Set-NetFirewallProfile -Profile Private -Enabled $Value
                    Write-Host "`n Rollback of Private profile to $Value is successful"
					"`nRollback of Private profile to $Value is successful" >>$global:FirewallLogFile
                }
                elseif($SourceFolder -match "Public")
                {
                    $LineSplit = "$SourceFolder".split("=",2)
                    $Value = $LineSplit[1].Trim()
                    Set-NetFirewallProfile -Profile Public -Enabled $Value
                    Write-Host "`n Rollback of Public profile to $Value is successful"
					"`nRollback of Public profile to $Value is successful" >>$global:FirewallLogFile
                }
            }
            catch
            {
                $_ >>$global:FirewallLogFile
                Write-Host "Error when turning off profile. Please refer to log file for more details" -ForegroundColor Red
                "Error when turning off profile. Please refer to log file for more details" >>$global:FirewallLogFile
				return "Failed"
            }
        }        
    }
    else
    {
        #Write-Host "`n $global:FirewallBackUp is not present and turning off all firewall profiles"
        try
        {
            Set-NetFirewallProfile -All -Enabled False
            Write-Host "`n Disabling of all firewall profiles is successful"
            "Disabling of all firewall profiles is successful" >>$global:FirewallLogFile
        }
        catch
        {
            Write-Host "`n Disabling of all firewall profiles failed and hence exiting from the script. Check log file for more details"
            "Disabling of all firewall profiles failed" >>$global:FirewallLogFile
            $_ >>$global:FirewallLogFile
            exit
        }
    }
}

#-----------------------------
# Force Turning off the firewall
#-----------------------------

function ForceTurnOffFirewall()
{
    try
    {
        Set-NetFirewallProfile -All -Enabled False
        Write-Host "`n Disabling of all firewall profiles is successful"
        "Disabling of all firewall profiles is successful" >>$global:FirewallLogFile
    }
    catch
    {
        Write-Host "`n Disabling of all firewall profiles failed and hence exiting from the script. Check log file for more details"
        "Disabling of all firewall profiles failed" >>$global:FirewallLogFile
        $_ >>$global:FirewallLogFile
        exit
    }
}

#--------------------------------------
# Function to create new firewall rule
#--------------------------------------

function CheckFirewallRule($RuleName)
{
    try
    {
        Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop >>$global:FirewallLogFile
        Write-Host "`n Firewall rule exists with name $RuleName and updating/removing the rule" 		
		Remove-NetFirewallRule -DisplayName $RuleName		
    }
    catch [Exception]
    {
		"No Firewall rule exists with Rule Name [ $RuleName ]. New rule would be created..." >>$global:FirewallLogFile
		return "Failed"
        #$_.Exception.message >>$global:FirewallLogFile        
    }
}

#--------------------------------------
# Function to create new firewall rule
#--------------------------------------

function CreateNewFirewallRule($RuleName,$PortValues)
{
    PrintDateTime
    try
    {
        Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop >>$global:FirewallLogFile
        Write-Host "`n Firewall rule exists with name $RuleName and updating/removing the rule" 		
		Remove-NetFirewallRule -DisplayName $RuleName		
    }
    catch [Exception]
    {
		"No Firewall rule exists with Rule Name [ $RuleName ]. New rule would be created..." >>$global:FirewallLogFile		
        #$_.Exception.message >>$global:FirewallLogFile        
    }
    try
    { 
        New-NetFirewallRule -DisplayName $RuleName -Profile 'Private, Domain, Public' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $global:ValidPorts >>$global:FirewallLogFile
    }
    catch
    {
        $_ >>$global:FirewallLogFile
        Write-Host "Error while create firewall rule and exiting from script. Please refer log file for more details" -ForegroundColor Red
        exit
    }
}

#--------------------------------------
# Function to remove new firewall rule
#--------------------------------------

function RemoveFirewallRule($RuleName)
{
    PrintDateTime
    CheckFirewallRule $RuleName
}

#------------------------------------------
# Function to create ICMPV4 firewall rule
#------------------------------------------

function CreateICMPV4Rule()
{
    PrintDateTime
    try
    {		
		if([bool](Get-NetFirewallRule -DisplayName "ICMPV4" -ErrorAction SilentlyContinue))
		{
			"ICMPV4 rule exists and deleting it" >>$global:FirewallLogFile
			Remove-NetFirewallRule -DisplayName "ICMPV4"
		}
        New-NetFirewallRule -DisplayName "ICMPV4" -Direction Inbound -Protocol "ICMPv4" -IcmpType 5,14,16,18 -Action Block >>$global:FirewallLogFile
    }
    catch
    {
        $_ >>$global:FirewallLogFile
		return "Failed"
    }
}

#------------------------------------------
# Function to create ICMPV6 firewall rule
#------------------------------------------

function CreateICMPV6Rule()
{
    PrintDateTime
    try
    {
		if([bool](Get-NetFirewallRule -DisplayName "ICMPV6" -ErrorAction SilentlyContinue))
		{
			"ICMPV6 rule exists and deleting it" >>$global:FirewallLogFile
			Remove-NetFirewallRule -DisplayName "ICMPV6"
		}
        New-NetFirewallRule -DisplayName "ICMPV6" -Direction Inbound -Protocol "ICMPv6" -IcmpType 133,134,137 -Action Block >>$global:FirewallLogFile
    }
    catch
    {
        $_ >>$global:FirewallLogFile
		return "Failed"
    }
}

#------------------------------------------
# Function to create ICMPV4 firewall rule
#------------------------------------------

function RemoveICMPV4Rule()
{
    PrintDateTime
    CheckFirewallRule "ICMPV4"
}

#------------------------------------------
# Function to create ICMPV6 firewall rule
#------------------------------------------

function RemoveICMPV6Rule()
{
    PrintDateTime
    CheckFirewallRule "ICMPV6"
}

#-----------------------------------------------------
# Check if logged user is BIS Admin or Not
#-----------------------------------------------------

function CheckBISAdmin()
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
	$CheckUser  = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)	
    if($CheckUser)
    {
        "`n Logged user is Administrator" >>$global:FirewallLogFile
        #Write-Host "`n Logged user is Administrator"
    }
    else
    {        
        "`n Logged user is not Administrator. Please logon as Administrator and run the script for firewall settings" >>$global:FirewallLogFile        
        exit
    }
}

#-----------------------------------------------------
# Check if logged user is Domain Administrator or Not
#-----------------------------------------------------

function CheckDomainAdministrator()
{
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)  
    if($WindowsPrincipal.IsInRole("Domain Admins")) 
    {     
        #Write-Host "`n Logged on user is Domain Administrator" 
        "`n Logged on user is Domain Administrator" >>$global:FirewallLogFile
    } 
    else 
    {    
        Write-Host "`n Logged on user is not Domain Administrator and exiting from script" 
        "`n Logged on user is not Domain Administrator and exiting from script" >>$global:FirewallLogFile
        exit
    } 
}

#------------------------------------------------------------------------
#function for Checking if server is Active directory
#------------------------------------------------------------------------
function CheckAD()
{
    try
    {
        Get-ADForest | Out-Null
        return $true
    }
    catch
    {
		$_ >>$global:FirewallLogFile
        return $false
    }
}

#----------------------------------------------------------
# Checking the server configuration 
#----------------------------------------------------------

function CheckServer()
{
	#Checking for server type
	
    PrintDateTime
    if(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4*\config Manager")
    {
		if(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
		{
			"It's a Co-Deployed (BIS and NetAn) server" >>$global:FirewallLogFile
			CheckBISAdmin	
			$global:NetAnServer = "True"
			$global:BISServer = "True"
		}
		else
		{
			"It's a BIS server" >>$global:FirewallLogFile
			CheckBISAdmin        
			$global:BISServer = "True"
		}        
    }
	elseif(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
    {
		"It's a NetAn server" >>$global:FirewallLogFile
        CheckBISAdmin	
		$global:NetAnServer = "True"
    }
    elseif((Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent") -AND (Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora"))
    {
        "It's VDA server with BO Client installed" >>$global:FirewallLogFile 
        CheckBISAdmin
        $global:OCSServer = "True"
    }
    elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller")
    {   
        if(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Desktop Delivery Controller' -Name InstallDir).InstallDir)
        {
            "It's CCS server" >>$global:FirewallLogFile
        }
        elseif(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
        {
            "It's VDA server" >>$global:FirewallLogFile
        }    	
        CheckDomainAdministrator	                
        $global:OCSServer = "True"
    }
    elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent")
    {
        if(Test-path -Path (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Citrix Virtual Desktop Agent' -Name InstallDir).InstallDir)
        {
            "It's VDA server without BO Client installed" >>$global:FirewallLogFile
            CheckDomainAdministrator
            $global:OCSServer = "True"
        }
    }
	elseif(Test-Path -Path "HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora")
	{
		"It's OCS-without-Citrix server with BO Client installed" >>$global:FirewallLogFile
		CheckBISAdmin
		$global:OCSwithoutCitrixServer = "True"
	}																					   

    if(($BISServer -ne "True") -AND ($OCSServer -ne "True") -AND ($NetAnServer -ne "True") -AND ($OCSwithoutCitrixServer -ne "True"))
    {
        $CheckADServer = CheckAD        
        if($CheckADServer)
        {                
            "It's An AD server">>$global:FirewallLogFile
            $global:OCSServer = "True"            
        }
        else
        {
            $_ >>$global:FirewallLogFile
            Write-Host "`n Unable to recognize server" -ForegroundColor Red
            exit
        }
    }
}

#MAIN

$global:LogDirectory = "C:\Firewall\log"
$global:TimeStamp=get-date -format yyyy-MM-dd_HH_mm_ss
$InputFile = "C:\Firewall\FirewallRule_Values.ini"
$global:BISServer = "False"
$global:OCSServer = "False"
$global:NetAnServer = "False"
$global:ErrorCount = 0
$global:ValidPorts = new-object Collections.Generic.List[string]
$global:FirewallBackUp = "C:\Firewall\FirewallBackup.ini"
#------------------------------------------------------------------------
#Checking if user has given correct argument or not
#------------------------------------------------------------------------
if($args.Count -lt 1)
{
    Write-Host "`n [ERROR]: No arguments are given when running the script. Please use anyone of the following arguments to run the script EnableFirewall, DisableFirewall, BlockICMP, UnblockICMP." -ForegroundColor Red
    exit
}
elseif($args.Count -gt 1)
{
    Write-Host "`n [ERROR]: Only one argument should be given when running the script. Please use EnableFirewall, DisableFirewall, BlockICMP, UnblockICMP arguments and try running the script." -ForegroundColor Red
    exit
}

if(($args -ne "EnableFirewall") -AND ($args -ne "DisableFirewall") -AND ($args -ne "BlockICMP") -AND ($args -ne "UnblockICMP"))
{
    Write-Host "`n [ERROR]: $args is an Invalid argument. EnableFirewall, DisableFirewall, BlockICMP, UnblockICMP are valid arguments" -ForegroundColor Red
    exit
}
else
{
    Write-Host "`n Script is running with $args argument"
}

#------------------------------------------------------------------------
#Checking if Log directory is present and creating log file
#------------------------------------------------------------------------

if(Test-Path $LogDirectory)
{     
    $global:FirewallLogFile = New-Item C:\Firewall\log\Firewall_Settings_"$args"-"$global:TimeStamp".txt -ItemType File
    PrintDateTime
    "New log file created in C:\Firewall\log directory" >>$global:FirewallLogFile
}
else
{    
    New-Item -Path $LogDirectory -ItemType Directory | Out-Null
	$global:FirewallLogFile = New-Item C:\Firewall\log\Firewall_Settings_"$args"-"$global:TimeStamp".txt -ItemType File
    PrintDateTime
    "New log file created in C:\Firewall\log directory" >>$global:FirewallLogFile
}

#------------------------------------------------------------------------
#Checking if port_values file is exists or not 
#------------------------------------------------------------------------

if(Test-Path $InputFile)
{
    "`nThe required configuration file 'FirewallRule_Values.ini' for creating firewall found" >>$global:FirewallLogFile
    #Write-Host "`n $args of firewall settings started"
}
else
{
   Write-Host "`n[ ERROR ] : The required configuration file 'FirewallRule_Values.ini' for creating group policy is not found in C:\Firewall" -ForegroundColor Red
   exit
}

CheckServer

if($args -eq "EnableFirewall")
{
    if(Test-Path $FirewallBackUp)
    {
        "`n Firewall backup file is already present in C:\Firewall folder" >>$global:FirewallLogFile
        Clear-Content $FirewallBackUp
    }
    else
    {
        "`n Firewall backup file is not present in C:\Firewall folder and creating the file." >>$global:FirewallLogFile
        New-Item -Path $FirewallBackUp -ItemType File | Out-Null
    }
    $global:firewall_argument = "EnableFirewall"    
    if(($BISServer -eq "True"))
    {        
		if($NetAnServer -eq "True")
		{
			readBISParameters
			readNetAnParameters
			CreateNewFirewallRule $NetAnRuleName $NetAnPortValues
		}		
		elseif($BISServer -eq "True")
		{
			readBISParameters
			CreateNewFirewallRule $BISRuleName $BISPortValues
		}
        
    }
	elseif($NetAnServer -eq "True")
	{
		readNetAnParameters
		CreateNewFirewallRule $NetAnRuleName $NetAnPortValues
	}
    elseif($OCSServer -eq "True")
    {        
        readOCSParameters
        CreateNewFirewallRule $OCSRuleName $OCSPortValues
    }
	elseif($OCSwithoutCitrixServer -eq "True")
	{
		readOCSwithoutCitrixParameters
		CreateNewFirewallRule $OCSwithoutCitrixRuleName $OCSwithoutCitrixPortValues
	}								 
    TurnFileShareRuleOn
    TurnOnFirewall
    Write-Host "`n Enabling of firewall rule is successful" -ForegroundColor Green
	return "Success"
}
elseif($args -eq "DisableFirewall")
{   
    $global:firewall_argument = "FirewallDisable"    
    if($BISServer -eq "True")
    {        
		if($NetAnServer -eq "True")
		{
			readBISParameters
			readNetAnParameters
			RemoveFirewallRule $NetAnRuleName 
		}
		else
		{
			readBISParameters
			RemoveFirewallRule $BISRuleName      
		}
    }
	elseif($NetAnServer -eq "True")
	{		
		readNetAnParameters
		RemoveFirewallRule $NetAnRuleName 
	}
    elseif($OCSServer -eq "True")
    {        
        readOCSParameters
        RemoveFirewallRule $OCSRuleName
    }  
	elseif($OCSwithoutCitrixServer -eq "True")
	{
		readOCSwithoutCitrixParameters
		RemoveFirewallRule $OCSwithoutCitrixRuleName
	}								 
    TurnFileShareRuleOff
    TurnOffFirewall   
    Write-Host "`n Disabling of firewall rule is successful" -ForegroundColor Green 
	return "Success"	
}
elseif($args -eq "ForceDisable")
{
    $global:firewall_argument = "ForceDisable"        
    ForceTurnOffFirewall
}    
elseif($args -eq "BlockICMP")
{        
    CreateICMPV4Rule
    CreateICMPV6Rule
    Write-Host "`n Blocking of ICMP vulnerabilities is successful" -ForegroundColor Green
	return "Success"
}
elseif($args -eq "UnblockICMP")
{
    RemoveICMPV4Rule
    RemoveICMPV6Rule
    Write-Host "`n UnBlocking of ICMP vulnerabilities is successful" -ForegroundColor Green
	return "Success"
}