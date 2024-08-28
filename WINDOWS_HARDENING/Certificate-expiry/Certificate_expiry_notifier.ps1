
#   (c) Ericsson Radio Systems AB 2020 - All rights reserved.
#   The copyright to the computer program(s) herein is the property
# 	and/or copied only with the written permission from Ericsson Radio
# 	Systems AB or in accordance with the terms and conditions stipulated
# 	in the agreement/contract under which the program(s) have been
# 	supplied.
#
# ********************************************************************
#	Name    : Certificate_expiry_notifier.ps1
# 	Date    : 04/06/2020
# 	Purpose : This file is used to check the log file and
#             provide alert notification when the conditions are met. 
#
# 	Usage   : Certificate_expiry_notifier.ps1 check the log file and provide notification according to severity

# ********************************************************************************************************************************************
# ------------------------------------------------------   SUB  functions   ---------------------------------------------------------------
# ********************************************************************************************************************************************

# *****************************************************************************
#	To check the type of Server
# *****************************************************************************

 function check_ServerType()
 { 
   try
   {  
     if(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager')
     {
        if(Test-Path –Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir)
        {  
           $server_Type=1
        }
	    if(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
		{
		   $server_Type=2
        }
     }
	 elseif((Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora') -AND (!(Test-Path -Path 'HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent')))
	 {
		if(Test-Path -Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path)
		{
			$server_Type=3
		}
	 }
     elseif(Test-Path -Path "C:\Ericsson\NetAnServer\Server")
     {
         $server_Type=4
	 }
	 
     else
     {
         $server_Type=0
     }
   }
   catch
   {
      $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Checking for the type of server failed." >>$script:log
      "Checking for the type of server failed. "+$time_Stamp >>$debuglog_notifier
       EXIT(1)
     } 
   return $server_Type
 }

   
# *****************************************************************************
#	To check if the user is Administrator
# *****************************************************************************

function check_If_Admin 
{
   try
   {
	$user = [Environment]::UserName
	if ($user -ne "Administrator")
    {
       "Administrator has not logged into the server.">> $script:log
       "Administrator has not logged into the server. "+$time_Stamp >> $debuglog_notifier
		EXIT (1)
    }
    else
    { 
       $login=Get-Content -Path $script:log |Select-String -Pattern "Administrator has logged in " | Select-Object -Last 1
        $today=(Get-Date).ToString("dd/MM/yyyy")
        if($login)
        {
		    if($login -match $today)
		    {
               "Administrator has logged into the server again.">>$script:log
               "Administrator has logged into the server again. "+$time_Stamp >>$debuglog_notifier
                EXIT(1)
		     }
            else
            {
               "Administrator has logged in "+$time_Stamp>>$script:log
               check_Instances
             }
         }
        else
        {
		   "Administrator has logged in "+$time_Stamp>>$script:log
		   check_Instances
        }
     }
     }
     catch
     {
       $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Checking  if the logged in user is Administrator in a server failed." >>$script:log
      "Checking  if the logged in user is Administrator in a server failed. "+$time_Stamp >>$debuglog_notifier
       EXIT(1)
     } 
}


# *****************************************************************************
#	To check if the user is Domain Administrator
# *****************************************************************************

function check_If_Domain_Admin 
{
   try
   {
	$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$windowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($user)
	if (!$windowsPrincipal.IsInRole("Domain Admins")) 
    {
     "Domain Administrator has not logged into the server.">> $script:log
      "Domain Administrator has not logged into the server. "+$time_Stamp >> $debuglog_notifier
		EXIT (1)
    }
    else
    { 
        $login=Get-Content -Path $script:log |Select-String -Pattern "Domain Administrator has logged in " | Select-Object -Last 1
        $today=(Get-Date).ToString("dd/MM/yyyy")
        if($login)
        {
		    if($login -match $today)
		    {
               "Domain Administrator has logged into the server again.">>$script:log
               "Domain Administrator has logged into the server again. "+$time_Stamp >>$debuglog_notifier
                EXIT(1)
		     }
            else
            {
               "Domain Administrator has logged in "+$time_Stamp>>$script:log
               check_Instances
             }
         }
        else
        {
		  "Domain Administrator has logged in "+$time_Stamp>>$script:log
		   check_Instances
        }
     } 
     }
     catch
     {
       $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Checking if logged in user is Domain Administrator failed." >>$script:log
      "Checking if logged in user is Domain Administrator failed. "+$time_Stamp >> $debuglog_notifier
       EXIT(1)
     } 
      
}

# **********************************************************************
#	Get the required inputs from configuration file
# **********************************************************************

function get_Inputs_From_File()
{
  try
  {
        [int[]]$frequencyValue=@()
         [int[]]$lowerInterval=@()
		 [int[]]$upperInterval=@()
      foreach($line in Get-Content -Path "C:\Certificate-expiry\config_file.ini")
     {
        if($line -match "_severity")
       {
         try
         {
          $split = "$line".Split("|",3)
          $split_Value = $split[2].Trim()
          $frequencyValue+=$split_Value
          $interval = $split[1].Split("-",2)
          $lowerInterval+=$interval[0]
          $upperInterval+=$interval[1]
         }
         catch
         {
          $errorMessage = $_.Exception.Message
	      $errorMessage >> $script:log
           "Obtaining the intervals and frequency for notification of certificate from the configuration file failed." >>$script:log
            "Obtaining the intervals and frequency for notification of certificate from the configuration file failed. "+$time_Stamp >>$debuglog_notifier
           EXIT(1)
         }  
        }  
     }
    } 
    catch
    {
     $_ >>$script:log
     "Obtaining required inputs from configuration file failed.">>$script:log
     "Obtaining required inputs from configuration file failed. "+$time_Stamp >>$script:log
     EXIT(1)
     }
    return $frequencyValue,$lowerInterval,$upperInterval
}
  

# **************************************************************************
#	Get the required details from certificate expiry check script
# **************************************************************************

function get_Details()
{
     [int[]]$days=@()
     [string[]]$splitLine=@()
     [string[]]$certNames_List = @()
     try
     {       
		if($server_Type -lt 4)
		{
		  powershell -command ". C:\Certificate-expiry\Certificate_expiry_check.ps1"
		}
		
		$req_NetAn = $null
		if($server_Type -eq 2 -OR $server_Type -eq 4)
		{
		$req_NetAn=powershell -command ". C:\Certificate-expiry\Certificate_expiry_check_NetAn.ps1;append_Log_File"

		}

	if($server_Type -lt 4)		
    {
        foreach($certName in $certNames)
        {
            $line=Get-Content -Path  $script:log | Select-String -Pattern "$pattern.$certName" -CaseSensitive | Select-Object -Last 1
            if($line)
            {
                $certNames_List+=$certName
                $splitLine+=$line.ToString().Split( )
                for($i=0;$i -lt $splitLine.Count;$i++)
                {
                    if($splitLine[$i] -match "days")
                    {
                       $daysLeft=[Regex]::Match($line,'in([^/)]+)days') | ForEach-Object { $_.Groups[1].Value}  
                       $days+=$daysLeft
                       $splitLine=$null
                    }
                    elseif($splitLine[$i] -match "today")
                    {
                       $days+=0
                       $splitLine=$null
                    }
					elseif($splitLine[$i] -match "hours")
					{
						$days+=0
						$splitLine=$null
					}
                    elseif($splitLine[$i] -match "expired.")
                    { 
                       $days+=-1
                       $splitLine=$null
                    }   
                 }
            }
            else
            {
               continue
            }
        }

        "The ($days) and ($certNames_List) are obtained.  "+$time_Stamp >>$debuglog_notifier
	}
	
        if(($days.Count -eq 0) -AND ($certNames_List.Count -eq 0) -AND ($req_NetAn -eq $null))
        {
         "No certificate needs to be provided alert,as they are auto renewable.">>$script:log
         "No certificate needs to be provided alert,as they are auto renewable. "+$time_Stamp >>$debuglog_notifier
         EXIT(1)
        }
        else
        {
         "The certificates in this server are checked for providing alert.">>$script:log
         "The certificates in this server are checked for providing alert. "+$time_Stamp >>$debuglog_notifier
        }
	
		if($server_Type -eq 2 -OR $server_Type -eq 4)
		{
			if($req_NetAn -ne $null)
			{
				$parameters=$req_NetAn.Split(" ")
				for($j=0;$j -lt $req_NetAn.Count;$j++)
				{
					if($j -lt ($parameters.Count / 2 ))
					{
						$days+=$parameters[$j]
					}
					else
					{
						$certNames_List+=$parameters[$j]
					}
				}
			}	
		}
     }
     catch
     {
       $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Getting details from the certificate expiry check script failed.  "+$time_Stamp >>$debuglog_notifier
      "Getting details from the certificate expiry check script failed." >>$script:log
       EXIT(1)
     }
    return  $days,$certNames_List
}



# *************************************************************************
#	To check for the instances in which notification should be provided
# *************************************************************************

function check_Instances
{
$days,$certNames_List=get_Details
$freq,$low_Limit,$up_Limit=get_Inputs_From_File
$instance=@()
  try
  { 
    for($j=0;$j -lt $days.Count;$j++)
    {
        :OutOfNestedFor_LABEL #This is the label where break will re-direct the script to

        for($i=$freq.Count-1;$i -ge 0;$i--)
        {
          if ($days[$j] -le $up_Limit[$i] -and $days[$j] -ge $low_Limit[$i])
          {
             if ($days[$j] -eq $up_Limit[$i] -or $days[$j] -eq $low_Limit[$i])
             {
               $instance+=1
               Break :OutOfNestedFor_LABEL
             }
             else
             {
	           $minor=$up_Limit[$i]-$days[$j]
                if(($minor%$freq[$i]) -eq 0)
	             {
                  $instance+=1
	             }
			     else
			     {
                   $instance+=0
			     } 
	     	   Break :OutOfNestedFor_LABEL
            }
           }
           elseif($days[$j] -lt 0)
           {
                $instance+=1
                Break :OutOfNestedFor_LABEL
           }
		   else
		   {
                 if($i -eq 0)
		         {
		           $instance+=0
                   Break :OutOfNestedFor_LABEL			  
			     }
			     else
			     {
                  Continue :OutOfNestedFor_LABEL
			     }
		   }
		 }  
     }
	  $occur_int=(0..($instance.Count-1)) |where {$instance[$_] -eq '1'}
      $notification_String=get_Notification_String
      $notify_String=$notification_String | Out-String
      check_For_Notifications
    }
    catch
    {
      $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Checking the instances for notification of certificates failed.  "+$time_Stamp >>$debuglog_notifier
      "Checking  the instances for notification of certificates failed." >>$script:log
       EXIT(1)
     }      
}


# *****************************************************************************
#	To check for the notifications to be provided according to the instances
# *****************************************************************************

function check_For_Notifications
{   
  try
  {
      if($notify_String)
      {
         "Notification string for the certificates in this server is present.  "+$time_Stamp >>$debuglog_notifier
        [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
        [Microsoft.VisualBasic.Interaction]::MsgBox($notify_String, "OKOnly,SystemModal,Information", "Expiry of certificates") 
         for($m=0;$m -lt $occur_int.Count;$m++)
         {
	         "Alert for the expiry of "+$certNames_List[$occur_int[$m]]+" certificate is given on "+$time_Stamp>>$script:log
         }
         "---------------------------------------------------------------" >> $script:log
       }
       else
       {
           "No certificate in this server matches the criteria for alert.">>$script:log
           "No certificate in this server matches the criteria for alert.  "+$time_Stamp >>$debuglog_notifier
           "---------------------------------------------------------------" >> $script:log
        }
   }
   catch
   {
      $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Checking for the display of notification failed.  "+$time_Stamp >>$debuglog_notifier
      "Checking  for the display of notification failed." >>$script:log
       EXIT(1)
     }      
 }



# *****************************************************************************
#	To get the string to be notified in the message box
# *****************************************************************************

 function get_Notification_String()
{
 $notification_String=New-Object string[] $certNames_List.Count
try
{

      if( $occur_int.Count -ne 0 )
      {  	
        for($j=0;$j -lt $occur_int.Count;$j++)
        {
              :OutofForloop_LABEL 
               
            for($i=0;$i -lt $days.Count;$i++)
            {
                 if($occur_int[$j] -eq $i)
                 {
                    if($days[$i] -lt 0)
                    {
                         $notification_String[$i]="The $($certNames_List[$i]) certificate has expired."
                         Break :OutofForloop_LABEL
                     }
                     elseif($days[$i] -eq 0)
                     {
                        $notification_String[$i]="The $($certNames_List[$i]) certificate expires in less than 24 hours."
                         Break :OutofForloop_LABEL
                      }
                      else
                      {                      
                         $notification_String[$i]="The $($certNames_List[$i]) certificate expires in $($days[$i]) days."
                          Break :OutofForloop_LABEL
                       }
                 }
                  else
                  {
                      Continue :OutofForloop_LABEL
                   }
              }
            }
        $notification_String=$notification_String+"`r`n Please renew the certificate(s)."
     }   
     else
     {
      "Notification string is null for the certificates present in this server.  "+$time_Stamp >>$debuglog_notifier
       $notification_String=$null
      }
     
}
catch
{
      $errorMessage = $_.Exception.Message
	  $errorMessage >> $script:log
      $_ >>$script:log
      "Checking for the notification string to display failed.  "+$time_Stamp >>$debuglog_notifier
      "Checking for the notification string to display failed." >>$script:log
       EXIT(1)
 }      
return $notification_String

}



# ************************************************************************************************************************************************
# -----------------------------------------------------------MAIN() function----------------------------------------------------------------------
# ************************************************************************************************************************************************

     $time_Stamp=(Get-Date).ToString("dd/MM/yyyy HH:mm:ss")
     $timeStampDefault=Get-Date -Format yyyyMMdd
     $script:log="C:\Certificate-expiry\log\certificate_expiry_log.log"
if(Test-Path -Path $script:log)
{
      $pattern="The"
     $serverCert=(Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
     $serverCertRDP = (Get-WmiObject win32_computersystem).DNSHostName+"_RDP"
     $serverCertSSO = (Get-WmiObject win32_computersystem).DNSHostName+"_SSO"
     $serverCertTLS = (Get-WmiObject win32_computersystem).DNSHostName+"_TLS"
     $certNames=@('ENM_PKI_Root_CA','ENM_External_Entity_CA',"CA-Signed_$serverCert","Self-Signed_$serverCert","$serverCertRDP","$serverCertSSO","$serverCertTLS",'Server','CA-Signed_tomcatssl','Self-Signed_tomcatssl') 
     $lookup=@()
     $instance=@()
     $occur=@()
     $server_Type=check_ServerType
      #Creation of log files under install_config folder 
          if($server_Type -eq 1 -OR $server_Type -eq 2)
          {  
			if(Test-Path "C:\ebid\install_config")
			{
			  New-Item -ItemType Directory -Path C:\ebid\install_config\cert_log -erroraction 'silentlycontinue' | out-null
              $debuglog_notifier="C:\ebid\install_config\cert_log\certificate_log_$timeStampDefault.txt"
              "-------------------------------------------------------------">>$debuglog_notifier
			  "Certificate expiry notifier script started on "+$time_Stamp >> $debuglog_notifier
              "-------------------------------------------------------------">>$debuglog_notifier
			}
			else
			{
			"install_config folder not present.">>$script:log
			}
		  }
		  elseif($server_Type -eq 3)
		  {
			if(Test-Path "C:\OCS-without-Citrix\install_config")
			 {				 	
			     New-Item -ItemType Directory -Path C:\OCS-without-Citrix\install_config\cert_log -erroraction 'silentlycontinue' | out-null
                 $debuglog_notifier="C:\OCS-without-Citrix\install_config\cert_log\certificate_log_$timeStampDefault.txt"
                 "-------------------------------------------------------------">>$debuglog_notifier
                 "Certificate expiry notifier script started on "+$time_Stamp >> $debuglog_notifier
                 "-------------------------------------------------------------">>$debuglog_notifier
	        }
			else
			{
				New-Item -ItemType Directory -Path C:\OCS-without-Citrix\install_config -erroraction 'silentlycontinue' | out-null
				New-Item -ItemType Directory -Path C:\OCS-without-Citrix\install_config\cert_log -erroraction 'silentlycontinue' | out-null
                 $debuglog_notifier="C:\OCS-without-Citrix\install_config\cert_log\certificate_log_$timeStampDefault.txt"
                 "-------------------------------------------------------------">>$debuglog_notifier
                 "Certificate expiry notifier script started on "+$time_Stamp >> $debuglog_notifier
                 "-------------------------------------------------------------">>$debuglog_notifier
			}
		  }	
	      else
	      {
		     if(Test-Path "C:\OCS\install_config")
			 {
			     New-Item -ItemType Directory -Path C:\OCS\install_config\cert_log -erroraction 'silentlycontinue' | out-null
                 $debuglog_notifier="C:\OCS\install_config\cert_log\certificate_log_$timeStampDefault.txt"
                 "-------------------------------------------------------------">>$debuglog_notifier
                 "Certificate expiry notifier script started on "+$time_Stamp >> $debuglog_notifier
                 "-------------------------------------------------------------">>$debuglog_notifier
	        }
			else
			{
				if($server_Type -eq 0)
				{
			     New-Item -ItemType Directory -Path C:\OCS\install_config -erroraction 'silentlycontinue' | out-null
			     New-Item -ItemType Directory -Path C:\OCS\install_config\cert_log -erroraction 'silentlycontinue' | out-null
                 $debuglog_notifier="C:\OCS\install_config\cert_log\certificate_log_$timeStampDefault.txt"
                 "-------------------------------------------------------------">>$debuglog_notifier
			     "Certificate expiry notifier script started on "+$time_Stamp >> $debuglog_notifier
                 "-------------------------------------------------------------">>$debuglog_notifier            			  
				 }
             }
           }
	       

# **********************************************************************
# --------------------------Start of Script----------------------------- 
# **********************************************************************


"---------------------------------------------------------------" >> $script:log
	 "Certificate expiry notifier script started on "+$time_Stamp >> $script:log
"---------------------------------------------------------------" >> $script:log
	 "Checking for certificates that has to be notified.."  >> $script:log
     if($server_Type -ge 1)
     {
        check_If_Admin
        "*************************************************************************************">>$debuglog_notifier
     }
     else
     {
         check_If_Domain_Admin    
         "************************************************************************************">>$debuglog_notifier
     }
    }
    else
    {
      EXIT(1)
     }
    