
#   (c) Ericsson Radio Systems AB 2020 - All rights reserved.
#   The copyright to the computer program(s) herein is the property
# 	and/or copied only with the written permission from Ericsson Radio
# 	Systems AB or in accordance with the terms and conditions stipulated
# 	in the agreement/contract under which the program(s) have been
# 	supplied.
#
# **************************************************************************************
#	Name    : Certificate_expiry_check.ps1
# 	Date    : 04/06/2021
# 	Purpose : This file is used to find the expiry date
#             of the certificates and log the required details 
#             in the log file.   	
#
# 	Usage   : Certificate_expiry_check.ps1  find expiry date and log the information

# ********************************************************************************************************************************************
# ------------------------------------------------------   SUB  functions   ---------------------------------------------------------------
# ********************************************************************************************************************************************

# ********************************************************************************
#         To Check if server is Active directory
# ********************************************************************************
function CheckAD()
{
    try
    {
        Get-ADForest | Out-Null
        return $true
    }
    catch
    {
        $_ >>$debuglog
        return $false
    }
}


# *****************************************************************************
#	To check the type of Server
# *****************************************************************************

 function check_ServerType()
 {  
  [string[]]$purpose,[string[]]$rdp_Thumbprint,[string[]]$test_Certificate,[string[]]$thumbprint_Values,[string[]]$sample_Thumbprint=@()
  [string[]]$test_Detail,[string[]]$test_Certname,[string[]]$httpCert_Thumbprint,[string[]]$spec_Sample_Thumbprint,[string[]]$spec_Thumbprint_Values=@()
  [string[]]$test_Thumbprint=$null
   $OCS_path='Cert:\LocalMachine\My'

   try
   { 
       if(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager')
	   {
          if(Test-Path -Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir)
          {  
		  $bi_install_dir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
	      Copy-Item "C:\Certificate-expiry\Keystore.jsp" -Destination $bi_install_dir"\tomcat\webapps\AdminTools\" -Force
	      $tomcat_path="$bi_install_dir"+"tomcat\"
	      $serverXmlPath = "$tomcat_path\conf\server.xml"
	      $xml = [xml](Get-Content $serverXmlPath)
	      $keyPass =([String]($xml.Server.Service.Connector.keystorePass)).trim()
	      $path =([String]($xml.Server.Service.Connector.keystoreFile)).trim()
	      $filepath=$path.replace('\','//')
          $output = cscript C:\ebid\install_config\wget_custom.js http://$env:computername`:8080/AdminTools/Keystore.jsp?keystorePass=$keyPass`&keystorePath=$filepath
          $next = Get-Content C:\Certificate-expiry\expiry_log.log | %{ $test =$_ -split ':'}
          $last = $test[$test.Count - 1]
	      $arrayk = $last.trim()
		  $rdp_cert_thumbprint = (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices).SSLCertificateSHA1Hash
		  $cert_count_expiry = Get-ChildItem -path Cert:\localmachine\my\$rdp_cert_thumbprint -erroraction silentlycontinue
             $server_Type=1
             $deployment="BO"
			 $SSL=check_If_Tomcatssl_Present
			 if ($SSL -match "CA-Signed_tomcatssl" )
			 {
				if([int]$arrayk -ge 0)
				{
					if($cert_count_expiry -ne $null)
					{
					$purpose="BO Web Applications, Remote Desktop Services"
					}
					else
					{
					$purpose="BO Web Applications"
					}
				}
				else
				{
				$purpose="BO Web Applications"
				}
			 }
			 elseif($SSL -match "Self-Signed_tomcatssl")
			 {
				$purpose="BO Web Applications"
			 }
			 else
			 {
				$purpose=$null
			 }
				$function="BO Web Applications"
             "The current server is BO server.  "+$time_Stamp >>$debuglog
          }
	      else
	      {
	        continue
	      }
       }
	   elseif((Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora') -AND (!(Test-Path -Path 'HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent')))
		{
			
			if(Test-Path -Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path)
			{ 	
				"The current server is OCS without Citrix server with BO Client installed.  "+$time_Stamp >>$debuglog
				$server_Type=2
				$deployment="OCS-without-Citrix"
				$rdp_Thumbprint = ((Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices).SSLCertificateSHA1Hash).Split(" ")
				$test_Value=(Get-ChildItem $OCS_path | Select-Object Thumbprint | Select-String -Pattern "$serverCertRDP" -CaseSensitive -SimpleMatch).Line
				if($test_Value -match $rdp_Thumbprint[0])
				{
					$purpose= "Remote Desktop Services"
				}	
				else
				{
					$purpose = $null
				}
				
			}
			else
			{
				continue
			}	
			
		}
       else
       {
          $count=0
          $server_Type=0
          [string[]]$certificate_Names=@("$serverCert","$serverCertRDP","$serverCertTLS","$serverCertSSO")
          $rdp_Thumbprint = ((Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices).SSLCertificateSHA1Hash).Split(" ")
          #Get the tls certificate detail if present
          if(Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd")
          {
             $tls_Cert=Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd" -Name "SSLEnabled"
          }
          else
          {
            $tls_Cert=$null
          }

           ForEach($certificate_Name in $certificate_Names)
           {
                $test_Value=(Get-ChildItem $OCS_path | Select-Object Subject,NotBefore,NotAfter,Thumbprint | Select-String -Pattern "$certificate_Name" -CaseSensitive -SimpleMatch).Line
                 if($test_Value)
                 {
                      "Some Server certificates are present in Cert:\LocalMachine\My folder.  "+$time_Stamp >>$debuglog
                      $count+=1
                      $test_Certificate=$test_Value.Split('}')
                      $test_Certificate=$test_Certificate | ? {$_}

                      for($i=0;$i -lt $test_Certificate.Count;$i++)
                      {
                             $test_Detail=$test_Certificate[$i].Split(";")
                             $test_Certname=$test_Detail[0].Split(",")
                             if($certificate_Name -match "$serverCert")
                             {
                                if($test_Certname[1]  -match "OU=Ericsson-ENM" -or $test_Certname[1] -match "OU=Ericsson-ENIQ")
                                {
                                    $sample_Thumbprint=$test_Detail[3].Split("=",2)
                                    $thumbprint_Values+=$sample_Thumbprint[1]
                                }
                                else
                                {
                                    $test_Path_SSO="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates"
                                    if(Test-Path -Path $test_Path_SSO)
                                    {
                                      $sample_Thumbprint=$test_Detail[3].Split("=",2)
                                      $thumbprint_Values+=$sample_Thumbprint[1]
                                    }
                                    else
                                    {
                                      continue
                                    }
                                }
                              }
                              else
                              {
                                 if($test_Certname[1]  -match "OU=Ericsson-ENM" -or $test_Certname[1] -match "OU=Ericsson-ENIQ")
                                 {
                                    $spec_Sample_Thumbprint=$test_Detail[3].Split("=",2)
                                    $spec_Thumbprint_Values+=$spec_Sample_Thumbprint[1]
                                 }
                                 else
                                 {
                                      continue
                                 }
                              } 
                          $test_Detail=$null
                          $test_Certname=$null
                       }
                   }
                   else
                   {
                    $count+=$null
                   }
             }
        
             if(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent")
             {
                $deployment="OCS-VDA"
                 ForEach($certificate_Name in $certificate_Names)
                 {
                       if($certificate_Name -match "$serverCert")
                       { 
                              for($k=0;$k -lt $thumbprint_Values.Count;$k++)
                              {
                                   if(($thumbprint_Values[$k] -match $rdp_Thumbprint[0]) -and ($tls_Cert -eq 1))
                                   {
                                        $tls_Cert_Present=1
                                        $rdp_Cert_Present=1
                                        $purpose+="OCS Web Applications,Remote Desktop Services"
                                        $test_Thumbprint+=$thumbprint_Values[$k]
                                        break
                                   }
                                   elseif(!($thumbprint_Values[$k] -notmatch $rdp_Thumbprint[0]) -and ($tls_Cert -eq 1))
                                   {
                                        $tls_Cert_Present=1
                                        $purpose+="OCS Web Applications"
                                        $test_Thumbprint+=$thumbprint_Values[$k]
                                        break
                                   }
                                   elseif(($thumbprint_Values[$k] -match $rdp_Thumbprint[0]) -and ($tls_Cert -ne 1))
                                   {
                                        $rdp_Cert_Present=1
                                        $purpose+="Remote Desktop Services"
                                        $test_Thumbprint+=$thumbprint_Values[$k]
                                        break
                                   }
                                   else
                                   {
                                     continue
                                   }
                              }
                              "The purpose of Server certificate is $purpose.  "+$time_Stamp >>$debuglog
                        }
                       else
                       {
                            ForEach($spec_Thumbprint_Value in $spec_Thumbprint_Values)
                            {
                                if(($spec_Thumbprint_Value -match $rdp_Thumbprint[0]) -and ($certificate_Name -match "$serverCertRDP"))
                                {
                                   $rdp_Cert_Present=1
                                   break
                                }
                                elseif(($tls_Cert -eq 1) -and ($certificate_Name -match "$serverCertTLS"))
                                {
                                   $tls_Cert_Present=1
                                   break
                                }
                                else
                                {
                                   continue
                                }
                            }
                         }
                 }
                 if($count -gt 0)
                 { 
                     if(($tls_Cert_Present -eq 1) -and ($rdp_Cert_Present -eq 1))
                     {
                         $function="Remote Desktop Connection,TLS Configuration"
                     }
                     elseif(($tls_Cert_Present -eq 1) -and ($rdp_Cert_Present -ne 1))
                     {
                         $function="TLS Configuration"
                     }
                     elseif(($tls_Cert_Present -ne 1) -and ($rdp_Cert_Present -eq 1))
                     {
                         $function="Remote Desktop Connection"
                     }
                     else
                     {
                           $function="TLS Configuration"
                     }
                     "The current server is OCS-VDA server.  "+$time_Stamp >>$debuglog
                 }
                 else
                 {
                     "No certificates are found in Cert:\LocalMachine\My folder.  "+$time_Stamp >>$debuglog
                     "Install the required certificates in the server.">>$script:log
                     EXIT(1)
                 }         
              }
             elseif(Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller")
             {
                  $deployment="OCS-CCS"
                   Get-ChildItem -Path IIS:SSLBindings | ForEach-Object -Process `
                   {
                     $httpCert_Thumbprint= $_.Thumbprint
                   }
                     ForEach($certificate_Name in $certificate_Names)
                     {  
                         if($certificate_Name -match "$serverCert")
                         {  
                               for($k=0;$k -lt $thumbprint_Values.Count;$k++)
                               { 
                                 if($httpCert_Thumbprint.Count -gt 0)
                                 {
                                    for($l=0;$l -lt $httpCert_Thumbprint.Count;$l++)
                                    { 
                                      if(($thumbprint_Values[$k] -match $rdp_Thumbprint[0]) -and ($thumbprint_Values[$k] -match $httpCert_Thumbprint[$l]))
                                      {
                                        $http_Cert_Present=1
                                        $rdp_Cert_Present=1
                                        $purpose+="OCS Web Applications,Remote Desktop Services"
                                        $test_Thumbprint+=$thumbprint_Values[$k]
                                        break
                                      }
                                      elseif(($thumbprint_Values[$k] -notmatch $rdp_Thumbprint[0]) -and ($thumbprint_Values[$k] -match $httpCert_Thumbprint[$l]))
                                      {
                                        $http_Cert_Present=1
                                        $purpose+="OCS Web Applications"
                                        $test_Thumbprint+=$thumbprint_Values[$k]
                                        break
                                      }
                                      elseif(($thumbprint_Values[$k] -match $rdp_Thumbprint[0]) -and ($thumbprint_Values[$k] -notmatch $httpCert_Thumbprint[$l]))
                                      {
                                        $rdp_Cert_Present=1
                                        $purpose+="Remote Desktop Services"
                                        $test_Thumbprint+=$thumbprint_Values[$k]
                                        break
                                      }
                                      else
                                      {
                                        continue
                                      } 
                                    }
                                 }
                                 else
                                 {
                                      if($thumbprint_Values[$k] -match $rdp_Thumbprint[0])
                                      {
                                        $rdp_Cert_Present=1
                                        $purpose+="Remote Desktop Services"
                                        $test_Thumbprint+=$thumbprint_Values[$k]
                                        break
                                      }
                                      else
                                      {
                                       continue
                                      }
                                  }
                                }
                              "The purpose of server certificate is $purpose.  "+$time_Stamp >>$debuglog
                         }
                         else
                         {
                           ForEach($spec_Thumbprint_Value in $spec_Thumbprint_Values)
                           {
                             if(($spec_Thumbprint_Value -match $rdp_Thumbprint[0]) -and ($certificate_Name -match "$serverCertRDP"))
                             {
                                $rdp_Cert_Present=1
                                break
                             }
                             else
                             {
                               continue
                             }
                           }
                         }
                     } 
                     if($count -gt 0)
                     {
                         if(($http_Cert_Present -eq 1) -and ($rdp_Cert_Present -eq 1))
                         {
                              $function="OCS Web Applications,Remote Desktop Connection"
                         }
                         elseif(($http_Cert_Present -eq 1) -and ($rdp_Cert_Present -ne 1))
                         {
                              $function="OCS Web Applications"
                         }
                         elseif(($http_Cert_Present -lt 0) -and ($rdp_Cert_Present -eq 1))
                         {
                              $function="Remote Desktop Connection"
                         }
                         else
                         {
                                $function="OCS Web Applications"
                         }
                      "The current server is OCS-CCS server.  "+$time_Stamp >>$debuglog
                    }
                    else
                    {
                        "No server certificate is present in Cert:\LocalMachine\My folder.  "+$time_Stamp >>$debuglog 
                        "Install the required certificates in the server.">>$script:log
                        EXIT(1)
                     }        
               }
             else
             {
                  $server_Check=CheckAD
                       if($server_Check)
                       {
                          $deployment="OCS-ADDS"
                 
                             ForEach($certificate_Name in $certificate_Names)
                             {
                                if($certificate_Name -match "$serverCert")
                                {               
                                   for($i=0;$i -lt $thumbprint_Values.Count;$i++)
                                   {
                                     $test_Path="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates"+$thumbprint_Values[$i]
                                     if((Test-Path -Path $test_Path) -and ($thumbprint_Values[$i] -match $rdp_Thumbprint[0]))
                                     {
                                       $rdp_Cert_Present=1
                                       $sso_Cert_Present=1
                                       $purpose+="SSO configuration,Remote Desktop Services"
                                       $test_Thumbprint+=$thumbprint_Values[$i]
                                       break
                                     }
                                     elseif((Test-Path -Path $test_Path) -and !($thumbprint_Values[$i] -match $rdp_Thumbprint[0]))
                                     {
                                       $sso_Cert_Present=1
                                       $purpose+="SSO configuration"
                                       $test_Thumbprint+=$thumbprint_Values[$i]
                                       break
                                     }
                                     elseif(!(Test-Path -Path $test_Path) -and ($thumbprint_Values[$i] -match $rdp_Thumbprint[0]))
                                     {
                                       $rdp_Cert_Present=1
                                       $purpose+="Remote Desktop Services"
                                       $test_Thumbprint+=$thumbprint_Values[$i]
                                       break
                                     }
                                     else
                                     {
                                       continue
                                     } 
                                   }
                                }
                                else
                                {
                                      ForEach($spec_Thumbprint_Value in $spec_Thumbprint_Values)
                                      {
                                         $test_Path_Server="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates"+$spec_Thumbprint_Value
                                         if(($spec_Thumbprint_Value -match $rdp_Thumbprint[0]) -and ($certificate_Name -match "$serverCertRDP"))
                                         {
                                             $rdp_Cert_Present=1
                                             break
                                         }
                                         elseif((Test-Path -Path $test_Path_Server) -and ($certificate_Name -match "$serverCertSSO"))
                                         {
                                             $sso_Cert_Present=1
                                             break
                                         }
                                         else
                                         {
                                             continue
                                         }
                                      }
                                 }
                             }
                          if($count -ge 1)
                          {
                             if(($sso_Cert_Present -eq 1) -and ($rdp_Cert_Present -eq 1))
                             {
                                 $function="Remote Desktop Connection,SSO Configuration"
                             }
                             elseif(($sso_Cert_Present -eq 1) -and ($rdp_Cert_Present -ne 1))
                             {
                                 $function="SSO Configuration"
                             }
                             elseif(($sso_Cert_Present -ne 1) -and ($rdp_Cert_Present -eq 1))
                             {
                                 $function="Remote Desktop Connection"
                             }
                             else
                             {
                                 $function="SSO configuration"
                             }
                            "The current server is OCS-ADDS server.  "+$time_Stamp >>$debuglog
                         }
                          else
                          {
                             "No certificates are present in the Cert:\LocalMachine\My folder.  "+$time_Stamp >>$debuglog 
                             "The certificates in this server will be auto renewed." >>$script:log
                              EXIT(1)
                          }
                       }
                       else
                       {
                          "Error in GetADForest function.  "+$time_Stamp >>$debuglog
                           EXIT(1)
                       }
               } 
        }
    }
    catch
    {
     $_ >>$debuglog
     "Checking for the type of server failed.  "+$time_Stamp >>$debuglog
     "Checking for the type of server failed." >>$script:log
     EXIT(1)
    }   
   return $server_Type,$deployment,$purpose,$test_Thumbprint,$function,$arrayk
 }
   
# *****************************************************************************
#	To check the presence of tomcatssl certificate
# *****************************************************************************

function check_If_Tomcatssl_Present
{
 try
 {
	if($server_Type -eq 1)
    {
	  $bi_install_dir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
	  Copy-Item "C:\Certificate-expiry\Keystore.jsp" -Destination $bi_install_dir"\tomcat\webapps\AdminTools\" -Force
	   $tomcat_path="$bi_install_dir"+"tomcat\"
	   $serverXmlPath = "$tomcat_path\conf\server.xml"
	   $xml = [xml](Get-Content $serverXmlPath)
	   $keyPass =([String]($xml.Server.Service.Connector.keystorePass)).trim()
	   $path =([String]($xml.Server.Service.Connector.keystoreFile)).trim()
    }
    else
    {
       "Tomcatssl certificate is not present in this server.  "+$time_Stamp >>$debuglog
    }
       if ($path -match "C:\\ebid\\SSL\\CA\\cert\\tomcatssl.bin")
       {
     	  $SSL = "CA-Signed_tomcatssl"
       }
   	   elseif ($path -match "C:\\ebid\\SSL\\cert\\tomcatssl.bin")
	   {
	      $SSL = "Self-Signed_tomcatssl"
 	   }
	   else
       {
          $SSL=$null
       }
    } 
    catch
    {
       $_ >>$debuglog
       "Checking for the presence of tomcatssl certificate failed.  "+$time_Stamp >>$debuglog
        "Checking for the presence of tomcatssl certificate failed." >>$script:log
       EXIT(1)
    }
    return $SSL
	"$SSL is present in the server.  "+$time_Stamp >>$debuglog
} 
 
# **********************************************************************
#	Get the required inputs from configuration file
# **********************************************************************

function get_Inputs_From_File
{
    try
    {
          foreach($line in Get-Content -Path "C:\Certificate-expiry\config_file.ini")
          {
			if($line -match "SSL_Auto_Renewal")
			{			
				$split = "$line".split("=",2)			
				$global:SSLAutoValue = $split[1].Trim()								
			}
          }
    } 
    catch
    {
     $_ >>$debuglog
     "Getting inputs from config file failed.  "+$time_Stamp >>$debuglog
     "Getting inputs from config file failed." >>$script:log
     EXIT(1)
    }
}
  

# **********************************************************************
#	Get the days before expiry of all the certificates
# **********************************************************************

function get_Expiry_Date()
{
    [System.Collections.ArrayList]$certNames_List=$certNames
	[int[]]$day=@()
    [string[]]$expiryDate=@()
  try
  {
     $cert_Array,$cert_Thumbprint=get_Certificate_Details
     #cert_Array contains the name,start date,end date,thumbprint of the certificates present in the server
     if($cert_Array.Count -ne 0)
     {
        "The details of expected certificates are obtained successfully...  "+$time_Stamp >>$debuglog
        for($j=0;$j -lt $cert_Array.Count;$j++)
        {
          if($cert_Array[$j] -match "NotAfter=")
          {  
			#"The details of expected certificates are obtained successfully-... $cert_Array[$j]  "+$time_Stamp >>$debuglog
              $endat=$cert_Array[$j].Split("=",2)
			  #"The details of expected certificates are obtained successfully1... $endat[0]  "+$time_Stamp >>$debuglog
               $format=$endat[1]
			  # "The details of expected certificates are obtained successfully2... $endat[1]  "+$time_Stamp >>$debuglog
              try
              {
                 $converted_Date = [datetime]::ParseExact($format,'MM/dd/yyyy HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
                 #"The details of expected certificates are obtained successfully3... $converted_Date  "+$time_Stamp >>$debuglog
                 $expiryDate+= Get-Date $converted_Date -Format "dd/MM/yyyy"
				 #"The details of expected certificates are obtained successfully4... $expiryDate  "+$time_Stamp >>$debuglog
              }
              catch [System.Management.Automation.MethodInvocationException]
              { 
                 $converted_Date = $format
                 $expiryDate+= Get-Date $converted_Date -Format "dd/MM/yyyy"
              } 
             if(((New-TimeSpan -Start (Get-Date) -End $converted_Date).Days) -eq 0)
			{
				$minutes = ((New-TimeSpan -Start (Get-Date) -End $converted_Date).Minutes) 
				#"The details of expected certificates are obtained successfully8... $minutes  "+$time_Stamp >>$debuglog
				if(((New-TimeSpan -Start (Get-Date) -End $converted_Date).Minutes) -lt 0)
				{
					#"The details of expected certificates are obtained successfully9... $day  "+$time_Stamp >>$debuglog
					$day+= -1;
				}
				else
				{
					$day+=(New-TimeSpan -Start (Get-Date) -End $converted_Date).Days
				}
			}
			else
			{
				$day+=(New-TimeSpan -Start (Get-Date) -End $converted_Date).Days
			}
           }
           else
           {
              continue
           }
         }
	     if($arrayk -ne $null)
         {
	         $day=$day+$arrayk
             $expiryDate=$expiryDate+$lastdate
         }
         else
         {
	        $expiryDate=$expiryDate
            $day=$day
         }
     }
     else
     {
       "Only tomcatssl certificate is present in the server.  "+$time_Stamp >>$debuglog
       $expiryDate=$lastdate
       $day=$arrayk
     }
   }
   catch
   {
         $errorMessage = $_.Exception.Message
	     $errorMessage >> $debuglog
          $_ >>$debuglog
         "Obtaining the no of days left for expiry of certificate failed." >>$script:log
		 "Obtaining the no of days left for expiry of certificate failed.  "+$time_Stamp >>$debuglog
          EXIT(1)
   }
   return $expiryDate,$day,$certNames_List,$cert_Thumbprint
}


# **********************************************************************
#	Get the details of the certificate to process 
# **********************************************************************

 function get_Certificate_Details()
 {
    $cert_Prop_Array=New-Object string[] $certNames_List.Count
    [string[]]$certificate_Present,[string[]]$certPatterns_Array,[string[]]$cert_Thumbprint=@()
    $cert_Array=New-Object string[] $certNames_List.Count
    [int[]]$certificate_Not_Found,[string[]]$cert_Detail,[string[]]$cert_DetailName,[string[]]$cert_Prop_Line=@()

    try
    {
      
      ForEach($path in $paths)
      {    
        $pathIndex=[array]::IndexOf($paths,$path)
    
        :OutOfNestedForEach_LABEL #This is the label where break will re-direct the script to
       
          Foreach($certPattern in $certPatterns)
          {
              $patternIndex=[array]::IndexOf($certPatterns,$certPattern)
              $path_Split=$path.Split(":")
              #To get the required certificates present in the Cert folder. 
              if($path_Split[0] -match "Cert")
              {
                   "The certificates present in cert folder is being checked..  "+$time_Stamp >>$debuglog
                   $cert_Prop_Array=Get-ChildItem $path | Select-Object Subject,NotBefore,NotAfter,Thumbprint | Select-String -Pattern  $certPattern -CaseSensitive -SimpleMatch
                   $cert_Prop_Array_Line=($cert_Prop_Array).Line
                   if($cert_Prop_Array_Line)
                   {
                      "The expected $certPattern is found in the server.  "+$time_Stamp >>$debuglog
                      $certificate_Present=$cert_Prop_Array_Line.Split('}')
                      $certificate_Present=$certificate_Present | ? {$_}
                      
                        if(($certPattern -match "$serverCert") -and ($certificate_Present.Count -eq 1))
                        {
						   if($server_Type -eq 0)
						   {
                             $cert_Detail+=$certificate_Present.Split(";")
                             $cert_Thumbprint_Full=$cert_Detail[3].Split("=",2)
                             $cert_Thumbprint=$cert_Thumbprint_Full[1]
                             $cert_DetailName+=$cert_Detail[0].Split(",")
                             if($deployment -match "OCS-ADDS")
                             {                       
                                  if($cert_DetailName[1]  -match "OU=Ericsson-ENM" -or $cert_DetailName[1] -match "OU=Ericsson-ENIQ")
                                  {
                                      $certNames_List[$pathIndex]="CA-Signed_"+$certNames_List[$pathIndex]
                                  }
                                  else
                                  {
                                     $certNames_List[$pathIndex]="Self-Signed_"+$certNames_List[$pathIndex]
                                  }
                             }
                             else
                             {                             
                                  if($cert_DetailName[1]  -match "OU=Ericsson-ENM" -or $cert_DetailName[1] -match "OU=Ericsson-ENIQ")
                                  {
                                      $certNames_List[$pathIndex]="CA-Signed_"+$certNames_List[$pathIndex]
                                  }
                                  else
                                  {
                                        $certPatterns=$certPatterns | Where-Object {$_ -ne $certPattern}
                                        $certificate_Not_Found+=1
                                        Break :OutOfNestedForEach_LABEL
                                  }

                             }
                           }
                           else
                           {
                             $certPatterns=$certPatterns | Where-Object {$_ -ne $certPattern}
                             $certificate_Not_Found+=1
                             Break :OutOfNestedForEach_LABEL
                         }  
				       }
                      else
                      {
                         "......................................................">>$debuglog
                      }
                      #To get the required certificate from multiple certificates of a same type of certificates. 
                      if($certificate_Present.Count -gt 1)
                      {
                          "Checking for the multiple certificate present in the server...  "+$time_Stamp >>$debuglog
                          $recent_Cert_Index,$cert_Thumbprint=check_For_Multiple_Certificates
                          if($recent_Cert_Index.Count -ne 0)
                          {
                             $cert_Prop_Line=$null
                             for($i=0;$i -lt $recent_Cert_Index.Count;$i++)
                             {
                                 $cert_Prop_Line+=$certificate_Present[$recent_Cert_Index[$i]]
                             }
                          } 
                          else
                          { 
                              $certPatterns=$certPatterns | Where-Object {$_ -ne $certPattern}
                              $certificate_Not_Found+=1
                              Break :OutOfNestedForEach_LABEL
                          }               
                       }
                       else
                       {
                          "Only one certificate is present in the server.  "+$time_Stamp >>$debuglog
                           $cert_Prop_Line=$certificate_Present
                       } 
                       $certificate_Not_Found+=0
                       $cert_Array+=$cert_Prop_Line.Split(";")                       
                       $certPatterns=$certPatterns | Where-Object {$_ -ne $certPattern}
                       Break :OutOfNestedForEach_LABEL
               }
                   else
                   {  
                     "The $certPattern certificate is not present in the server.  "+$time_Stamp >>$debuglog 
                      $certificate_Not_Found+=1
                      $certPatterns=$certPatterns | Where-Object {$_ -ne $certPattern}
                      Break :OutOfNestedForEach_LABEL
                   }  
              }
             #To find the required certificate present in the C drive.
              else
              {
                 if(Test-Path $path)
                 {
                     "The expected certificate path is present in the server.  "+$time_Stamp >>$debuglog
                     $cert_Prop_Array_Line=Get-ChildItem $path -Recurse  | where {$_.Name -like $certPattern} | Import-Certificate -CertStoreLocation Cert:\LocalMachine\My
                     if($cert_Prop_Array_Line)
                     {
                        "The expected server.crt certificate  present in the server.  "+$time_Stamp >>$debuglog
                        $cert_Array+="NotAfter="+$cert_Prop_Array_Line.GetExpirationDateString()
                        $certPatterns=$certPatterns | Where-Object {$_ -ne $certPattern}
                        $certificate_Not_Found+=0
                     }
                     else
                     {
                        "Server.crt certificate is not present.  "+$time_Stamp >>$debuglog
                        Continue :OutOfNestedForEach_LABEL
                     }
                 }
                 else
                 {
                     "The path for server.crt certificate is not present. "+$time_Stamp >>$debuglog
                     if($certPattern -match $certPatterns[-1] )
                     {
                        $certificate_Not_Found+=1
                     }
                     else
                     {
                        Continue :OutOfNestedForEach_LABEL
                     }
                 }
              } 
          }
      }
       $not_Found=(0..($certificate_Not_Found.Count-1)) |where {$certificate_Not_Found[$_] -eq '1'}
       if($not_Found)
       {
          "Some certificates are not present in the server.  "+$time_Stamp >>$debuglog
          for($k=$not_Found.Count-1;$k -ge 0;$k--)
          {
               $certNames_List.RemoveAt($not_Found[$k])
          }
       }
       else
       {
          "All the certificates are present in the server.  "+$time_Stamp >>$debuglog
       }
    }
    catch
    {
      $errorMessage = $_.Exception.Message
	  $errorMessage >> $debuglog
      $_ >> $debuglog
      "Obtaining the certificate details failed." >>$script:log
      "Obtaining the certificate details failed.  "+$time_Stamp >>$debuglog
       EXIT(1)
    }
  return $cert_Array,$cert_Thumbprint
 }

# **********************************************************************
#     Check for the presence of multiple certificates with same name 
# **********************************************************************

 function check_For_Multiple_Certificates()
 {
      [int[]]$recent_Cert_Index_CA,[string[]]$cert_Thumbprint_CA,[int[]]$recent_Cert_Index_SS,[string[]]$cert_Thumbprint_SS,[int[]]$recent_Cert=@()
      [int[]]$recent_Cert_Index,[string[]]$cert_Details,[string[]]$cert_DetailsName,[string[]]$cert_NotBefore,[string[]]$cert_Thumbprint=@()
       $initial=$certNames_List[$pathIndex]
       $nextIndex=$pathIndex+1
      try
      {
           if($pathIndex -eq 2 -and $certPattern -match "$serverCert")
           {
             if($server_Type -eq 0) 
             {
                 for($l=0;$l -lt $certificate_Present.Count;$l++)
                 {
                    $cert_Details+=$certificate_Present[$l].Split(";")
                    $temp=$cert_Details[3].Split("=",2)
                    $cert_DetailsName+=$cert_Details[0].Split(",")
                    if($cert_DetailsName[1] -match "OU=Ericsson-ENM" -or $cert_DetailsName[1] -match "OU=Ericsson-ENIQ")
                    {
                      $recent_Cert_Index_CA+=$l
                      $cert_Thumbprint_CA+=$temp[1]
                    }
                    else
                    {
                      $recent_Cert_Index_SS+=$l
                      $cert_Thumbprint_SS+=$temp[1]
                    }
                   $cert_Details=$null
                   $cert_DetailsName=$null
                 }
                 $recent_Cert_Index1,$cert_Thumbprint1=get_CA_Signed_Cert
                 $recent_Cert_Index2,$cert_Thumbprint2=get_SS_Signed_Cert
				 if(($recent_Cert_Index1 -ne $null) -and ($recent_Cert_Index2 -ne $null))
                 { 
                       $cert_Thumbprint=$cert_Thumbprint1+$cert_Thumbprint2
                       $recent_Cert_Index=$recent_Cert_Index1+$recent_Cert_Index2       
                 }
                 elseif(($recent_Cert_Index1 -ne $null) -and ($recent_Cert_Index2 -eq $null))
                 {
                       $cert_Thumbprint=$cert_Thumbprint1
                       $recent_Cert_Index=$recent_Cert_Index1       
                 }
                 else
                 {
                      $cert_Thumbprint=$cert_Thumbprint2
                       $recent_Cert_Index=$recent_Cert_Index2       
                 }       
             }
             else
             {
                $recent_Cert_Index=$null
                $cert_Thumbprint=$null
             }   
           }
           else
           {
                $recent_Cert_Index=$null
                   $cert_NotBefore=[Regex]::Matches($cert_Prop_Array_Line,"NotBefore=\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}")
                   for($j=0;$j -lt $cert_NotBefore.Count;$j++)
                   {
                    $cert_Gen_Date=$cert_NotBefore[$j].Split("=",2)
                    $recent_Cert+=(New-Timespan -Start $cert_Gen_Date[1] -End (Get-Date)).Days
                   }
                   $recent_Cert_Found=$recent_Cert | sort
                   $recent_Cert_Index=(0..($recent_Cert_Found.Count-1)) | where {$recent_Cert[$_] -eq $recent_Cert_Found[0]}
            } 
       }
       catch
       {  
          $errorMessage = $_.Exception.Message
	      $errorMessage >> $debuglog
          $_ >> $debuglog
          "Checking for the presence of multiple certificates failed.  "+$time_Stamp >>$debuglog
          "Checking for the presence of multiple certificates failed." >>$script:log
           EXIT(1)
       } 
       return $recent_Cert_Index,$cert_Thumbprint
 }

 
 function get_CA_Signed_Cert()
 {
 [string[]]$cert_Thumbprint,[string[]]$thumbprint,[string[]]$httpCert_Thumbprint,[int[]]$recent_Cert_Index=@()
 [int[]]$no_purpose=@()
       try
       {
                 if($recent_Cert_Index_CA.Count -ne 0)
                 {
                     "Some CA signed server certificates are present in the server.  "+$time_Stamp >>$debuglog
                      $thumbprint = ((Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices).SSLCertificateSHA1Hash).Split(" ")
                       #Get the tls certificate detail if present
                       if(Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd")
                       {
                          $tls_Cert=Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd" -Name "SSLEnabled"
                       }
                       else
                       {
                          $tls_Cert=$null
                       }

                      if($recent_Cert_Index_CA.Count -eq 1)
                      {
                         if($deployment -match "OCS-ADDS")
                         {
                            "One CA signed server certificate is present in the ADDS server.  "+$time_Stamp >>$debuglog
                            $keyNtds="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\"+$cert_Thumbprint_CA
                            if(($cert_Thumbprint_CA -match $thumbprint[0]) -and (Test-Path -Path $keyNtds))
                            {
                                  $no_purpose+=0
                                  "A CA server cert for SSO configuration and rdp services is found.  "+$time_Stamp >>$debuglog
                            }
                            elseif(($cert_Thumbprint_CA -notmatch $thumbprint[0]) -and (Test-Path -Path $keyNtds))
                            {
                                    $no_purpose+=0                               
                                 "A CA server cert for SSO configuration is found.  "+$time_Stamp >>$debuglog
                            }
                            elseif(($cert_Thumbprint_CA -match $thumbprint[0]) -and !(Test-Path -Path $keyNtds))
                            {
                                  $no_purpose+=0
                                  "A CA server cert for rdp services is found.  "+$time_Stamp >>$debuglog
                            }
                            else
                            {
                                 $no_purpose+=1
                                  "A CA server cert with no purpose found.  "+$time_Stamp >>$debuglog
                            }
                              #Adding the valid certificate details to find the expiry date
                              for($k=0;$k -lt $no_purpose.Count;$k++)
                              {
                                   if($no_purpose[$k] -eq 0)
                                   {
                                      $certNames_List[$pathIndex]="CA-Signed_"+$initial
                                      $recent_Cert_Index+=$recent_Cert_Index_CA
                                      $cert_Thumbprint+=$cert_Thumbprint_CA  
                                      break  
                                   }
                                   else
                                   {
                                     continue
                                   }
                              }
                         }
                         elseif($deployment -match "OCS-CCS")
                         {
                              Get-ChildItem -Path IIS:SSLBindings | ForEach-Object -Process `
                              {
                                  $httpCert_Thumbprint= $_.Thumbprint
                              }
                              #To know whether a web apps certificate is available or not
                              if($httpCert_Thumbprint.Count -ge 1)
                              {
                                  for($t=0;$t -lt $httpCert_Thumbprint.Count;$t++)
                                  {
                                     if(($cert_Thumbprint_CA -match $thumbprint[0]) -and ($cert_Thumbprint_CA -match $httpCert_Thumbprint[$t]))
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for WebApps and rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($cert_Thumbprint_CA -notmatch $thumbprint[0]) -and ($cert_Thumbprint_CA -match $httpCert_Thumbprint[$t]))
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for WebApps is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($cert_Thumbprint_CA -match $thumbprint[0]) -and ($cert_Thumbprint_CA -notmatch $httpCert_Thumbprint[$t]))
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     else
                                     {
                                        $no_purpose+=1
                                         "A CA server cert with no purpose found.  "+$time_Stamp >>$debuglog
                                     }
                                  }
                               }
                               else
                               {
                                    if($cert_Thumbprint_CA -match $thumbprint[0])
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     else
                                     {
                                        $no_purpose+=1
                                         "A CA server cert with no purpose found.  "+$time_Stamp >>$debuglog
                                     }
                                }  
                                  #Adding the valid certificate details to find the expiry date
                                  for($k=0;$k -lt $no_purpose.Count;$k++)
                                  {
                                    if($no_purpose[$k] -eq 0)
                                    {
                                       "A CA server cert is found in the server.  "+$time_Stamp >>$debuglog
                                       $certNames_List[$pathIndex]="CA-Signed_"+$initial
                                       $recent_Cert_Index+=$recent_Cert_Index_CA
                                       $cert_Thumbprint+=$cert_Thumbprint_CA
                                       break
                                    }
                                    else
                                    {
                                       continue
                                     }
                                  }
                         }
                         else
                         {
                                     if(($cert_Thumbprint_CA -match $thumbprint[0]) -and ($tls_Cert -eq 1))
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for WebApps and rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($cert_Thumbprint_CA -notmatch $thumbprint[0]) -and ($tls_Cert -eq 1))
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for WebApps is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($recent_Cert_Index_CA -match $thumbprint[0]) -and ($tls_Cert -ne 1))
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for rdp is found.  "+$time_Stamp >>$debuglog
                                     }
                                     else
                                     {
                                       $no_purpose+=1
                                       "A CA server cert with no purpose found.  "+$time_Stamp >>$debuglog
                                     }
                                   #Adding the valid certificate details to find the expiry date
                                 for($k=0;$k -lt $no_purpose.Count;$k++)
                                 {
                                   if($no_purpose[$k] -eq 0)
                                   {
                                        "A CA server cert is found in the server.  "+$time_Stamp >>$debuglog
                                       $certNames_List[$pathIndex]="CA-Signed_"+$initial
                                       $recent_Cert_Index+=$recent_Cert_Index_CA
                                       $cert_Thumbprint+=$cert_Thumbprint_CA
                                       break
                                   }
                                   else
                                   {
                                    continue
                                   }
                                 }
                              }
                      }       
                      else
                      {
                         if($deployment -match "OCS-ADDS")
                         {
                           "Multiple CA server certs are present in the server.  "+$time_Stamp >>$debuglog
                           for($q=0;$q -lt $cert_Thumbprint_CA.Count;$q++)
                           {
                             $keyNtds="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\"+$cert_Thumbprint_CA[$recent_Cert_Index_CA[$q]]
                               if(($cert_Thumbprint_CA[$q] -match $thumbprint[0]) -and (Test-Path -Path $keyNtds))
                                {
                                      $no_purpose+=0
                                      "A CA server cert for SSO configuration and rdp services is found.  "+$time_Stamp >>$debuglog
                                }
                                elseif(($cert_Thumbprint_CA[$q] -notmatch $thumbprint[0]) -and (Test-Path -Path $keyNtds))
                                {
                                    $no_purpose+=0
                                     "A CA server cert for SSO configuration is found.  "+$time_Stamp >>$debuglog
                                }
                                elseif(($cert_Thumbprint_CA[$q] -match $thumbprint[0]) -and !(Test-Path -Path $keyNtds))
                                {
                                    $no_purpose+=0
                                     "A CA server cert for RDP services is found.  "+$time_Stamp >>$debuglog
                                }
                                else
                                {
                                       $no_purpose+=1
                                     "A CA server cert of no purpose found.  "+$time_Stamp >>$debuglog
                                } 
                                 #Adding the valid certificate details to find the expiry date
                                 if($no_purpose[$q] -eq 0)
                                 {  
                                     if($certNames_List[$pathIndex] -match "CA-Signed_"+$initial)
                                     { 
                                        $certNames_List[$nextIndex]="CA-Signed_"+$initial
                                     }
                                     else
                                     {
                                        $certNames_List[$pathIndex]="CA-Signed_"+$initial
                                     }
                                    $recent_Cert_Index+=$recent_Cert_Index_CA[$q]
                                    $cert_Thumbprint+=$cert_Thumbprint_CA[$recent_Cert_Index_CA[$q]]
                                    break
                                  }
                                  else
                                  {
                                    continue
                                  }
                            }
                          } 
                         elseif($deployment -match "OCS-CCS")
                         {
                              Get-ChildItem -Path IIS:SSLBindings | ForEach-Object -Process `
                              {
                                  $httpCert_Thumbprint= $_.Thumbprint
                              }
                               for($s=0;$s -lt $cert_Thumbprint_CA.Count;$s++)
                               {
                                 if($httpCert_Thumbprint.Count -ge 1)
                                 {
                                   for($t=0;$t -lt $httpCert_Thumbprint.Count;$t++)
                                   {
                                     if(($cert_Thumbprint_CA[$s] -match $thumbprint[0]) -and ($cert_Thumbprint_CA[$s] -match $httpCert_Thumbprint[$t]))
                                     {
                                          $no_purpose+=0
                                         "A CA server cert for WebApps and rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($cert_Thumbprint_CA[$s] -notmatch $thumbprint[0]) -and ($cert_Thumbprint_CA[$s] -match $httpCert_Thumbprint[$t]))
                                     {
                                          $no_purpose+=0
                                         "A CA server cert for WebApps is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($cert_Thumbprint_CA[$s] -match $thumbprint[0]) -and ($cert_Thumbprint_CA[$s] -notmatch $httpCert_Thumbprint[$t]))
                                     {
                                          $no_purpose+=0
                                         "A CA server cert for rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     else
                                     {
                                        $no_purpose+=1
                                         "A CA server cert with no purpose found.  "+$time_Stamp >>$debuglog
                                     }
                                   }
                                  }
                                  else
                                  {
                                     if($cert_Thumbprint_CA[$s] -match $thumbprint[0])
                                     {
                                          $no_purpose+=0
                                         "A CA server cert for rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     else
                                     {
                                       $no_purpose+=1
                                         "A CA server cert with no purpose found.  "+$time_Stamp >>$debuglog
                                     }
                                  }
                                  #Adding the valid certificate details to find the expiry date
                                    if($no_purpose[$s] -eq 0)
                                    {
                                      if($certNames_List[$pathIndex] -match "CA-Signed_"+$initial)
                                      { 
                                        $certNames_List[$nextIndex]="CA-Signed_"+$initial
                                      }
                                      else
                                      {
                                        $certNames_List[$pathIndex]="CA-Signed_"+$initial
                                      }
                                      $recent_Cert_Index+=$recent_Cert_Index_CA[$s]
                                      $cert_Thumbprint+=$cert_Thumbprint_CA[$recent_Cert_Index_CA[$s]]
                                      break
                                    }
                                    else
                                    {
                                     continue
                                    }
                               }
                         }
                         else
                         {
                              for($s=0;$s -lt $cert_Thumbprint_CA.Count;$s++)
                              {
                                     if(($cert_Thumbprint_CA[$s] -match $thumbprint[0]) -and ($tls_Cert -eq 1))
                                     {
                                          $no_purpose+=0
                                         "A CA server cert for WebApps and rdp services is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($cert_Thumbprint_CA[$s] -notmatch $thumbprint[0]) -and ($tls_Cert -eq 1))
                                     {
                                          $no_purpose+=0
                                         "A CA server cert for WebApps is found.  "+$time_Stamp >>$debuglog
                                     }
                                     elseif(($cert_Thumbprint_CA[$s] -match $thumbprint[0]) -and ($tls_Cert -ne 1))
                                     {
                                         $no_purpose+=0
                                         "A CA server cert for rdp is found.  "+$time_Stamp >>$debuglog
                                     }
                                     else
                                     {
                                       $no_purpose+=1
                                       "A CA server cert with no purpose found.  "+$time_Stamp >>$debuglog
                                     }
                                   #Adding the valid certificate details to find the expiry date
                                   if($no_purpose[$s] -eq 0)
                                   {
                                     if($certNames_List[$pathIndex] -match "CA-Signed_"+$initial)
                                     { 
                                        $certNames_List[$nextIndex]="CA-Signed_"+$initial
                                     }
                                     else
                                     {
                                        $certNames_List[$pathIndex]="CA-Signed_"+$initial
                                     }
                                     $recent_Cert_Index+=$recent_Cert_Index_CA[$s]
                                     $cert_Thumbprint+=$cert_Thumbprint_CA[$recent_Cert_Index_CA[$s]]
                                     break
                                   }
                                   else
                                   {
                                    continue
                                   }
                              }
                         }
                      }
                  }
                  else
                  {
                    $recent_Cert_Index=$null
                    $cert_Thumbprint=$null
                  }
       }
       catch
       {  
          $errorMessage = $_.Exception.Message
	      $errorMessage >> $debuglog
          $_ >> $debuglog
          "Checking for the presence of CA signed server certificate failed.  "+$time_Stamp >>$debuglog
          "Checking for the presence of CA signed server certificate failed." >>$script:log
           EXIT(1)
       } 
     return $recent_Cert_Index,$cert_Thumbprint
 }


 function get_SS_Signed_Cert()
 {
 [string[]]$cert_Thumbprint,[int[]]$recent_Cert_Index=@()
       try
       {
                if(($recent_Cert_Index_SS.Count -ne 0) -and ($deployment -match "OCS-ADDS"))
                {
                   "Some self signed(SS) server certificates are found in the server. "+$time_Stamp >>$debuglog
                    if($recent_Cert_Index_SS.Count -eq 1)
                    {
                        "One SS server cert  is present in the server.  "+$time_Stamp >>$debuglog

                        $keyNtds="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\"+$cert_Thumbprint_SS
                            
                        if(Test-Path -Path $keyNtds)
                        {
                         "A SS server cert for SSO configuration is found.  "+$time_Stamp >>$debuglog
                          $certNames_List[$pathIndex]="Self-Signed_"+$initial 
                          $recent_Cert_Index=$recent_Cert_Index_SS
                          $cert_Thumbprint=$cert_Thumbprint_SS
                        }
                        else
                        {
                          "A SS server cert with no purpose is found.  "+$time_Stamp >>$debuglog
                          $recent_Cert_Index=$null
                        }
                    }
                    else
                    {
                      "Multiple SS server certs are present in the server.  "+$time_Stamp >>$debuglog
                      for($q=0;$q -lt $recent_Cert_Index_SS.Count;$q++)
                      {
                           $keyNtds="Registry::"+"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\"+$cert_Thumbprint_SS[$recent_Cert_Index_SS[$q]]

                         if(Test-Path -Path $keyNtds)
                         {
                            "A SS server cert for SSO configuration is found.  "+$time_Stamp >>$debuglog
                            $certNames_List[$pathIndex]="Self-Signed_"+$initial
                            $recent_Cert_Index=$recent_Cert_Index_SS[$q]
                            $cert_Thumbprint=$cert_Thumbprint_SS[$recent_Cert_Index_SS[$q]]
                            break
                         }
                         else
                         {
                            continue
                         }
                       }
                     }
                }
                else
                {
                  $recent_Cert_Index=$null
                  $cert_Thumbprint=$null
                }
        }
        catch
        {  
          $errorMessage = $_.Exception.Message
	      $errorMessage >> $debuglog
          $_ >> $debuglog
          "Checking for the presence of self signed server certificate failed.  "+$time_Stamp >>$debuglog
          "Checking for the presence of self signed server certificate failed." >>$script:log
           EXIT(1)
        }  
return $recent_Cert_Index,$cert_Thumbprint
} 
   
   

# *****************************************************************************************
#	Append the log file with days before expiry and certificates present in the server
# *****************************************************************************************

function append_Log_File
{
$expiryDate,$days,$certNames_List,$cert_Thumbprint=get_Expiry_Date
$i=0 #Count for no of cerificates with server name in server
  try
  { 
     for($j=0;$j -lt $days.Count;$j++)
     {
        if($days[$j] -gt 0)
        {
           "The "+$certNames_List[$j]+" certificate  expires in "+$days[$j]+" days( "+$expiryDate[$j]+" ).">>$script:log 
        }
        elseif($days[$j] -eq 0)
        {
           "The "+$certNames_List[$j]+" certificate  expires in less than 24 hours ( "+$expiryDate[$j]+" ).">>$script:log
		   foreach($line in Get-Content -Path "C:\Certificate-expiry\config_file.ini")
            {
                if($line -match "SSL_Auto_Renewal")
                {              
                    $split = "$line".Split("=",2)
                    $SSLAutoValue = $split[1].Trim()                    
                }  
            }            
		    if(($certNames_List[$j] -match "Self-Signed_Tomcatssl") -AND ($SSLAutoValue -eq "Yes"))
			{					
				if((Test-Path -path "C:\ebid\SSL\cert\tomcatssl.bin") -AND (Test-Path -path "C:\ebid\SSL\ebid_ssl_config.ps1"))
				{									
					powershell C:\ebid\SSL\ebid_ssl_config.ps1 AutoRenew					
					"Self-Signed Certificate auto-renewed.  "+$time_Stamp >>$debuglog
				}
			}		    
        } 
        else
        {
           "The "+$certNames_List[$j]+" certificate has expired. Renew the certificate. ">>$script:log
        }
     }
     #Appending the log files for DDC-DDP and AdminUI
	 
         "Deployment::Certificate Name::Purpose::Certificate Expiry Date::Certificate Expiry(in days)`n">>$logNew
         "Deployment::Certificate Name::Purpose::Certificate Expiry Date::Certificate Expiry(in days)`n">>$logDDC
          for($k=0;$k -lt $days.Count;$k++)
          {
               if($certNames_List[$k] -match "Server")
               {
                  "`r"+$deployment+"::"+$certNames_List[$k]+"::Citrix License::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
                   "`r"+$deployment+"::"+$certNames_List[$k]+"::Citrix License::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC
               }
				elseif(($certNames_List[$k] -match "CA-Signed_tomcatssl") -or ($certNames_List[$k] -match "Self-Signed_tomcatssl"))
				{
					"`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
                    "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC
				}
               elseif(($certNames_List[$k] -match "CA-Signed_$serverCert") -or ($certNames_List[$k] -match "Self-Signed_$serverCert"))
               {
                if($test_Thumbprint -ne $null)
                {
                   if($test_Thumbprint.Count -gt 1)
                   {
                      if($test_Thumbprint[$i] -match $cert_Thumbprint[$i])
                      {
					    "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose[$i]+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
                        "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose[$i]+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC
                      }
                      else
                      {
					    "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose[$i+1]+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
                        "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose[$i+1]+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC
                      }
                      $i=$i+1
                   }
                   else
                   { 
				       "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
                       "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$purpose+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC
                   }
                 }
                 else
                 {
                      "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$function+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
                       "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$function+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC
                 }
               }
               elseif($certNames_List[$k] -match "$serverCertRDP")
               {
                   "`r"+$deployment+"::"+$certNames_List[$k]+"::Remote Desktop Services::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
				   "`r"+$deployment+"::"+$certNames_List[$k]+"::Remote Desktop Services::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC 
               }
               elseif($certNames_List[$k] -match "$serverCertSSO")
               {
                   "`r"+$deployment+"::"+$certNames_List[$k]+"::SSO configuration::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
				   "`r"+$deployment+"::"+$certNames_List[$k]+"::SSO configuration::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC 
               }
               elseif($certNames_List[$k] -match "$serverCertTLS")
               {
                   "`r"+$deployment+"::"+$certNames_List[$k]+"::TLS configuration::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
				   "`r"+$deployment+"::"+$certNames_List[$k]+"::TLS configuration::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC 
               }
               else
               {
                 "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$function+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logNew
				 "`r"+$deployment+"::"+$certNames_List[$k]+"::"+$function+"::"+$expiryDate[$k]+"::"+$days[$k]+"`n">>$logDDC
               }
          }
   }
   catch
   {
      $errorMessage = $_.Exception.Message
      $errorMessage >> $debuglog
      $_ >> $debuglog
      "Appending the log file with the certificates details present in server failed." >>$script:log
	  "Appending the log file with the certificates details present in server failed.  "+$time_Stamp >>$debuglog
       EXIT(1)
   }
}

# *****************************************************************************
#         Renew Certificate
# *****************************************************************************

function bind_RDP_cert 
{		
	try
	{ 	
		$server_date = get-date
	    $rdp_cert_thumbprint = (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices).SSLCertificateSHA1Hash
		$cert_count_expiry = Get-ChildItem -path Cert:\localmachine\my\$rdp_cert_thumbprint -erroraction silentlycontinue
			
			if($cert_count_expiry) 
			{
				$enm_cert_expiry = $cert_count_expiry.NotAfter
				
				if($server_date.adddays(1) -gt $enm_cert_expiry) 
				{
					Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name SSLCertificateSHA1Hash
					if($?)
					{
					"RDP ENM CA certificate replaced by Self-Signed certificate." >> $script:log
					}
				}
			}		
	}
	
	catch
	{
	    $errorMessage2 = $_.Exception.Message
        $errorMessage2>>$debuglog
        "Binding RDP cert process failed.  "+$time_Stamp >>$debuglog
        "Binding RDP cert process failed. ">>$script:log
	}
}

# *****************************************************************************
#			Logs Retention
# *****************************************************************************

function logs_retention
{
	try
	{
        if($server_Type -eq 1)
        {
	       $install_cert="C:\ebid\install_config\cert_log"
	       $DDC_cert="C:\ebid\DDC_logs\certificate_logs"
	       $install_cert_count=( Get-ChildItem "C:\ebid\install_config\cert_log" ).Count
	       $DDC_cert_count=( Get-ChildItem "C:\ebid\DDC_logs\certificate_logs" ).Count
		}
		elseif($server_Type -eq 2)
		{
			$install_cert="C:\OCS-without-Citrix\install_config\cert_log"
			$DDC_cert="C:\OCS-without-Citrix\DDC_logs\certificate_logs"
			$install_cert_count=( Get-ChildItem "C:\OCS-without-Citrix\install_config\cert_log" ).Count
			$DDC_cert_count=( Get-ChildItem "C:\OCS-without-Citrix\DDC_logs\certificate_logs" ).Count
		}	
        else
        {
           $install_cert="C:\OCS\install_config\cert_log"
	       $DDC_cert="C:\OCS\DDC_logs\certificate_logs"
	       $install_cert_count=( Get-ChildItem "C:\OCS\install_config\cert_log" ).Count
	       $DDC_cert_count=( Get-ChildItem "C:\OCS\DDC_logs\certificate_logs" ).Count
		}
            if((Test-Path $install_cert) -AND ($install_cert_count -gt 7))
	    	{
		         Get-ChildItem $install_cert -Recurse -File | Where CreationTime -lt  (Get-Date).AddDays(-7)  | Remove-Item -Force
		         if($?)
		         {
		           "Logs older than 7 days deleted in install_config\cert_logs  "+$time_Stamp >>$debuglog
	           	 }
		    }
		    else
		    {
		      "No logs deleted for install_config\cert_log  "+$time_Stamp >>$debuglog
		    }
		    if((Test-Path $DDC_cert) -AND ($DDC_cert_count -gt 7))
		    {
		         Get-ChildItem $DDC_cert -Recurse -File | Where CreationTime -lt  (Get-Date).AddDays(-7)  | Remove-Item -Force
		         if($?)
	             {
		           "Logs older than 7 days deleted in DDC_logs\certificate_logs  "+$time_Stamp >>$debuglog
		         }
		    }
		    else
		    {
		       "No logs deleted for DDC_logs\certificate_logs  "+$time_Stamp >>$debuglog
		    }
	}
	catch
	{
	    $errorMessage2 = $_.Exception.Message
        $errorMessage2 >> $debuglog
        "Log retention for install_config and AdminUI failed.  "+$time_Stamp >>$debuglog
	}
}

# *****************************************************************************
#         Windows-ToUnixFileConversion
# *****************************************************************************

Function Windows-ToUnixFileConversion {
   
   if($server_Type -eq 1)
   {
      $certlogFiles="C:\ebid\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv"
   }
   elseif($server_Type -eq 2)
   {
		$certlogFiles="C:\OCS-without-Citrix\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv"
	}	
   else
   {
     $certlogFiles="C:\OCS\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv"
   }
        
    $scriptBlockConversionCmd = {
      $certContents = [IO.File]::ReadAllText($certlogFiles) -replace "`r`n?", "`n"
      $certUtf8 = New-Object System.Text.UTF8Encoding $false
      [IO.File]::WriteAllText($certlogFiles, $certContents, $certUtf8)
   }
    try 
    { 
        Invoke-Command -ScriptBlock $scriptBlockConversionCmd -errorAction stop 
        "Conversion from dostounix is done successfully.  "+$time_Stamp >>$debuglog   
    }
    catch
    {	
        $errorMessage = $_.Exception.Message
        $errorMessage >> $debuglog
        "Conversion from dostounix failed for AdminUI log files.  "+$time_Stamp >>$debuglog
    }

}

# ************************************************************************************************************************************************
# -----------------------------------------------------------MAIN() function----------------------------------------------------------------------
# ************************************************************************************************************************************************

     $time_Stamp = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss")
     $startdate = (Get-Date 23:30:00).toString("HH:mm:ss")
	 $enddate   = (Get-Date 23:32:00).toString("HH:mm:ss")
     $timeStampDefault = Get-Date -Format yyyyMMdd
     $serverCert = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
     $serverCertRDP = (Get-WmiObject win32_computersystem).DNSHostName+"_RDP"
     $serverCertSSO = (Get-WmiObject win32_computersystem).DNSHostName+"_SSO"
     $serverCertTLS = (Get-WmiObject win32_computersystem).DNSHostName+"_TLS"


     #Import module for finding Web App certificate
	 if (Test-Path -Path "HKLM:\SOFTWARE\Citrix\Citrix Desktop Delivery Controller") 
	 {
      try
      {
       Import-Module -Name WebAdministration
      }
      catch
      {
        $errorMessage = $_.Exception.Message
	    $errorMessage >> $debuglog
        $_ >>$debuglog
        Write-Host "Error occured while importing a module"
        EXIT(1)
      }
	 }
    
     New-Item -ItemType Directory -Path C:\Certificate-expiry\log -erroraction 'silentlycontinue' | out-null
     $first= Test-Path C:\Certificate-expiry\log\certificate_expiry_log.log -PathType Leaf
	  #Creation of log file inside Certificate-expiry folder
      if(!$first)
	  {
        try
        {
	      New-Item -ItemType File -Path C:\Certificate-expiry\log -Name certificate_expiry_log.log 
		  $script:log="C:\Certificate-expiry\log\certificate_expiry_log.log"
        }
        catch
        {
          Write-Host "Error occured while creating the log file"
          EXIT(1)
        }
	  }
      else
      {
		  $script:log="C:\Certificate-expiry\log\certificate_expiry_log.log"
      }
   
	#Creation of log file inside install-config
	if(Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager')
	   {
          if(Test-Path -Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir)
          {  
			if(Test-Path "C:\ebid\install_config")
			{
			New-Item -ItemType Directory -Path C:\ebid\install_config\cert_log -erroraction 'silentlycontinue' | out-null
              $debuglog="C:\ebid\install_config\cert_log\certificate_log_$timeStampDefault.txt"
              "-------------------------------------------------------------">>$debuglog
			  "Certificate expiry check script started on "+$time_Stamp >> $debuglog
              "-------------------------------------------------------------">>$debuglog
			}
			else
			{
			"install_config folder not present.">>$script:log
			}
		  }
		}
		elseif((Test-Path -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora') -AND (!(Test-Path -Path 'HKLM:\SOFTWARE\Citrix\Citrix Virtual Desktop Agent')))
		{
			if(Test-Path -Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\Installer\Aurora' -Name path).path)
			{
				if(Test-Path "C:\OCS-without-Citrix\install_config")
				{
					 New-Item -ItemType Directory -Path C:\OCS-without-Citrix\install_config\cert_log -erroraction 'silentlycontinue' | out-null
					 $debuglog="C:\OCS-without-Citrix\install_config\cert_log\certificate_log_$timeStampDefault.txt"
					 "-------------------------------------------------------------">>$debuglog
					 "Certificate expiry check script started on "+$time_Stamp >> $debuglog
					 "-------------------------------------------------------------">>$debuglog
				}
				else
				{
					 New-Item -ItemType Directory -Path C:\OCS-without-Citrix\install_config -erroraction 'silentlycontinue' | out-null
					 New-Item -ItemType Directory -Path C:\OCS-without-Citrix\install_config\cert_log -erroraction 'silentlycontinue' | out-null
					 $debuglog="C:\OCS-without-Citrix\install_config\cert_log\certificate_log_$timeStampDefault.txt"
					 "-------------------------------------------------------------">>$debuglog
					 "Certificate expiry check script started on "+$time_Stamp >> $debuglog
					 "-------------------------------------------------------------">>$debuglog                 			  
				 }
			}
		}
	else
	{
		     if(Test-Path "C:\OCS\install_config")
			{
			     New-Item -ItemType Directory -Path C:\OCS\install_config\cert_log -erroraction 'silentlycontinue' | out-null
                 $debuglog="C:\OCS\install_config\cert_log\certificate_log_$timeStampDefault.txt"
                 "-------------------------------------------------------------">>$debuglog
                 "Certificate expiry check script started on "+$time_Stamp >> $debuglog
                 "-------------------------------------------------------------">>$debuglog
	        }
			else
			{
			     New-Item -ItemType Directory -Path C:\OCS\install_config -erroraction 'silentlycontinue' | out-null
			     New-Item -ItemType Directory -Path C:\OCS\install_config\cert_log -erroraction 'silentlycontinue' | out-null
                 $debuglog="C:\OCS\install_config\cert_log\certificate_log_$timeStampDefault.txt"
                 "-------------------------------------------------------------">>$debuglog
			     "Certificate expiry check script started on "+$time_Stamp >> $debuglog
                 "-------------------------------------------------------------">>$debuglog                 			  
             }
	}
	
# **********************************************************************
# --------------------------Start of Script----------------------------- 
# **********************************************************************

"--------------------------------------------------------------" >> $script:log
	 "Certificate expiry check script started on "+$time_Stamp >> $script:log
"--------------------------------------------------------------" >> $script:log
	 "Checking for the expiry of certificates.."  >> $script:log
     	
  	
     $server_Type,$deployment,$purpose,$test_Thumbprint,$function,$arrayk=check_ServerType
     $certPatterns=@('CN=ENM_PKI_Root_CA','CN=ENM_External_Entity_CA',"$serverCert","$serverCertRDP","$serverCertSSO","$serverCertTLS",'server.crt')
	 $SSL=check_If_Tomcatssl_Present
     $certNames=@('ENM_PKI_Root_CA','ENM_External_Entity_CA',"$serverCert","$serverCertRDP","$serverCertSSO","$serverCertTLS",'Server.crt',"$SSL") 
     $paths=@('Cert:\LocalMachine\Root','Cert:\LocalMachine\CA','Cert:\LocalMachine\My','Cert:\LocalMachine\My','Cert:\LocalMachine\My','Cert:\LocalMachine\My','C:\Program Files (x86)\Citrix\Licensing\LS\conf')
	 $today= Select-String -Path "C:\Certificate-expiry\log\certificate_expiry_log.log" -Pattern "Certificate expiry check script started on" |ForEach-Object {-split $_.Line |Select-Object -Last 1 } | Select-Object -Last 1
	 
	 
     #Check whether configuration file is present or not
     if(Test-Path C:\Certificate-expiry\config_file.ini -PathType Leaf)
     {
       "The configuration file present in the server is found.  "+$time_Stamp >>$debuglog
     }
     else
     {
       "The configuration file is not found in the specified path.  "+$time_Stamp >>$debuglog
       Write-Host "The configuration file is not found in the specified path."
        EXIT(1)
     }  

     if($server_Type -eq 1)
     {
      try
      {
        #Creation of AdminUI log file
		 if($today -ge $startdate -and $today -lt $enddate)
        {
            if(Test-Path -Path C:\ebid\DDC_logs -ErrorAction SilentlyContinue) 
            {
               if(Test-Path -Path C:\ebid\DDC_logs\certificate_logs -ErrorAction SilentlyContinue)
               {
                 if(Test-Path -Path C:\ebid\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv -ErrorAction SilentlyContinue)
                 {
                  $logNew=$null
                  "Log file for AdminUI regarding certificate expiry alert is created already.  "+$time_Stamp >>$debuglog
                 }
                 else
                 {
                    $logNew="C:\ebid\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv" 
                   "Log file for AdminUI regarding certificate expiry alert is created($logNew) successfully.  "+$time_Stamp >>$debuglog 
                 }
               }
               else
               {
                  New-Item -ItemType Directory -Path C:\ebid\DDC_logs\certificate_logs -erroraction 'silentlycontinue' | out-null
                  $logNew="C:\ebid\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv" 
                  "Log file for AdminUI regarding certificate expiry alert is created($logNew) successfully.  "+$time_Stamp >>$debuglog  
               }
            }    
            else
            {
               $logNew=$null
                "Log file for AdminUI not created($logNew) at expected time..  "+$time_Stamp >>$debuglog  
            }
        }
        else
        {
               $logNew=$null 
                "Attempt to create log file for AdminUI at unexpected time failed.  "+$time_Stamp  >>$debuglog  
        }
         
        #Creation of DDC-DDP log file
		    if($today -ge $startdate -and $today -lt $enddate)
        {
            if(Test-Path -Path C:\ebid\DDC_logs\system_logs -ErrorAction SilentlyContinue) 
            {
              if(Test-Path -Path "C:\ebid\DDC_logs\system_logs\System_Certificate_expiry_$timeStampDefault.tsv" -ErrorAction SilentlyContinue)
              {
               $logDDC=$null
               "Log file for DDC regarding certificate expiry alert is created already. "+$time_Stamp >>$debuglog
              }
              else
              {
               $logDDC="C:\ebid\DDC_logs\system_logs\System_Certificate_expiry_$timeStampDefault.tsv"  
                "Log file for DDC regarding certificate expiry alert is created($logDDC) successfully.  "+$time_Stamp >>$debuglog 
              }
            }    
            else
            {
               $logDDC=$null
                "Log file for DDC is not created($logDDC) at expected time...  "+$time_Stamp >>$debuglog  
            }
        }
        else
        {
               $logDDC=$null
                "Attempt to create Log file for DDC at unexpected time failed.  "+$time_Stamp >>$debuglog  
        }
 
            
        if($SSL -ne $null)
        {
		  $bi_install_dir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\SAP BusinessObjects\Suite XI 4.0\config Manager' -Name InstallDir).InstallDir
	      Copy-Item "C:\Certificate-expiry\Keystore.jsp" -Destination $bi_install_dir"\tomcat\webapps\AdminTools\" -Force
	      $tomcat_path="$bi_install_dir"+"tomcat\"
	      $serverXmlPath = "$tomcat_path\conf\server.xml"
	      $xml = [xml](Get-Content $serverXmlPath)
	      $keyPass =([String]($xml.Server.Service.Connector.keystorePass)).trim()
	      $path =([String]($xml.Server.Service.Connector.keystoreFile)).trim()
	      $filepath=$path.replace('\','//')
          $output = cscript C:\ebid\install_config\wget_custom.js http://$env:computername`:8080/AdminTools/Keystore.jsp?keystorePass=$keyPass`&keystorePath=$filepath
          $next = Get-Content C:\Certificate-expiry\expiry_log.log | %{ $test =$_ -split ':'}
          $last = $test[$test.Count - 1]
	      <#note:#>$arrayk = $last.trim()
		  $formatdate = (Select-String -Path C:\Certificate-expiry\expiry_log.log -Pattern "Formated Date: (.*)").Matches.Groups[1].Value
		  $timeanddate = $formatdate.substring(0,19)
		  $lastdate = $timeanddate.substring(0,10)
          Remove-Item -Recurse -Force "C:\Certificate-expiry\expiry_log.log" 
        }
        else
        {
          "The Tomcatssl certificate is not present in the server.">>$script:log
		  "The Tomcatssl certificate is not present in the server.  "+$time_Stamp >>$debuglog
        }
        append_Log_File
		bind_RDP_cert
        "---------------------------------------------------------------" >> $script:log
         if($today -ge $startdate -and $today -lt $enddate)
        {
		  logs_retention
		  Windows-ToUnixFileConversion
        }
        else
        {
         "--------------------------------------------------------------">>$debuglog
		}
      }
      catch
     {
      $errorMessage = $_.Exception.Message
	  $errorMessage >> $debuglog
      $_ >>$debuglog
      "Checking  the certificates for BO server  failed.  "+$time_Stamp >>$debuglog
       EXIT(1)
      }
	 } 
	
elseif($server_Type -eq 2)
	 {
		try
       {
        #Creation of AdminUI log file for OCS-without-Citrix server with BO Client installed
        if($today -ge $startdate -and $today -lt $enddate)
        {
            if(Test-Path -Path C:\OCS-without-Citrix\DDC_logs -ErrorAction SilentlyContinue) 
            {
               if(Test-Path -Path C:\OCS-without-Citrix\DDC_logs\certificate_logs -ErrorAction SilentlyContinue)
               {
                 if(Test-Path -Path C:\OCS-without-Citrix\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv -ErrorAction SilentlyContinue)
                 {
                  $logNew=$null
                  "Log file for AdminUI regarding certificate expiry alert is created already.  "+$time_Stamp >>$debuglog
                 }
                 else
                 {
                    $logNew="C:\OCS-without-Citrix\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv" 
                   "Log file for AdminUI regarding certificate expiry alert is created($logNew) successfully.  "+$time_Stamp >>$debuglog 
                 }
               }
               else
               {
                  New-Item -ItemType Directory -Path C:\OCS-without-Citrix\DDC_logs\certificate_logs -erroraction 'silentlycontinue' | out-null
                  $logNew="C:\OCS-without-Citrix\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv" 
                  "Log file for AdminUI regarding certificate expiry alert is created($logNew) successfully.  "+$time_Stamp >>$debuglog  
               }
            }    
            else
            {
               $logNew=$null
                "Log file for AdminUI not created($logNew) at expected time..  "+$time_Stamp >>$debuglog  
            }
        }
        else
        {
             $logNew=$null
             "Attempt to create log file for AdminUI at unexpected time failed.  "+$time_Stamp  >>$debuglog  
        }
		
		#Creation of DDC-DDP log file for OCS-without-Citrix server with BO Client installed
        if($today -ge $startdate -and $today -lt $enddate)
        {
            if(Test-Path -Path C:\OCS-without-Citrix\DDC_logs\system_logs -ErrorAction SilentlyContinue) 
            {
              if(Test-Path -Path "C:\OCS-without-Citrix\DDC_logs\system_logs\System_Certificate_expiry_$timeStampDefault.tsv" -ErrorAction SilentlyContinue)
              {
               $logDDC=$null
               "Log file for DDC regarding certificate expiry alert is created already. "+$time_Stamp >>$debuglog
              }
              else
              {
               $logDDC="C:\OCS-without-Citrix\DDC_logs\system_logs\System_Certificate_expiry_$timeStampDefault.tsv"  
                "Log file for DDC regarding certificate expiry alert is created($logDDC) successfully.  "+$time_Stamp >>$debuglog 
              }
            }    
            else
            {
               $logDDC=$null
                "Log file for DDC is not created($logDDC) at expected time...  "+$time_Stamp >>$debuglog  
            }
        }
        else
        {
               $logDDC=$null
                "Attempt to create Log file for DDC at unexpected time failed.  "+$time_Stamp >>$debuglog  
        }
            append_Log_File
			bind_RDP_cert
             "---------------------------------------------------------------" >> $script:log
             if($today -ge $startdate -and $today -lt $enddate)
             {
                logs_retention
	    	    Windows-ToUnixFileConversion
             }
             else
             {
             "---------------------------------------------------------------">>$debuglog
             }
        }
        catch
        {
           $errorMessage = $_.Exception.Message
           $errorMessage >>$debuglog
           $_ >>$debuglog
           "Checking  the certificates for OCS-without-Citrix server  failed." >>$debuglog
           "Checking  the certificates for OCS-without-Citrix server  failed." >>$script:log
           EXIT(1)
         } 	
        
     }
     else
     {
       try
       {
        #Creation of AdminUI log file
        if($today -ge $startdate -and $today -lt $enddate)
        {
            if(Test-Path -Path C:\OCS\DDC_logs -ErrorAction SilentlyContinue) 
            {
               if(Test-Path -Path C:\OCS\DDC_logs\certificate_logs -ErrorAction SilentlyContinue)
               {
                 if(Test-Path -Path C:\OCS\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv -ErrorAction SilentlyContinue)
                 {
                  $logNew=$null
                  "Log file for AdminUI regarding certificate expiry alert is created already.  "+$time_Stamp >>$debuglog
                 }
                 else
                 {
                    $logNew="C:\OCS\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv" 
                   "Log file for AdminUI regarding certificate expiry alert is created($logNew) successfully.  "+$time_Stamp >>$debuglog 
                 }
               }
               else
               {
                  New-Item -ItemType Directory -Path C:\OCS\DDC_logs\certificate_logs -erroraction 'silentlycontinue' | out-null
                  $logNew="C:\OCS\DDC_logs\certificate_logs\System_Certificate_Expiry_$timeStampDefault.tsv" 
                  "Log file for AdminUI regarding certificate expiry alert is created($logNew) successfully.  "+$time_Stamp >>$debuglog  
               }
            }    
            else
            {
               $logNew=$null
                "Log file for AdminUI not created($logNew) at expected time..  "+$time_Stamp >>$debuglog  
            }
        }
        else
        {
             $logNew=$null
             "Attempt to create log file for AdminUI at unexpected time failed.  "+$time_Stamp  >>$debuglog  
        }
        #Creation of DDC-DDP log file
        if($today -ge $startdate -and $today -lt $enddate)
        {
            if(Test-Path -Path C:\OCS\DDC_logs\system_logs -ErrorAction SilentlyContinue) 
            {
              if(Test-Path -Path "C:\OCS\DDC_logs\system_logs\System_Certificate_expiry_$timeStampDefault.tsv" -ErrorAction SilentlyContinue)
              {
               $logDDC=$null
               "Log file for DDC regarding certificate expiry alert is created already. "+$time_Stamp >>$debuglog
              }
              else
              {
               $logDDC="C:\OCS\DDC_logs\system_logs\System_Certificate_expiry_$timeStampDefault.tsv"  
                "Log file for DDC regarding certificate expiry alert is created($logDDC) successfully.  "+$time_Stamp >>$debuglog 
              }
            }    
            else
            {
               $logDDC=$null
                "Log file for DDC is not created($logDDC) at expected time...  "+$time_Stamp >>$debuglog  
            }
        }
        else
        {
               $logDDC=$null
                "Attempt to create Log file for DDC at unexpected time failed.  "+$time_Stamp >>$debuglog  
        }
            append_Log_File
             "---------------------------------------------------------------" >> $script:log
             if($today -ge $startdate -and $today -lt $enddate)
             {
                logs_retention
	    	    Windows-ToUnixFileConversion
             }
             else
             {
             "---------------------------------------------------------------">>$debuglog
             }
        }
        catch
        {
           $errorMessage = $_.Exception.Message
           $errorMessage >>$debuglog
           $_ >>$debuglog
           "Checking  the certificates for OCS server  failed." >>$debuglog
           "Checking  the certificates for OCS server  failed." >>$script:log
           EXIT(1)
         }    
        
      }