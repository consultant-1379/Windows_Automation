<%
// *******************************************************************************
// Ericsson Radio Systems AB                                     SCRIPT
// *******************************************************************************
// (c) Ericsson Radio Systems AB 2020 - All rights reserved.
// The copyright to the computer program(s) herein is the property
// of Ericsson Radio Systems AB, Sweden. The programs may be used
// and/or copied only with the written permission from Ericsson Radio
// Systems AB or in accordance with the terms and conditions stipulated
// in the agreement/contract under which the program(s) have been
// supplied.
// *******************************************************************************
// Name    : Keystore.jsp
// Date    : 07/08/2020
// Revision: A.1
// Purpose : This JSP is used to disable default user QaaWSServletPrincipal in CMC.
// *******************************************************************************
%>
<%@ page import="java.io.FileInputStream,
java.security.KeyStore,
java.util.Enumeration,
java.io.IOException,
java.security.KeyStoreException,
java.security.NoSuchAlgorithmException,
java.security.UnrecoverableEntryException,
java.security.cert.Certificate,
java.security.cert.CertificateException,
java.security.cert.X509Certificate,
java.util.Date,
java.text.SimpleDateFormat,
java.nio.file.Files.*,
java.net.*,
java.io.*,
java.text.*,
java.nio.charset.StandardCharsets,
java.net.InetAddress.*,
java.util.*"
%> 
<%

File logFile = new File("C:\\Certificate-expiry\\expiry_log.log" );
String password = request.getParameter("keystorePass");
String path = request.getParameter("keystorePath");
FileOutputStream fout = new FileOutputStream(logFile,true);
OutputStreamWriter fileWriter = new OutputStreamWriter(fout, StandardCharsets.UTF_8);
BufferedWriter logOutput = new BufferedWriter(fileWriter);
logOutput.newLine();
logOutput.write("Tomcat SSL certificate expiry log");
 try {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream(path),password.toCharArray());
        Enumeration aliases = keystore.aliases();
        for(; aliases.hasMoreElements();) {
			logOutput.newLine();
            String alias = (String) aliases.nextElement();
            Date certExpiryDate = ((X509Certificate) keystore.getCertificate(alias)).getNotAfter();
            SimpleDateFormat ft = new SimpleDateFormat ("yyyy-MM-dd HH:mm:ss");
			SimpleDateFormat ft1 = new SimpleDateFormat ("dd/MM/YYYY HH:mm:ss");
            //Tue Oct 17 06:02:22 AEST 2006
            Date today = new Date();
            long dateDiff = certExpiryDate.getTime() - today.getTime();
            long expiresIn = dateDiff / (24 * 60 * 60 * 1000);
			if(dateDiff<0)
			{
				expiresIn =-1;
			}
			logOutput.newLine();
            logOutput.write("Certifiate: " + alias + "\tExpires On: " + certExpiryDate + "\tFormated Date: " + ft1.format(certExpiryDate) + "\tToday's Date: " + ft.format(today) + "\tExpires In: "+ expiresIn);
			logOutput.close();
        }
    }

catch (Exception e)
     {
       logOutput.write(e.toString());
	   logOutput.close();
    }
  
  
%>	