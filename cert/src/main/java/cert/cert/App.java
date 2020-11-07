package cert.cert;

/**
 * Hello world!
 *
 */
import java.security.cert.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.Collections;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
//import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.JCEECPublicKey;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.ValidatorBuilder;
import no.difi.certvalidator.rule.CRLRule;
import no.difi.certvalidator.rule.ExpirationRule;
import no.difi.certvalidator.rule.SigningRule;
public class App{
   public static void main(String []args){
      System.out.println("Hello World");
  // this certificate does not include any extensions
      //String strKeyPEM = "";
      //String filename = "google_cert.pem";
      //BufferedReader br = new BufferedReader(new FileReader(filename));
      //String line =br.readLine();
      //System.out.println(line);
      //while ((line = br.readLine()) != null) {
      //    strKeyPEM += line + "\n";
      //}

      System.setProperty("javax.net.ssl.trustStore", "trust-store.jks");
      System.setProperty("javax.net.ssl.trustStorePassword", "TrustStore");
      String sCert = ""; 
      try { 
    	  sCert = new String(Files.readAllBytes(Paths.get("C:\\Users\\Abdelatif Chairi\\Desktop\\Censys_Certification_Hash\\Amazon\\3\\5c35d9e95309e21f417ea4f52945feb60ee47fd4b5dab9eff940fcdf0b952f42.txt"))); 
    	  } 
      catch (IOException e) {
    	  e.printStackTrace(); 
    	  }
      
      File[] files = new File("C:\\\\Users\\\\Abdelatif Chairi\\\\Desktop\\\\Censys_Certification_Hash\\\\CloudFlare_Inc\\\\1").listFiles();
      showFiles(files);
      System.out.println("sub2 "+sCert);
      /*
      String sCert =
    		  "-----BEGIN CERTIFICATE-----\r\n" + 
    		  "MIIE7zCCBJSgAwIBAgIQDzHJH4+1o32UuNHF6bYypDAKBggqhkjOPQQDAjBvMQsw\n" + 
    		  "CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28x\n" + 
    		  "GTAXBgNVBAoTEENsb3VkRmxhcmUsIEluYy4xIDAeBgNVBAMTF0Nsb3VkRmxhcmUg\n" + 
    		  "SW5jIEVDQyBDQS0yMB4XDTIwMDExODAwMDAwMFoXDTIwMTAwOTEyMDAwMFowbTEL\n" + 
    		  "MAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2Nv\n" + 
    		  "MRkwFwYDVQQKExBDbG91ZGZsYXJlLCBJbmMuMR4wHAYDVQQDExVzbmkuY2xvdWRm\n" + 
    		  "bGFyZXNzbC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARXXV6kKA79BHoI\n" + 
    		  "8w0lwwIhvnMmwBWQwf1uunUTMBOq6RTHGr8ht6TKCzD0GjFHExXThcipiWRwR+5d\n" + 
    		  "paIGw0wwo4IDEjCCAw4wHwYDVR0jBBgwFoAUPnQtH89FdQR+P8Cihz5MQ4NRE8Yw\n" + 
    		  "HQYDVR0OBBYEFB+qH/XAFIOpqj6taPPfVM7Eg52AMEYGA1UdEQQ/MD2CEGpveXNw\n" + 
    		  "eXJzb2ZmZGUuY2aCEiouam95c3B5cnNvZmZkZS5jZoIVc25pLmNsb3VkZmxhcmVz\n" + 
    		  "c2wuY29tMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB\n" + 
    		  "BQUHAwIweQYDVR0fBHIwcDA2oDSgMoYwaHR0cDovL2NybDMuZGlnaWNlcnQuY29t\n" + 
    		  "L0Nsb3VkRmxhcmVJbmNFQ0NDQTIuY3JsMDagNKAyhjBodHRwOi8vY3JsNC5kaWdp\n" + 
    		  "Y2VydC5jb20vQ2xvdWRGbGFyZUluY0VDQ0NBMi5jcmwwTAYDVR0gBEUwQzA3Bglg\n" + 
    		  "hkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29t\n" + 
    		  "L0NQUzAIBgZngQwBAgIwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRw\n" + 
    		  "Oi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYWNlcnRz\n" + 
    		  "LmRpZ2ljZXJ0LmNvbS9DbG91ZEZsYXJlSW5jRUNDQ0EtMi5jcnQwDAYDVR0TAQH/\n" + 
    		  "BAIwADCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AKS5CZC0GFgUh7sTosxncAo8\n" + 
    		  "NZgE+RvfuON3zQ7IDdwQAAABb7qTzlYAAAQDAEcwRQIhAILEugEwcrO99A1UVu1n\n" + 
    		  "fCEYZzgDeOEiZvm+8HFI6ujjAiBHFYBXehHh/rX826HfLfuQVArfPHSSEdNIxLa4\n" + 
    		  "WAgwAgB2AF6nc/nfVsDntTZIfdBJ4DJ6kZoMhKESEoQYdZaBcUVYAAABb7qTzfAA\n" + 
    		  "AAQDAEcwRQIhAO6U5wDWRnzoAmb+FSCEk4ztbnyd2AJ/Y5F2A1kORAtTAiBa4e7L\n" + 
    		  "Zu4MokIML95hPL0+CmDW96pkYbh+fFvwJDEocjAKBggqhkjOPQQDAgNJADBGAiEA\n" + 
    		  "9gujEwmHlAj8XNyE8h3YpH0Z+Iq/HWYWmzWecldtm5ICIQD//CzlDnEzmsdXBy0U\n" + 
    		  "wt7NAJSBfPXDfMX2uSDQgQUzNw==\n" + 
    		  "-----END CERTIFICATE-----\n";
    		  */
      String Self_signed = "0";
      /*
      String sCert1 = "-----BEGIN CERTIFICATE-----\n"
    		  +"MIIFezCCBGOgAwIBAgIQDNrmdJVhms94iUC1J/RFyzANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQG\n"
    		  +"EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS8w\n"
    		  +"LQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNzdXJhbmNlIFNlcnZlciBDQTAeFw0xODAxMDkw\n"
    		  +"MDAwMDBaFw0yMTAyMTIxMjAwMDBaMIGNMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p\n"
    		  +"YTERMA8GA1UEBxMIU2FuIEpvc2UxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jwb3JhdGVk\n"
    		  +"MRowGAYDVQQLExFEaWdpdGFsIE1hcmtldGluZzEVMBMGA1UEAwwMKi5kZW1kZXgubmV0MIIBIjAN\n"
    		  +"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHnzaLiMkjadgAhr1weyAXzjSGtZ17HPrXWiYeJF\n"
    		  +"2oFH/WThmcLICr6yxlY7idQbxSyyR3LSjJGoJYd1BBZZCZfY8TOZnr1EsqNP0ND7Aock6XZC+AAg\n"
    		  +"YdeedwAQAKuz1n3Fho87o776lnvXKsWVU7XAzSlfe2BNe8ShENupGIH1oAhh4G/B1Dve6LadciJ7\n"
    		  +"bgUUn3Aw19jcJnhh/cJH+5kNcVOIKUf63wH5Ov2pNkGqvPsqNtS9IAIaEtsRBfSrECp03z3bUlNE\n"
    		  +"kFHE5+zSj/49RefNcOm+e82bvnlRPsIlHB+zJ9arolAZ7e71p/8I0V5SeE4Xsorf6UHxhwsVkwID\n"
    		  +"AQABo4IB8TCCAe0wHwYDVR0jBBgwFoAUUWj/kK8CB3U8zNllZGKiErhZcjswHQYDVR0OBBYEFAdF\n"
    		  +"vymUM5SmEbUTTqsggGfmLD/wMCMGA1UdEQQcMBqCDCouZGVtZGV4Lm5ldIIKZGVtZGV4Lm5ldDAO\n"
    		  +"BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHUGA1UdHwRuMGww\n"
    		  +"NKAyoDCGLmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWhhLXNlcnZlci1nNi5jcmwwNKAy\n"
    		  +"oDCGLmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWhhLXNlcnZlci1nNi5jcmwwTAYDVR0g\n"
    		  +"BEUwQzA3BglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29t\n"
    		  +"L0NQUzAIBgZngQwBAgIwgYMGCCsGAQUFBwEBBHcwdTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au\n"
    		  +"ZGlnaWNlcnQuY29tME0GCCsGAQUFBzAChkFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln\n"
    		  +"aUNlcnRTSEEySGlnaEFzc3VyYW5jZVNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3\n"
    		  +"DQEBCwUAA4IBAQBCEPqZtOIZP+eN3nGGJBsSzBXsCAResAu84NOjt5UYnRHx4NmmcDFzjh3Tuo2E\n"
    		  +"WKeSvyp0rpslprigvM5wza4LFCD3OfAQ5vGyPLLpByQStBOGZhQNdZUVknDbNAebAUcTwyFV+XzS\n"
    		  +"dCgoS2but6YPlMwPy5kGw9Ih+MewE09L1sF3ISPy+Eay3QYcoH2eBz+QYNNnm5arGm3nXw4DodnM\n"
    		  +"LW109M2JZjn3Z3gRSHgNrijc53ZuBOQsZhPGkAdXlkY08hDZ04iY8qNiP5ZkCctP6SDmdEaYY00q\n"
    		  +"kg7aT//h+MTPB+xIsJ86BzmPLAPvj6+AYR56CwXtYvR2pGqDziBc\n"
    		  +"-----END CERTIFICATE-----";
      String sCert2 = "-----BEGIN CERTIFICATE-----\n"
    		  +"MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG\n"
    		  +"EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSsw\n"
    		  +"KQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAw\n"
    		  +"MFoXDTI4MTAyMjEyMDAwMFowcDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ\n"
    		  +"MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFz\n"
    		  +"c3VyYW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC24C/CJAbI\n"
    		  +"bQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMICKq/QmO4LQNfE0DtyyBSe\n"
    		  +"75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaF\n"
    		  +"D15EWCo3j/018QsIJzJa9buLnqS9UdAn4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3Fhah\n"
    		  +"nSMSTeXXkgisdaScus0Xsh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZv\n"
    		  +"FEohQcftbZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEAMA4G\n"
    		  +"A1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNAYIKwYBBQUHAQEE\n"
    		  +"KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSwYDVR0fBEQwQjBAoD6g\n"
    		  +"PIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENB\n"
    		  +"LmNybDA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNl\n"
    		  +"cnQuY29tL0NQUzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D\n"
    		  +"aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwdaOpKj4PWUS+N\n"
    		  +"a0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNHE+r1hspZcX30BJZr01lYPf7T\n"
    		  +"MSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCY\n"
    		  +"JkJA69aSEaRkCldUxPUd1gJea6zuxICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbv\n"
    		  +"fXknsuvCnQsH6qqF0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIA\n"
    		  +"V0AecPUeybQ=\n"
    		  +"-----END CERTIFICATE-----";
    		 */ 
      //System.out.println(sCert);
      ArrayList<String> certs=new ArrayList<String>();
      try {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      //certs.add(sCert1);
      //certs.add(sCert2);
      int n = certs.size();
      /*
      for (int i=0;i<n-1;i++) {
    	  ByteArrayInputStream bytes1 = new ByteArrayInputStream(certs.get(i).getBytes());
    	  X509Certificate cert1 = (X509Certificate) certFactory.generateCertificate(bytes1);
    	  ByteArrayInputStream bytes2 = new ByteArrayInputStream(certs.get(i+1).getBytes());
    	  X509Certificate issuer1 = (X509Certificate) certFactory.generateCertificate(bytes2);
    	  System.out.println("issuer1 "+cert1.getIssuerDN());
    	  System.out.println("sub1 "+cert1.getSubjectDN());
    	  System.out.println("issuer2 "+issuer1.getIssuerDN());
    	  System.out.println("sub2 "+issuer1.getSubjectDN());
    	  System.out.println("cert 2 "+issuer1 );
    	  if (cert1.getIssuerX500Principal().equals(issuer1.getSubjectX500Principal()) == false) {
        	  System.out.println("Certificates do not chain");
          }
          cert1.verify(issuer1.getPublicKey());
          System.out.println("Verified: " + cert1.getSubjectX500Principal());
          if (cert1.getIssuerX500Principal().equals(cert1.getSubjectX500Principal())) {
              //cert1.verify(cert1.getPublicKey());
              System.out.println("certificate selfsigned");
          }
      }
      */
      ByteArrayInputStream bytes = new ByteArrayInputStream(sCert.getBytes());
      //System.out.println(bytes);
      X509Certificate c = (X509Certificate) certFactory.generateCertificate(bytes);
      //CertPath cp = .build(params).getCertPath();
      int nbr_ext = c.getCriticalExtensionOIDs().size() + c.getNonCriticalExtensionOIDs().size();
      System.out.println("Number of extensions "+ nbr_ext );
      
      System.out.println("Critical "+ c.getCriticalExtensionOIDs().size());
      System.out.println("no crtitcal "+ c.getNonCriticalExtensionOIDs().size());
      String c_str = c.toString();
      System.out.println("Cert :"+ c);
      //int nbr_ext = Integer.parseInt(c_str.substring(c_str.indexOf("Certificate Extensions:")+23,c_str.indexOf("Certificate Extensions:")+26).replaceAll("\\s+",""));
      //System.out.println("Nbr of extensions:"+nbr_ext );
      //ArrayList<Boolean> list_crtic = new ArrayList<Boolean>(0);
      //list_crtic.addAll(Collections.nCopies(0, Boolean.FALSE));
      //System.out.println("Nbr of extensions:"+      list_crtic );
      //for (int index = c_str.indexOf("Criticality=");
 		//     index >= 0;
 		 //    index = c_str.indexOf("Criticality=", index + 1))
 		//{
    	  //boolean b = Boolean.parseBoolean(c_str.substring(index+12,index+17).replaceAll("\\s+",""));
    	  //list_crtic.add(b);
 		//}
      //System.out.println("Nbr of extensions:"+c );
      //System.out.println("Nbr of criticallity :"+c );
      //System.out.println("Nbr of criticallity :"+list_crtic );
      long startTime = System.nanoTime();
      Validator validator = ValidatorBuilder.newInstance()
    		    .addRule(new ExpirationRule())
    		    .addRule(new SigningRule())
    		    .addRule(new CRLRule())
    		    //.addRule(new OCSPRule())
    		    .build();
      //Validator test = (Validator)"false";
      if (validator.isValid(c)) {
    	  System.out.println("valid");
      }
      else {
    	  System.out.println("certificate is revoked "); 
      }
      //String Self_signed = "0";
      if (c.getIssuerX500Principal().equals(c.getSubjectX500Principal())) {
          Self_signed = "1";
          }
      System.out.println("certificate is Self_signed "+ Self_signed);
      //System.out.println("validate :"+validator.isValid(c));
      //boolean fl = Boolean.FALSE;
      //System.out.println("No_critical = "+Collections.frequency(list_crtic, fl));
      //System.out.println("yes_critical = "+Collections.frequency(list_crtic, !fl));
      PublicKey pk = c.getPublicKey();
      String ld = getKeyLength(pk);
      System.out.println("algo and key size :" + ld) ;
      long endTime = System.nanoTime();
      long duration = (endTime - startTime);
      System.out.println("time exc :" +duration/100000000);
      
      
      System.out.println("issuer :" + c.getIssuerDN());
      System.out.println("subject :" + c.getSubjectDN());
      System.out.println("end cert :" + c.getNotAfter());
      System.out.println("start cert : " + c.getNotBefore());
      //X509CRL crl = null;
      //X509CRLEntry revokedCertificate = null;
      //System.out.println(CRL);
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] der = c.getEncoded();
      md.update(der);
      byte[] digest = md.digest();
      String digestHex = DatatypeConverter.printHexBinary(digest);
      System.out.println(" sha 1 certificate : " + digestHex.toLowerCase());
      }  catch (Exception ex) {
          ex.printStackTrace();
      }
     }
   public static String getKeyLength(PublicKey pk) {
   	String algo = null ;
       int len = -1;
       if (pk instanceof RSAPublicKey) {
       	 algo  ="RSA";
           final RSAPublicKey rsapub = (RSAPublicKey) pk;
           len = rsapub.getModulus().bitLength();
       } else if (pk instanceof JCEECPublicKey) {
       	algo = "JCEEC";
           final JCEECPublicKey ecpriv = (JCEECPublicKey) pk;
           final org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
           if (spec != null) {
               len = spec.getN().bitLength();              
           } else {
               // We support the key, but we don't know the key length
               len = 0;
           }
       } else if (pk instanceof ECPublicKey) {
       	algo = "EC";
           final ECPublicKey ecpriv = (ECPublicKey) pk;
           final java.security.spec.ECParameterSpec spec = ecpriv.getParams();
           if (spec != null) {	
               len = spec.getOrder().bitLength(); // does this really return something we expect?
           } else {
               // We support the key, but we don't know the key length
               len = 0;
           }
       } else if (pk instanceof DSAPublicKey) {
       	//System.out.println("DSA");
       	algo = "DSA";
           final DSAPublicKey dsapub = (DSAPublicKey) pk;
           if ( dsapub.getParams() != null ) {
               len = dsapub.getParams().getP().bitLength();
           } else {
               len = dsapub.getY().bitLength();
           }
       } 
       String finale = Integer.toString(len) + ";;;"+algo ;
       return finale;
   }
   
   public static void showFiles(File[] files) {
	    for (File file : files) {
	        if (file.isDirectory()) {
	            System.out.println("Directory: " + file.getName());
	            showFiles(file.listFiles()); // Calls same method again.
	        } else {
	            System.out.println("File: " + file.getName());
	        }
	    }
	}
}