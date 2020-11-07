package url_gen.url_gen;

/**
 * Hello world!
 *
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

//import java.util.ArrayList;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
//import org.apache.spark.sql.Dataset;
//import org.apache.spark.sql.Row;
//import org.apache.spark.sql.RowFactory;
//import org.apache.spark.sql.SparkSession;
//import org.apache.spark.sql.types.DataTypes;
//import org.apache.spark.sql.types.StringType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

//import javax.security.cert.X509Certificate;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.ValidatorBuilder;
import no.difi.certvalidator.rule.CRLRule;
import no.difi.certvalidator.rule.ExpirationRule;
import no.difi.certvalidator.rule.SigningRule;

import javax.net.ssl.HttpsURLConnection;

import java.util.Scanner;
//import javax.security.cert.Certificate;

/**
 * Hello world!
 *
 */

public class App 
{	
	
    public static void main( String[] args ) throws IOException, InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException
    {
    	//SparkSession spark = SparkSession.builder().appName("documentation").master("local").getOrCreate();
    	//spark.sparkContext().setLogLevel("ERROR");
        System.out.println( "Hello World!" );
        //String pathToCsv = args[0];
      //put your path file that contains a list of domain name
      //Format:
      //0,diaryofagameaddict.com
      //1,barak.cf
     // 2,ooredoo.tn
     // 3,barak.cf
     // 4,facebook.com
        String pathToCsv = "C:\\Users\\Abdelatif Chairi\\Desktop\\new_new.txt";   
        BufferedReader csvReader = new BufferedReader(new FileReader(pathToCsv));
        String row1;
        List<String> Subj=new ArrayList<String>();
        List<String> issue=new ArrayList<String>();
        List<String> self_si=new ArrayList<String>();
        List<String> revok=new ArrayList<String>();
        List<String> certip=new ArrayList<String>();
        List<String> crtical=new ArrayList<String>();
        List<String> no_crtical=new ArrayList<String>();
        List<String> urls=new ArrayList<String>();
        List<String> chain_rule=new ArrayList<String>();
        List<String> before=new ArrayList<String>();
        List<String> after=new ArrayList<String>();
        int k = 0 ;
		while (((row1 = csvReader.readLine()) != null)){
            String data = (String)row1;
            String[] data2 = data.split(",");
            String website = data2[1].replace("\"", "");
            //System.out.println("website :"+website);
            String end = "/";
            String start = "https://";
            String url =start+ website+end;
            //System.out.println("website :"+url);
            //System.out.println("website :"+url);***2
            // do something with the data

		//String data;
        urls.add(url);
        String aURL =url;
        System.out.println("website2 :"+url);
        System.out.println("instruction :"+k);
        k=k+1;
        
        //System.out.println("website5 :"+destinationURL2.getProtocol());
        //System.out.println("website2 :"+url);
        try {

		
        try {

			URL destinationURL = new URL(aURL);
			final HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
			final ExecutorService executor = Executors.newSingleThreadExecutor();
			Future<String> future = executor.submit(new Callable<String>() {

			    public String call() throws Exception {
			    	conn.connect();
			        return "OK";
			    }
			});
			try {
			    System.out.println(future.get(5, TimeUnit.SECONDS)); //timeout is in 2 seconds
			} catch (TimeoutException e) {
			    System.err.println("Timeout");
			}
			//executor.shutdown();
			//try { 
			//	  future.get(1, TimeUnit.MICROSECONDS);
			//	  logger.info("SQS_PUSH_SUCCESSFUL");
			//	  System.out.println("jdkj"+future);
			//	  executor.shutdownNow();

			//conn.connect();

			
			java.security.cert.X509Certificate[] certs = (java.security.cert.X509Certificate[]) conn.getServerCertificates();
			List<java.security.cert.X509Certificate> certList = Arrays.asList(certs);
			int n = certList.size();
			System.out.println("jdkj"+n);
			String issu = "";
			String sub = "";
			String a ="" ;
			String b="" ;
			String certype ="no type" ;
			String critical_ ="" ;
			String critical_no ="" ;
			String Chain = "";
			String bf = "";
			String af="";
			
			for (int i=0;i<n;i++) {
		            //System.out.println("");
		            //System.out.println("");
		            //System.out.println("");
		            //System.out.println("################################################################");
		            //System.out.println("");
		            //System.out.println("");
		            System.out.println("sub :"+certList.get(i).getSubjectDN());
		            System.out.println("issuer :"+certList.get(i).getIssuerDN());
		            issu += certList.get(i).getIssuerDN()+ "||";
		            sub += certList.get(i).getSubjectDN()+ "||";
		            critical_ += Integer.toString(certList.get(i).getCriticalExtensionOIDs().size())+ "||";
		            critical_no += Integer.toString(certList.get(i).getNonCriticalExtensionOIDs().size())+ "||";
		            bf+=certList.get(i).getNotBefore()+"||";
		            af+=certList.get(i).getNotAfter()+"||";
		            
		            System.out.println(critical_);
		            System.out.println(critical_no);

		            Validator validator = ValidatorBuilder.newInstance()
		        		    .addRule(new ExpirationRule())
		        		    .addRule(new SigningRule())
		        		    .addRule(new CRLRule())
		        		    //.addRule(new OCSPRule())
		        		    .build();
		            if (validator.isValid(certList.get(i))) {
		          	  System.out.println("valid");
		          	//System.out.println("certificate is not revoked ");
		          	  b =b+ "0";
		            }
		            else {
		            	b= b+ "1";
		          	  System.out.println("certificate is revoked "); 
		            }
		            b=b+"||";
		            if (certList.get(i).getIssuerX500Principal().equals(certList.get(i).getSubjectX500Principal())) {
		                //cert1.verify(cert1.getPublicKey());
		            	a =a+ "1";
		               System.out.println("certificate selfsigned");
		            }
		            else {
		            	a =a+"0" ;
		            	System.out.println("certificate not selfsigned");
		            }
		            a =a+"||";
		            
		            java.security.cert.X509Certificate cert = certList.get(i);
		            PublicKey pb =cert.getPublicKey();
		            System.out.println(getKeyLength(pb));
		            //RSAPublicKey rsaPk = (RSAPublicKey) cert.getPublicKey();
		            //System.out.println(rsaPk.getModulus().bitLength());
		            		byte[] value = cert.getExtensionValue("2.5.29.32");
		            		//System.out.println("Extensions "+value);
		            		if (value != null) { // extension is present
		            		    // CertificatePolicies is a sequence
		            		    DLSequence seq = (DLSequence) X509ExtensionUtil.fromExtensionValue(value);
		            		    //System.out.println("seq"+seq);
		            		    for (int j = 0; j < seq.size(); j++) {
		            		        // each element is also a sequence
		            		        DLSequence s = (DLSequence) seq.getObjectAt(j);
		            		        // first element is an OID
		            		        String oid = ((ASN1ObjectIdentifier) s.getObjectAt(0)).getId();
		            		        //System.out.println("oid "+oid);
		            		        if ("2.23.140.1.2.1".equals(oid)) {
		            		        	System.out.println("DV certificate");
		            		            // DV
		            		        	certype = "DV";
		            		        } 
		            		        if ("2.23.140.1.2.2".equals(oid)) {
		            		        	System.out.println("OV certificate");
		            		        	certype ="OV";
		            		        }
		            		        if ("2.16.840.1.114412.2.1".equals(oid) | "2.16.840.1.113733.1.7.23.6".equals(oid) | "2.23.140.1.1".equals(oid) ) {
		            		        	System.out.println("EV certificate");
		            		        	certype = "EV";
		            		        }
		            		    }
		            		}
		            		certype = certype +"||";
		            //X509Certificate c = (X509Certificate)cert;
			 }
			//System.out.println("self si"+a);
			//System.out.println("revok"+b);
			//System.out.println("self si"+critical_);
			//System.out.println("revok"+critical_no);
			//System.out.println("issuer all : "+issu);
			//System.out.println("sub all : "+sub);
			Subj.add(sub);
			issue.add(issu);
			revok.add(b);
			self_si.add(a);
			certip.add(certype);
			crtical.add(critical_);
			no_crtical.add(critical_no);
			for (int i=0;i<n-1;i++) {
			java.security.cert.X509Certificate cert1 = certList.get(i);
            java.security.cert.X509Certificate issuer1 = certList.get(i+1);
            //System.out.println("issuer1 is: " + cert1.getIssuerX500Principal());
            //System.out.println("subject1 is: " + cert1.getSubjectX500Principal());
            //System.out.println("issuer2 is: " + issuer1.getIssuerX500Principal());
            //System.out.println("subject2 is: " + issuer1.getSubjectX500Principal());
            
            //System.out.println("policy: " + issuer1.getExtensionValue(oid));
            if (cert1.getIssuerX500Principal().equals(issuer1.getSubjectX500Principal()) == false) {
          	  //System.out.println("Certificates do not chain");
          	  Chain = "1";
            }
            else {
            	//System.out.println("Certificates  chain");
            	Chain = "0";
            }
            Chain += "||";
            chain_rule.add(Chain);
            before.add(bf);
            after.add(af);
            //cert1.verify(issuer1.getPublicKey());
			}
	//}
		//catch (TimeoutException te) { 
		//	executor.shutdownNow();
		//	}
			
        } catch (MalformedURLException ex) {
			// TODO Auto-generated catch block
			continue;
		}
        }
        catch (Exception e) {
            continue;
        }
        k = k+1 ;
        System.out.println("iteration "+k);
        }
		csvReader.close();
        File file = new File("C:\\Users\\Abdelatif Chairi\\Desktop\\new_data.csv"); // put the path of the file name to store the certificate information
        System.out.println("Finiiishhhhh");
        FileWriter fw = new FileWriter(file);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write("Issuer,,,Subject,,,url,,,SelfSigned,,,Revoked,,,cert_type,,,critical,,,no_critical,,,chain_trusted,,,before,,,after");//separator ",,,"
        bw.newLine();
        for(int i=0;i<issue.size();i++)
        {
            bw.write(issue.get(i)+",,,"+Subj.get(i)+",,,"+urls.get(i)+",,,"+self_si.get(i)+",,,"+revok.get(i)+",,,"+certip.get(i)+",,,"+crtical.get(i)+",,,"+no_crtical.get(i)+",,,"+chain_rule.get(i)+",,,"+before.get(i)+",,,"+after.get(i));
            bw.newLine();
        }
        bw.close();
        fw.close();
        
    }
    public static String getKeyLength(final PublicKey pk) {
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
    
    
}