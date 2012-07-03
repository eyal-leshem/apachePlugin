package Implemtor;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import sun.misc.BASE64Encoder;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import org.json.*; 



import javax.crypto.SecretKey;

public class ApacheImplemntor extends Implementor {
	
	//apache file of trusted certificate  
	String caCertFilePath; 
	String serverCertFilePath; 
	String serverKeyFilePath; 

	//the strings of rersent the start end the end of certificate 
	public final String beginCertString="-----BEGIN CERTIFICATE-----\r\n"; 
	public final String endCertString="\r\n-----END CERTIFICATE-----\r\n";
	public final String startRSAkeyString="-----BEGIN RSA PRIVATE KEY-----\r\n"; 
	public final String endRSAkeyString="\r\n-----END RSA PRIVATE KEY-----\r\n"; 
 
	//defualt alogrithems 
	public final String defaultSig="SHA1withRSA";
	public final String defaultKpa="RSA"; 
	public final String defaultProvider="BC"; 
	
	

    
    
    public ApacheImplemntor(String params) throws  Exception {   
		
		/*
		 * json vars new to be : 
		 * {
		 *	 "caCertFilePath" :"the ca file of apache where the trusted certificate are",
		 *	 "serverCertFilePath":"the certificate file of the server" ,
		 *	 "serverKeyFilePath":"the file of the certificate of the server"
		 *	}  
		 */		
    	JSONObject json=new JSONObject(); 
    	caCertFilePath=json.getString("caCertFilePath");
    	serverCertFilePath=json.getString("serverCertFilePath"); 
    	serverKeyFilePath=json.getString("serverKeyFilePath");  
    	
    	
	}
	
	

	@Override
	public Certificate genrateKeyPair(String dName,String alias) throws ImplementorExcption{
		return this.genartePrivatekey(alias, dName); 
		
		/*CertificateFactory cf;
		
		try {
			cf=CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new ImplementorExcption("can't load certifcate factory",e);
		}
		
		File apacheTrustedCertFile=new File(caCertFilePath); 
		
		InputStream in;
		try {
			in=new FileInputStream(apacheTrustedCertFile);
		} catch (FileNotFoundException e) {
			throw new ImplementorExcption("problem with apache ca cert file", e); 
		} 
		
		Certificate cert; 
		try {
			cert=cf.generateCertificate(in);
		} catch (CertificateException e) {
			throw new ImplementorExcption("problem to genrate the certificate from file exception",e); 
		} 
		
		
		return cert; 
		*/
		
	   		
	}




	@Override
	public boolean installTrustCert(Certificate cert,String alias) throws ImplementorExcption {

		BASE64Encoder base64Encoder=new BASE64Encoder(); 
		String	      encodeCertBody;
		try {
			encodeCertBody=base64Encoder.encode(cert.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new ImplementorExcption("cann't encode this string",e); 
		} 
		String cerString=beginCertString+encodeCertBody+endCertString; 
		
		FileWriter fw;
		try {
			fw=new FileWriter(new File(this.caCertFilePath),true);
		} catch (IOException e) {
			throw new ImplementorExcption("can't open the file : "+caCertFilePath+" to write", e); 
		}
		
		try {
			fw.write(System.getProperty("line.separator"));
			fw.write(encodeCertBody); 
			fw.flush(); 
		} catch (IOException e) {
			throw new ImplementorExcption("can't save the certificate to the file", e); 
		} 
		finally{
			try {fw.close();} catch (IOException e) {}				
		}
		
		
		
		return false ; 
	}



	@Override
	public SecretKey genrateSecertKey(String alg,String alias) throws ImplementorExcption {
		throw new ImplementorExcption("apache not support private keys"); 
	}
	
	/**
	 * Generate a pair of private key and certificate that contain the public key
	 * @param alias
	 * @param dName
	 * @return the new certificate that generated
	 * @throws MyKeyToolException
	 * @throws MykeyToolIoException
	 */
	private  Certificate genartePrivatekey(String alias,String dName) throws ImplementorExcption{
			 
		  
		  CertAndKeyGen keypair;
		  try {
			 keypair = new CertAndKeyGen(defaultKpa,defaultSig,defaultProvider);
		  } catch (Exception e) {
				throw new ImplementorExcption("porblem while trying to create object of key pair", e); 
		  }
		
		  X500Name x500Name;
		  try {
			x500Name = new X500Name(dName);
		  } catch (IOException e) {
			  throw new ImplementorExcption("problem to producde X500 Name",e);
		  }
		  try {
			keypair.generate(1024);
		  } catch (InvalidKeyException e) {
			throw new ImplementorExcption("porblem while trying to genrate key pair", e); 
		  }
		  PrivateKey privKey = keypair.getPrivateKey();
		  X509Certificate[] chain = new X509Certificate[1];
		  
		  try {
			chain[0] = keypair.getSelfCertificate(x500Name, new Date(), 360*24L*60L*60L);
		  } 
		  catch (Exception e){
		  	throw new ImplementorExcption("problem to get self certificate form keypair",e);
		  }

		  try{
			  savePrivtaeKey(privKey); 
		  }catch (ImplementorExcption e) {
			 throw new ImplementorExcption("problem to store the key",e); 
		  }
		  
		  try{
			  saveSelfCert(chain[0]); 
		  }catch (ImplementorExcption e) {
			  throw new ImplementorExcption("poblem to save the self certifcate",e); 
		}
		  
		  
		  
		  return chain[0]; 
		  
		  
	}



	private void saveSelfCert(X509Certificate cert) throws ImplementorExcption {
		
		FileWriter fw; 
		String encodedKey;
		BASE64Encoder base64Encoder=new BASE64Encoder();
		
		//save the old server certificate 
		File certFile=new File(serverCertFilePath); 
		if(certFile.exists()){
			File old=new File(serverCertFilePath+".old"); 
			if(old.exists()) 
				old.delete(); 
			certFile.renameTo(new File(serverCertFilePath+".old")); 
		}
		
		
		//encode the certificate 
		try {
			encodedKey=base64Encoder.encode(cert.getEncoded());
		} 
		//try ro restore key file in fail 
		catch (CertificateEncodingException e) {
			if(restoreOldKey())
				throw new ImplementorExcption("problem encode sever cert , restore the old server key",e); 
			throw new ImplementorExcption("problem encode sever cert, no key and cert for this server",e); 
		}
		
		
		//open the file to write 
		try{
			fw=new FileWriter(serverCertFilePath); 
		}
		//try to restore key file in fail 
		catch(IOException e){
			if(restoreOldKey())
				throw new ImplementorExcption("problem open sever cert file , restore the old server key",e); 
			throw new ImplementorExcption("problem open sever cert file, no key and cert for this server",e);
		}
		
		
		//write the certificate to the file 
		try{
			fw.write(beginCertString); 
			fw.write(encodedKey); 
			fw.write(endCertString); 
			fw.flush(); 
		}
		//case of error try to restore the old data
		catch (IOException e) {
			if(restoreOldKey()&&restoreOldCert()) 
				throw new ImplementorExcption("problem while writing to server certificate file , restore the old server key and cert",e); 
			throw new ImplementorExcption("problem while writing to server certificate file ,no key and certificate for this server",e);
		}
		
		//close file
		try {fw.close();} catch (IOException ignore){}	
		
		
		
	}



	private boolean restoreOldCert() {
		File oldKeyFile=new File(serverCertFilePath+".old"); 
		
		//if exists restore the old key  
		if(oldKeyFile.exists()){
			
			//for success of rename 
			File badServerCertFile=new File(serverCertFilePath); 
			if(badServerCertFile.exists())
				badServerCertFile.delete(); 
			
			oldKeyFile.renameTo(new File(serverCertFilePath)); 
			return true; 
		}
		
		return false; 
	}



	private void savePrivtaeKey(PrivateKey privKey) throws ImplementorExcption {
		
		FileWriter fw; 
		BASE64Encoder base64Encoder=new BASE64Encoder();
		String encodedKey=base64Encoder.encode(privKey.getEncoded()); 
		
		File file=new File(serverKeyFilePath); 
		
		//save the old key for case of troubles
		if(file.exists()){
			
			File old=new File(file.getName()+".old");  
			
			//for success of remane 
			if(old.exists())
				old.delete();
			
			file.renameTo(old); 
		}
		
		//open the file to write 
		try {					
			fw=new FileWriter(serverKeyFilePath);		
		} catch (IOException e) {
			throw new ImplementorExcption("can't open the key file to writing",e); 
		}
		
		//try write the key to the file 
		try{
			fw.write(startRSAkeyString);
			fw.write(encodedKey); 
			fw.write(endRSAkeyString); 
			fw.flush();
		}
		
		//can't write to the file
		catch (IOException e) {
			//try to restore the old key 
			if(restoreOldKey())
				throw new ImplementorExcption("problem to store the new key ,return to use in old key",e); 
			//can't restore the old key 
			throw new ImplementorExcption("problem to store the new key ,no key and cert for this server",e);
		}
		
		//close file
		try {fw.close();} catch (IOException ignore){}		
				
	}
	
	/**
	 * restore the old key from the old key file path 
	 * @return true only on success 
	 */
	private boolean restoreOldKey(){
		File oldKeyFile=new File(serverKeyFilePath+".old"); 
		
		//if exists restore the old key  
		if(oldKeyFile.exists()){
			
			//delete for rename 
			File badServerKeyFile=new File(serverCertFilePath); 
			if(badServerKeyFile.exists())
				badServerKeyFile.delete(); 
			
			//restore
			oldKeyFile.renameTo(new File(serverKeyFilePath)); 
			return true; 
		}
		
		return false; 
		
	}
	


}
