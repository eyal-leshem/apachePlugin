package Implemtor;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import sun.misc.BASE64Encoder;
import sun.security.x509.CertAndKeyGen;
//import sun.security.x509.X500Name;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder; 
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.*; 

import com.sun.corba.se.impl.oa.poa.AOMEntry;

import java.security.cert.X509CRL;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;



import javax.crypto.SecretKey;

public class ApacheImplemntor extends Implementor
{
	
	//apache file of trusted certificate  
	String caCertFilePath; 
	String serverCertFilePath; 
	String serverKeyFilePath; 
	String serverCRLFilePath;

	//the strings of rersent the start end the end of certificate 
	public final String beginCertString = "-----BEGIN CERTIFICATE-----\r\n"; 
	public final String endCertString = "\r\n-----END CERTIFICATE-----\r\n";
	public final String startRSAkeyString = "-----BEGIN RSA PRIVATE KEY-----\r\n"; 
	public final String endRSAkeyString = "\r\n-----END RSA PRIVATE KEY-----\r\n"; 
 
	public final String beginCrl = "-----BEGIN X509 CRL-----\r\n"; 
	public final String endCrl =  "\r\n-----END X509 CRL-----\r\n";
	
	//defualt alogrithems 
	public final String defaultSig = "SHA1withRSA";
	public final String defaultKpa = "RSA"; 
	public final String defaultProvider = "BC"; 
	
	/**
	 * main - used only to check this class  
	 * @param args
	 */
	
	public static void main(String[] args)
	{
		
		//gen cert
		//genrateKeyPair("Hadas", "keyName" );
		/*try 
		{
			ApacheImplemntor imp = new ApacheImplemntor("");
			//imp.genrateKeyPair("cn=a,ou=a,o=a,l=a,s=a,c=a", "HadasKey");
			//add to crl
			imp.addToCrl(new BigInteger("01"));
			
			
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
		
		
	}

    
    
    public ApacheImplemntor(String params) throws  Exception 
    {   
		
		/*
		 * json vars new to be : 
		 * {
		 *	 "caCertFilePath" :"the ca file of apache where the trusted certificate are",
		 *	 "serverCertFilePath":"the certificate file of the server" ,
		 *	 "serverKeyFilePath":"the file of the certificate of the server"
		 *	}  
		 */		
    	
    	//get the string from the json 
    	JSONObject json  =  new JSONObject(); 
    	caCertFilePath  =  json.getString("caCertFilePath");
    	serverCertFilePath  =  json.getString("serverCertFilePath"); 
    	serverKeyFilePath  =  json.getString("serverKeyFilePath");  
    	serverCRLFilePath  =  json.getString("serverCRLFilePath");
    	
    	
 
	}
	
	

	public Certificate genrateKeyPair(String dName,String alias) throws ImplementorExcption{
		
		//adapter 
		return this.genartePrivatekey(alias, dName); 	
	
	   		
	}



	/**
	 * get certificate that apache need to trust 
	 * and insert it into the the CaCertificatesFiles of 
	 * apache (where is the certificate that apache trust )
	 */
	@Override
	public boolean installTrustCert(Certificate cert,String alias) throws ImplementorExcption {

		//encode this certifcate in vase 64 
		BASE64Encoder base64Encoder = new BASE64Encoder(); 
		String	      encodeCertBody;
		try {
			encodeCertBody = base64Encoder.encode(cert.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new ImplementorExcption("cann't encode this string",e); 
		} 
		
		//full certificate string 
		String cerString = beginCertString+encodeCertBody+endCertString; 
		
		//add the cert to the apache certifcate ca file
		FileWriter fw;
		try {
			fw = new FileWriter(new File(this.caCertFilePath),true);
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
		
		
		//ok 
		return true ; 
	}



	@Override
	public SecretKey genrateSecertKey(String alg,String alias) throws ImplementorExcption {
		//not supported 
		throw new ImplementorExcption("apache not support private keys"); 
	}
	
	/**
	 * Generate a pair of private key and certificate that contain the public key
	 * @param alias  not used here 
	 * @param dName  the full subject form of this certificate 
	 * 
	 *	@return the new certificate that generated
	 * @throws MyKeyToolException
	 * @throws MykeyToolIoException
	 */
	private  Certificate genartePrivatekey(String alias,String dName) throws ImplementorExcption
	{
			 
		  //get key pain object 
		  CertAndKeyGen keypair;
		  try {
			 keypair  =  new CertAndKeyGen(defaultKpa,defaultSig,defaultProvider);
		  } catch (Exception e) {
				throw new ImplementorExcption("porblem while trying to create object of key pair", e); 
		  }
		
		  //create the relvant x500 name for this certificate 
		  sun.security.x509.X500Name x500Name;
		  try {
			x500Name  =  new sun.security.x509.X500Name(dName);
		  } catch (IOException e) {
			  throw new ImplementorExcption("problem to producde X500 Name",e);
		  }
		  
		  //gnerate the key and x.509 certificate  
		  try {
			keypair.generate(1024);
		  } catch (InvalidKeyException e) {
			throw new ImplementorExcption("porblem while trying to genrate key pair", e); 
		  }
		  PrivateKey privKey  =  keypair.getPrivateKey();
	
		  //get the self sign certificate 
		  X509Certificate[] chain  =  new X509Certificate[1];
  		  try {
			chain[0]  =  keypair.getSelfCertificate(x500Name, new Date(), 360*24L*60L*60L);
		  } 
		  catch (Exception e){
		  	throw new ImplementorExcption("problem to get self certificate form keypair",e);
		  }

		  //save the private key 
		  try{
			  savePrivtaeKey(privKey); 
		  }catch (ImplementorExcption e) {
			 throw new ImplementorExcption("problem to store the key",e); 
		  }

		  //sate the sel certificate 
		  try{
			  saveSelfCert(chain[0]); 
		  }catch (ImplementorExcption e) {
			  throw new ImplementorExcption("poblem to save the self certifcate",e);
		  }
		  
		  //retrun the certificate 
		  return chain[0]; 
		  
		  
	}


	/**
	 * change the certificate file of the apache to new certifcate 
	 * (it save the old certifcate as "certFile.crt.old")   
	 *
	 * @param cert  the new server certifcate to to store 
	 * @throws ImplementorExcption when the save fail 
	 */
	private void saveSelfCert(X509Certificate cert) throws ImplementorExcption {
		
		FileWriter fw; 
		String encodedKey;
		BASE64Encoder base64Encoder = new BASE64Encoder();
		
		//save the old server certificate 
		File certFile = new File(serverCertFilePath); 
		if(certFile.exists()){
			File old = new File(serverCertFilePath+".old"); 
			if(old.exists()) 
				old.delete(); 
			certFile.renameTo(new File(serverCertFilePath+".old")); 
		}
		
		
		//encode the certificate 
		try {
			encodedKey = base64Encoder.encode(cert.getEncoded());
		} 
		//try ro restore key file in fail 
		catch (CertificateEncodingException e) {
			if(restoreOldKey())
				throw new ImplementorExcption("problem encode sever cert , restore the old server key",e); 
			throw new ImplementorExcption("problem encode sever cert, no key and cert for this server",e); 
		}
		
		
		//open the file to write 
		try{
			fw = new FileWriter(serverCertFilePath); 
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
		try { fw.close(); } catch (IOException ignore){}	
		
		
		
	}


	/**
	* in case of failure it return the certifcate file of apache 
	* to be the old certificate 
	*/
	private boolean restoreOldCert() {
		File oldKeyFile = new File(serverCertFilePath+".old"); 
		
		//if exists restore the old key  
		if(oldKeyFile.exists())
		{
			
			//for success of rename 
			File badServerCertFile = new File(serverCertFilePath); 
			if(badServerCertFile.exists())
				badServerCertFile.delete(); 
			
			oldKeyFile.renameTo(new File(serverCertFilePath)); 
			return true; 
		}
		
		return false; 
	}




	/**
	 * save this private key to be the key file of the apache  
	 *(store the old key file in "keyfileName.key.old")
	 *
	 * @param privKey the private key for saving  
	 * @throws ImplementorExcption
	 */
private void savePrivtaeKey(PrivateKey privKey) throws ImplementorExcption {
		
		FileWriter fw; 
		
	
		
		File file = new File(serverKeyFilePath); 
		
		//save the old key for case of troubles
		if(file.exists()){
			
			File old = new File(file.getName()+".old");  
			
			//for success of remane 
			if(old.exists())
				old.delete();
			
			file.renameTo(old); 
		}
		
		//open the file to write 
		try 
		{					
			fw = new FileWriter(serverKeyFilePath);		
		} catch (IOException e) {
			throw new ImplementorExcption("can't open the key file to writing",e); 
		}
		
		//try write the key to the file 
		try
		{
			PEMWriter pemWriter=new PEMWriter(fw);
			pemWriter.writeObject(privKey);
			pemWriter.flush();
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
		File oldKeyFile = new File(serverKeyFilePath+".old"); 
		
		//if exists restore the old key  
		if(oldKeyFile.exists()){
			
			//delete for rename 
			File badServerKeyFile = new File(serverCertFilePath); 
			if(badServerKeyFile.exists())
				badServerKeyFile.delete(); 
			
			//restore
			oldKeyFile.renameTo(new File(serverKeyFilePath)); 
			return true; 
		}
		
		return false; 
		
	}
	

	/**
	 * Method for adding into CRL object new entries
	 */
	public boolean		addToCrl(BigInteger serialNumber)  throws ImplementorExcption
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		File crlFile = new File(serverCRLFilePath); 
		X509CRLHolder crl = null;
		
		//generate builder for CRL
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("CN=ca"), new Date());
		
		KeyPairGenerator kpGen;
		
		try 
		{
			kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		}
		catch (NoSuchAlgorithmException e) 
		{
			throw new ImplementorExcption("Error, while trying to get instance of algorithm for CRL ",e); 
			
		} 
		catch(NoSuchProviderException e)
		{
			throw new ImplementorExcption("Error, while trying to get instance of algorithm for CRL ",e); 
		}
		
        KeyPair pair = kpGen.generateKeyPair();
        
        //build the CRL and add the entries
        try 
        {
	        try 
			{
				//write into new file with temp name
				BASE64Encoder base64Encoder = new BASE64Encoder(); 
				String encodedCrl;
		       
				//if the file exists we have to copy the previous content into new object
				if(crlFile.exists())
				{
					//get all the current entries
					FileInputStream f  = new FileInputStream(new File(serverCRLFilePath)); 
					byte[] decData = new BASE64Decoder().decodeBuffer(f);
					
					//initiate the CRL holder from byteStream that we read
					X509CRLHolder holder = new X509CRLHolder(decData); 
					
					//copy the previous entries 
					crlGen.addCRL(holder);
					f.close();
				}
				
				crl = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider("BC").build(pair.getPrivate()));
				
				//check if exists is holder
				X509CRLEntryHolder entry = crl.getRevokedCertificate(serialNumber);
				
		        if (entry != null)
		        {
		        	throw new ImplementorExcption("The certificate is already revoked: "+ serverCRLFilePath);
		        }
				
		        //add new entry
				crlGen.addCRLEntry(serialNumber, new Date(), 0);
				
				crl = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider("BC").build(pair.getPrivate()));
				encodedCrl = base64Encoder.encode(crl.getEncoded()); 
			
				FileWriter fw = new FileWriter(serverCRLFilePath);
				fw.write(encodedCrl);
				fw.flush();
				fw.close();
				
			}
			//can't write to the file
			catch (IOException e) 
			{
				throw new ImplementorExcption("Cannot open FileInputStream of CRL file path: "+ serverCRLFilePath,e);
			}
        }
        catch (OperatorCreationException e)
        {
			throw new ImplementorExcption("Error while trying to build crlGen: ",e);

		}
        
        return true;
	}
	
	
	
	
}
