package Implemtor;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;

public abstract class Implementor {
	
	protected String name;
	public Implementor() {
		// TODO Auto-generated constructor stub
	}
	
	/**
	 * build the im
	 * 
	 * @param params - json string that contain parameters for this key Store 
	 * @throws Exception 
	 */
	public Implementor(String params) throws Exception {
		throw new Exception("unimplement"); 
	}
	
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Certificate	genrateKeyPair(String dName,String alias) throws ImplementorExcption{
		throw new ImplementorExcption("unimplemnt method"); 
	}
	
	public SecretKey	genrateSecertKey(String alg,String alias) throws ImplementorExcption{
		throw new ImplementorExcption("unimplemnt method"); 
	} 
	
	public  boolean		installSecertKey(SecretKey key, String alias) throws ImplementorExcption {
		throw new ImplementorExcption("unimplemnt method"); 
	} 
	
	public boolean		installTrustCert(Certificate cert ,String alias) throws ImplementorExcption {
		throw new ImplementorExcption("unimplemnt method"); 
	}
	
	public boolean		addToCrl(BigInteger serialNumber)  throws ImplementorExcption{
		throw new ImplementorExcption("unimplemnt method"); 
	}
	
	public boolean		removeCertificate(BigInteger serialNumber)  throws ImplementorExcption{
		throw new ImplementorExcption("unimplemnt metho"); 
	}
		
}
