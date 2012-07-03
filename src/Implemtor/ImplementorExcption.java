package Implemtor;

public class ImplementorExcption extends Exception {
	
	public ImplementorExcption(String msg) {
		super(msg); 
	}
	
	public ImplementorExcption(String msg,Throwable e) {
		super(msg,e); 
	}
	

}
