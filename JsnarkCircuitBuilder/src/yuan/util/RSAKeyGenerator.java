package yuan.util;

import java.math.BigInteger;
import java.util.Random;

/**
 * Created by Weiran Liu on 2015/11/13.
 *
 * An RSA implementation
 */
public class RSAKeyGenerator {
    private int securityParam;
    private Random random;
    private BigInteger bigIntN;
    private BigInteger bigIntP;
    private BigInteger bigIntQ;

    private BigInteger bigIntPhiN;
    private BigInteger e;
    private BigInteger d;

    private final BigInteger minN = BigInteger.valueOf(2).pow(2043).multiply(new BigInteger("30"));
    //private final BigInteger minN = BigInteger.valueOf(1);
    public RSAKeyGenerator(int securityParam) {
    	this(securityParam, new Random());
    }
    
    public RSAKeyGenerator(int securityParam, Random rnd) {
        this.securityParam = securityParam;
        this.random = rnd;
        this.bigIntP = null;
        this.bigIntQ = null;
        int count = 0;
        while (true) {
        	count ++;
            try {
                //In some cases, e does not have inverse in phi(N), repeat until find valid phi(N)
                bigIntP = BigInteger.probablePrime(securityParam / 2, random);
                bigIntQ = BigInteger.probablePrime(securityParam / 2, random);
                this.bigIntN = bigIntP.multiply(bigIntQ);
                this.bigIntPhiN = this.bigIntN.subtract(bigIntP).subtract(bigIntQ).add(BigInteger.ONE);
                //We choose a recommended public key e = 65537
                this.e = new BigInteger("3");
                this.d = e.modInverse(bigIntPhiN);
                if(this.bigIntN.compareTo(this.minN) == 1){
                	break;
                }
                else {
                	//System.out.println(this.bigIntN.toString(16));
                	random = new Random(System.currentTimeMillis()%1000 + 1000*count*count*count + 100*count*count + 10*count);
                	continue;
                }
            } catch (ArithmeticException e) {
            	random = new Random(System.currentTimeMillis()%1000 + 1000*count*count*count + 100*count*count + 10*count);
                continue;
            }
        }
    }
    
    public RSAKeyGenerator(BigInteger p, BigInteger q) {
    	try {
	    	this.bigIntP = p;
	    	this.bigIntQ = q;
	    	this.bigIntN = bigIntP.multiply(bigIntQ);
	    	this.bigIntPhiN = this.bigIntN.subtract(bigIntP).subtract(bigIntQ).add(BigInteger.ONE);
	        //We choose a recommended public key e = 65537
	        this.e = new BigInteger("3");
	        this.d = e.modInverse(bigIntPhiN);
	    } catch (ArithmeticException e){
	    	System.err.println(p.toString(16));
	    	System.err.println(q.toString(16));
	    }
    }

    public void setE(BigInteger bigIntE) {
        while (true) {
            try {
                //In some cases, e does not have inverse in phi(N), repeat until find valid phi(N)
                this.bigIntP = BigInteger.probablePrime(securityParam / 2, random);
                this.bigIntQ = BigInteger.probablePrime(securityParam / 2, random);
                this.bigIntN = bigIntP.multiply(bigIntQ);
                this.bigIntPhiN = this.bigIntN.subtract(bigIntP).subtract(bigIntQ).add(BigInteger.ONE);
                //We choose a recommended public key e = 65537
                this.e = bigIntE;
                this.d = e.modInverse(bigIntPhiN);
                break;
            } catch (ArithmeticException e) {
                continue;
            }
        }
    }

    public void setD(BigInteger bigIntD) {
        while (true) {
            try {
                //In some cases, e does not have inverse in phi(N), repeat until find valid phi(N)
                this.bigIntP = BigInteger.probablePrime(securityParam / 2, random);
                this.bigIntQ = BigInteger.probablePrime(securityParam / 2, random);
                this.bigIntN = bigIntP.multiply(bigIntQ);
                this.bigIntPhiN = this.bigIntN.subtract(bigIntP).subtract(bigIntQ).add(BigInteger.ONE);
                //We choose a recommended public key e = 65537
                this.d = bigIntD;
                this.e = d.modInverse(bigIntPhiN);
                break;
            } catch (ArithmeticException e) {
                continue;
            }
        }
    }

    public void setPandQ(BigInteger bigIntP, BigInteger bigIntQ) {
        this.bigIntN = bigIntP.multiply(bigIntQ);
        this.bigIntPhiN = this.bigIntN.subtract(bigIntP).subtract(bigIntQ).add(BigInteger.ONE);
        BigInteger bigIntE = new BigInteger("65537");
        while (true) {
            try {
                //In some cases, e does not have inverse in phi(N), repeat until find valid phi(N)
                this.e = bigIntE;
                this.d = e.modInverse(bigIntPhiN);
                break;
            } catch (ArithmeticException e) {
                bigIntE = bigIntE.add(BigInteger.ONE);
                continue;
            }
        }
    }

    public BigInteger getE() {
        return this.e;
    }

    public BigInteger getD() {
        return this.d;
    }

    public BigInteger getN() {
        return this.bigIntN;
    }

    public BigInteger getP() { return this.bigIntP; }

    public BigInteger getQ() { return this.bigIntQ; }

    public byte[] encrypt(String message) {
        byte[] byteMessage = message.getBytes();
        BigInteger bigIntMessage = new BigInteger(byteMessage);
        if (bigIntMessage.compareTo(this.bigIntN) >= 0) {
            throw new RuntimeException("Message is bigger than N");
        }
        return bigIntMessage.modPow(this.e, this.bigIntN).toByteArray();
    }

    public String decrypt(byte[] ciphertext) {
        BigInteger bigIntCiphertext = new BigInteger(ciphertext);
        byte[] byteMessage = bigIntCiphertext.modPow(this.d, this.bigIntN).toByteArray();
        return new String(byteMessage);
    }
}
