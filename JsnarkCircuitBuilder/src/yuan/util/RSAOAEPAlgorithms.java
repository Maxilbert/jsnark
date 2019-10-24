package yuan.util;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Random;


public class RSAOAEPAlgorithms {
	
	public static final int RADIX_BITS = 4;
	public static final int RADIX = (int) Math.pow(2, RADIX_BITS);

	public static final int BIT_WIDTH = 64;
	public static final int CHAR_WIDTH = BIT_WIDTH / RADIX_BITS;
	public static final int ENC_BITS = 2048;

	public static final int OAEP_BIT_WIDTH = 32;
	public static final int RND_BITS = 256;
	public static final int MSG_BITS = ENC_BITS - RND_BITS;
	
	public static final int P_Q_LEN = ENC_BITS / BIT_WIDTH / 2;
	public static final int B_D_N_LEN = ENC_BITS / BIT_WIDTH;
	public static final int NRE_LEN = ENC_BITS / BIT_WIDTH + 2;
	
	
	
	
	public static RSAKeyComponents generateRSAKeyComponents(RSAKeyGenerator rsaKeyGenerator, BigInteger[] pIn, BigInteger[] qIn, BigInteger[] dIn, BigInteger[] nIn, BigInteger[] nReIn, BigInteger[] eIn, BigInteger[] tIn) {
		
		RSAKeyComponents rsaKeyComponents = new RSAKeyComponents();
		
		rsaKeyComponents.rsa = rsaKeyGenerator;
		//RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(ENC_BITS, rnd);
		
		rsaKeyComponents.n = rsaKeyGenerator.getN();
		rsaKeyComponents.d = rsaKeyGenerator.getD();
		rsaKeyComponents.p = rsaKeyGenerator.getP();
		rsaKeyComponents.q = rsaKeyGenerator.getQ();
		rsaKeyComponents.e = rsaKeyGenerator.getE();
		
		String n = rsaKeyGenerator.getN().toString(RADIX); // bit length should be ENC_BITS
		String d = rsaKeyGenerator.getD().toString(RADIX); // bit length should be a little bit shorter than ENC_BITS
		String p = rsaKeyGenerator.getP().toString(RADIX); // bit length should be ENC_BITS / 2
		String q = rsaKeyGenerator.getQ().toString(RADIX); // bit length should be ENC_BITS / 2


		BigDecimal nDecimal = new BigDecimal(new BigInteger(n,RADIX));
		int shift = 2 * ENC_BITS + BIT_WIDTH;
		BigDecimal nDecimalReciprocal = new BigDecimal(new BigInteger("2").pow(shift)).
				divide(nDecimal, 0, RoundingMode.DOWN);
		BigInteger nReciprocal = nDecimalReciprocal.toBigInteger();
		String nRe = nReciprocal.toString(RADIX);
		
		rsaKeyComponents.nRe = nReciprocal;
		
		//prime p
		int lenP = p.length();
		int zeroPad2P = CHAR_WIDTH * P_Q_LEN - lenP;
		if(zeroPad2P > 0) {
			p = leftPadZero(p, zeroPad2P);
		} else if (zeroPad2P < 0){
			System.out.println("P length is not correct!");
		}
		for (int i = 0; i < P_Q_LEN; i++){			
			pIn[i] = new BigInteger(
					p.substring(p.length()-CHAR_WIDTH*i-CHAR_WIDTH, p.length()-CHAR_WIDTH*i), RADIX);
		}
		
		//prime q
		int lenQ = q.length();
		int zeroPad2Q = CHAR_WIDTH * P_Q_LEN - lenQ;
		if(zeroPad2Q > 0) {
			q = leftPadZero(q, zeroPad2Q);
		} else if (zeroPad2Q < 0){
			System.out.println("Q length is not correct!");
		}
		for (int i = 0; i < P_Q_LEN; i++){			
			qIn[i] = new BigInteger(
					q.substring(q.length()-CHAR_WIDTH*i-CHAR_WIDTH, q.length()-CHAR_WIDTH*i), RADIX);
		}
		
		//d, decrypt power, private key
		int lenD = d.length();
		int zeroPad2D = CHAR_WIDTH * B_D_N_LEN - lenD;
		if(zeroPad2D > 0) {
			d = leftPadZero(d, zeroPad2D);
		} else if (zeroPad2D < 0){
			System.out.println("D length is not correct!");
		}
		for (int i = 0; i < B_D_N_LEN; i++){			
			dIn[i] = new BigInteger(
					d.substring(d.length()-CHAR_WIDTH*i-CHAR_WIDTH, d.length()-CHAR_WIDTH*i), RADIX);
		}
		
		//n, modular base, public info
		int lenN = n.length();
		int zeroPad2N = CHAR_WIDTH * B_D_N_LEN - lenN;
		if(zeroPad2N > 0) {
			n = leftPadZero(n, zeroPad2N);
		} else if (zeroPad2N < 0){
			System.out.println("N length is not correct!");
		}
		for (int i = 0; i < B_D_N_LEN; i++){			
			nIn[i] = new BigInteger(
					n.substring(n.length()-CHAR_WIDTH*i-CHAR_WIDTH, n.length()-CHAR_WIDTH*i), RADIX);
		}
		
		//nRe, modular base n's reciprocal
		int lenNRe = nRe.length();
		int zeroPad2NRe = CHAR_WIDTH * NRE_LEN - lenNRe;
		if(zeroPad2NRe > 0) {
			nRe = leftPadZero(nRe, zeroPad2NRe);
		} else if (zeroPad2NRe < 0){
			System.out.println("NRE length is not correct!");
		}
		for (int i = 0; i < NRE_LEN; i++) {
			nReIn[i] = new BigInteger(
					nRe.substring(nRe.length()-CHAR_WIDTH*i-CHAR_WIDTH, nRe.length()-CHAR_WIDTH*i), RADIX);	
		}

		// t * (e * d) = (p - 1) * (q - 1) + 1
		tIn[0] = new BigInteger("2");
		eIn[0] = rsaKeyGenerator.getE();
		return rsaKeyComponents;
	}
	
	
	public static RSAKeyComponents generateRSAKeyComponents(BigInteger[] pIn, BigInteger[] qIn, BigInteger[] dIn, BigInteger[] nIn, BigInteger[] nReIn, BigInteger[] eIn, BigInteger[] tIn){
		Random rnd = new Random();
		//RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(ENC_BITS, rnd);
		BigInteger p = new BigInteger("fcbf88e7e2e534ad3278f119ed3a059441016332ab2a3098d1be0064035e202211cc887e2cc60d3b7c0362fd35b0f50cba4f2c554a04eab0f269f62578d7b6d1bf38f4cc0608093b335b9d989cafcb8c801d9e82cd9b3de145b1961bc104a1f7981978e00e337c1a355bf526090184f2863b4e2f0df1a39d5cbdc9898e41dce5", 16);
		BigInteger q = new BigInteger("fed1a6b51cf1629351ddffb26bf9ab68dac7cdeeccc05574b25f6ea07f5b96cb99e4c535de58ae0ee9d795025033f9b72749b9f57ed9d63884afb92a89f37c5a864f974252780c8c32648f34119aac5571d5fae6ced61fb485c122367c60b86ac495876cc6e9b3fdf9721d29c57fce2d1a3479274446cbb9343267ec3afb9387", 16);
		RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(p, q);
		return generateRSAKeyComponents(rsaKeyGenerator, pIn, qIn, dIn, nIn, nReIn, eIn, tIn);
	}
	
	public static RSAKeyComponents generateRSAKeyComponents(BigInteger p, BigInteger q, BigInteger[] pIn, BigInteger[] qIn, BigInteger[] dIn, BigInteger[] nIn, BigInteger[] nReIn, BigInteger[] eIn, BigInteger[] tIn){
		//RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(ENC_BITS, rnd);
		RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(p, q);
		return generateRSAKeyComponents(rsaKeyGenerator, pIn, qIn, dIn, nIn, nReIn, eIn, tIn);
	}
	
	
	public static int[] addMask(int[] msg, int[] rnd) throws Exception {
		
		if(msg.length != 56){
			throw new Exception("msg shoud be 56 integers");
		}
		
		if(rnd.length != 8){
			throw new Exception("rnd shoud be 8 integers");
		}
		
		SHA256For256[] g = new SHA256For256[7];
		
		g[0] = new SHA256For256(rnd);
		g[1] = new SHA256For256(g[0].getHash());
		g[2] = new SHA256For256(g[1].getHash());
		g[3] = new SHA256For256(g[2].getHash());
		g[4] = new SHA256For256(g[3].getHash());
		g[5] = new SHA256For256(g[4].getHash());
		g[6] = new SHA256For256(g[5].getHash());

		int[] maskedMsg = new int[56];
		for (int i = 0; i < 7; i++){
			for (int j = 0; j < 8; j++){
				maskedMsg[8*i+j] = g[i].getHash()[j] ^ msg[8*i+j];
			}
		}
		SHA256For1792 h = new SHA256For1792(maskedMsg);
		int[] maskedMsgHash = h.getHash();
		int[] maskedRnd = new int[8];
		for (int j = 0; j < 8; j++) {
			maskedRnd[j] = rnd[j] ^ maskedMsgHash[j];
		}
		int[] outputs =  new int[64];
		for (int i = 0; i < 64; i++) {
			if (i < 56){
				outputs[i] = maskedMsg[i];
			} else {
				outputs[i] = maskedRnd[i - 56];
			}
		}
		return outputs;
	}
	
	
	
	public static int[] removeMask(int[] maskedMsgRnd) throws Exception {
		
		if(maskedMsgRnd.length != 64){
			throw new Exception("masked msg plus rnd shoud be 64 integers");
		}
		int[] maskedMsg = Arrays.copyOfRange(maskedMsgRnd, 0, 56);
		int[] maskedRnd = Arrays.copyOfRange(maskedMsgRnd, 56, 64);

		SHA256For1792 h = new SHA256For1792(maskedMsg);
		int[] maskedMsgHash = h.getHash();
		
		int[] rnd = new int[8];
		
		for (int i = 0; i < 8; i++){
			rnd[i] = maskedMsgHash[i] ^ maskedRnd[i];
		}
		
		SHA256For256[] g = new SHA256For256[7];
		
		g[0] = new SHA256For256(rnd);
		g[1] = new SHA256For256(g[0].getHash());
		g[2] = new SHA256For256(g[1].getHash());
		g[3] = new SHA256For256(g[2].getHash());
		g[4] = new SHA256For256(g[3].getHash());
		g[5] = new SHA256For256(g[4].getHash());
		g[6] = new SHA256For256(g[5].getHash());

		int[] msg = new int[56];
		for (int i = 0; i < 7; i++){
			for (int j = 0; j < 8; j++){
				msg[8*i+j] = g[i].getHash()[j] ^ maskedMsg[8*i+j];
			}
		}
		int[] outputs =  new int[64];
		for (int i = 0; i < 64; i++) {
			if (i < 56){
				outputs[i] = msg[i];
			} else {
				outputs[i] = rnd[i - 56];
			}
		}
		return outputs;
	}

	public static int[] getRandom8Integers(int seed){
		Random rand;
		int[] ret = new int[8];
		for(int i = 0; i < 8; i++){
			rand = new Random(seed*i + seed + i*i+ i*i*i);
			ret[i] = rand.nextInt();
		}
		return ret;
	}
	
	public static int[] getRandom8Integers(){
		return getRandom8Integers(0);
	}
	
	public static int[] stringTo56Integers(String msg){
		int[] preparedMsg = new int[56];
		for (int i = 0; i < 56; i++){
			if (i*4+4 <= msg.length()){
				preparedMsg[i] = new BigInteger(msg.substring(i*4, i*4+4).getBytes()).intValue();
			} else if (i*4 < msg.length()) {
				preparedMsg[i] = new BigInteger(msg.substring(i*4, msg.length()).getBytes()).intValue();
			} else {
				preparedMsg[i] = 0;
			}
		}
		return preparedMsg;
	}
	
	public static String msgIntegersToString(int [] msg){
		String msgStr = "";
		for(int i = 0; i < msg.length; i++){
			if (msg[i] != 0)
				msgStr += new String(BigInteger.valueOf(msg[i]).toByteArray());
		}
		return msgStr;
	}
	
	
	public static BigInteger littleEndianIntArrayToBigInteger(int[] integers) {
		String b = "";
		for (int i = 0; i < integers.length; i++){
			String iWordStr = BigInteger.valueOf(integers[i] & 0xffffffffL).toString(16);
			iWordStr = leftPadZero(iWordStr, 8 - iWordStr.length());
			b = iWordStr + b;
		}
		return new BigInteger(b, RADIX);
	}
	
	public static BigInteger[] bigIntegerTo32BigIntegers(BigInteger b){
		return hexCipherTextTo32BigIntegers(b.toString(16));
	}
	
    public static BigInteger[] hexCipherTextTo32BigIntegers(String cipher){
        BigInteger[] res = new BigInteger[32];
        int zeroPaddingNum = 32 * 16 - cipher.length();
        for (int i = 0; i < zeroPaddingNum; i++){
            cipher = "0" + cipher;
        }
        for(int i = 31; i >= 0; i--){
            res[31-i] = new BigInteger(cipher.substring(i*16, i*16+16), 16);
        }
        return res;
    }
	
	public static int[] bigIntegerToLittleEndianIntArray(BigInteger bi, int n) {
		int[] ret = new int[n];
		String biStr = bi.toString(16);
		biStr = leftPadZero(biStr, 8*n - biStr.length());
		for (int i = 0; i < n; i++){
			ret[i] = new BigInteger(biStr.substring((n-i)*8 - 8, (n - i)*8),16).intValue();
		}
		return ret;
	}
	
	
	private static String leftPadZero(String p, int zeroToPad) {
		if(zeroToPad <= 0)
			return p;
		String ret = p;
		for(int i = 0; i < zeroToPad; i++){
			ret = "0" + ret;
		}
		return ret;
	}
	//CHAR_WIDTH
	
	
	public static BigInteger enc (BigInteger maskedMsgRnd, int e, BigInteger n) {
		//return maskedMsgRnd.pow(e).mod(n);
		BigInteger bi1 = maskedMsgRnd.pow(e).mod(n);
		//BigInteger bi2 = maskedMsgRnd.modPow(BigInteger.valueOf(e), n);
		//System.out.println(bi1.equals(bi2));
		return bi1;
	}
	
	
	public static BigInteger dec (BigInteger cihperText, BigInteger d, BigInteger n) {
		return cihperText.modPow(d, n);
	}
	
	public static BigInteger enc_rsa_oaep (int[] msg, int[] rnd, RSAKeyComponents rsaKeyComponents){
		int[] maskedMagRnd = null;
		try {
			maskedMagRnd = addMask(msg, rnd);
		} catch (Exception e) {
			e.printStackTrace();
		}
		BigInteger biMaskedMsgRnd = RSAOAEPAlgorithms.littleEndianIntArrayToBigInteger(maskedMagRnd);
        if (biMaskedMsgRnd.compareTo(rsaKeyComponents.n) >= 0) {
        	//System.err.println("Masked Message is bigger than N");
        	//BigInteger cipherText = RSAOAEPAlgorithms.enc(biMaskedMsgRnd, 3, rsaKeyComponents.n);
        	//return cipherText;
            throw new RuntimeException("Masked Message is bigger than N");
        }
		BigInteger cipherText = RSAOAEPAlgorithms.enc(biMaskedMsgRnd, 3, rsaKeyComponents.n);
		return cipherText;
	}
	
	public static void main(String[] args) {
		
		String message = "Ethereum plus snarks is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on...";
		
		int[] msg = RSAOAEPAlgorithms.stringTo56Integers(message + "\0");
		int[] rnd = RSAOAEPAlgorithms.getRandom8Integers(10);
		
		System.out.println("Sending Msg");
		for(int i = 0; i < 56; i++){
			System.out.println(msg[i] & 0xfffffffL);
		}
		
		System.out.println("Sending Rnd");
		for(int i = 0; i < 8; i++){
			System.out.println(rnd[i] & 0xfffffffL);
		}
		
		BigInteger[] pIn = new BigInteger[P_Q_LEN]; 
		BigInteger[] qIn = new BigInteger[P_Q_LEN];
		BigInteger[] dIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nReIn = new BigInteger[NRE_LEN]; 
		BigInteger[] eIn = new BigInteger[1];
		BigInteger[] tIn = new BigInteger[1];
		
		RSAKeyComponents rsaKeyComponents = RSAOAEPAlgorithms.generateRSAKeyComponents(pIn, qIn, dIn, nIn, nReIn, eIn, tIn);
		
		try {
			int[] maskedMagRnd = RSAOAEPAlgorithms.addMask(msg, rnd);
			BigInteger biMaskedMsgRnd = RSAOAEPAlgorithms.littleEndianIntArrayToBigInteger(maskedMagRnd);
			System.out.println("Masked Msg Rnd");
			System.out.println(biMaskedMsgRnd.toString(16));
			System.out.println("N. This number should larger than Masked Msg and Rnd.");
			System.out.println(rsaKeyComponents.n.toString(16));
	        if (biMaskedMsgRnd.compareTo(rsaKeyComponents.n) >= 0) {
	            throw new RuntimeException("Masked Message is bigger than N");
	        }
			BigInteger cipherText = RSAOAEPAlgorithms.enc(biMaskedMsgRnd, 3, rsaKeyComponents.n);
			BigInteger biRecoveredMaskedMsgRnd = RSAOAEPAlgorithms.dec(cipherText, rsaKeyComponents.d, rsaKeyComponents.n);
			int[] recoveredMaskedMsgRnd = RSAOAEPAlgorithms.bigIntegerToLittleEndianIntArray(biRecoveredMaskedMsgRnd, 64);
			int[] recoveredMsgRnd = RSAOAEPAlgorithms.removeMask(recoveredMaskedMsgRnd);
			msg = Arrays.copyOfRange(recoveredMsgRnd, 0, 56);
			rnd = Arrays.copyOfRange(recoveredMsgRnd, 56, 64);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Receiving Msg");
		for(int i = 0; i < 56; i++){
			System.out.println(msg[i] & 0xfffffffL);
		}

		System.out.println("Receiving Rnd");
		for(int i = 0; i < 8; i++){
			System.out.println(rnd[i] & 0xfffffffL);
		}
		
		System.out.println(msgIntegersToString(msg));
	}
	
	
	
	
}

