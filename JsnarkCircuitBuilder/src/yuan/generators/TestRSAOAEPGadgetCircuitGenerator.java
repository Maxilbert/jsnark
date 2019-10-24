package yuan.generators;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Random;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.SHA256Gadget;
import yuan.gadgets.PinocchioGadget;
import yuan.gadgets.RSAOAEPGadget;
import yuan.util.RSAOAEPAlgorithms;
import yuan.util.RSAKeyGenerator;
import util.Util;

public class TestRSAOAEPGadgetCircuitGenerator extends CircuitGenerator {
	
	private final int RADIX_BITS = 4;
	private final int RADIX = (int) Math.pow(2, RADIX_BITS);

	private final int BIT_WIDTH = 64;
	private final int CHAR_WIDTH = BIT_WIDTH / RADIX_BITS;
	private final int ENC_BITS = 2048;

	private final int OAEP_BIT_WIDTH = 32;
	private final int RND_BITS = 256;
	private final int MSG_BITS = ENC_BITS - RND_BITS;
	
	private final int P_Q_LEN = ENC_BITS / BIT_WIDTH / 2;
	private final int B_D_N_LEN = ENC_BITS / BIT_WIDTH;
	private final int NRE_LEN = ENC_BITS / BIT_WIDTH + 2;

	
	private Wire eIn;
	private Wire[] nIn;
	private Wire[] nReIn;
	
	private Wire[] msg;		//
	private Wire[] rnd;		//256 bit = 8 integers

	
	private Wire tIn;
	private Wire[] pIn;
	private Wire[] qIn;
	private Wire[] bIn;
	private Wire[] dIn;

	private Wire[] outputs;

	
	public TestRSAOAEPGadgetCircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		
		//Public Inputs
		eIn = this.createInputWire();
		nIn = this.createInputWireArray(B_D_N_LEN);
		nReIn = this.createInputWireArray(NRE_LEN);
		
		//Secret Inputs
		tIn = this.createProverWitnessWire();
		//bIn = new Wire[B_D_N_LEN];
		//bIn = this.createProverWitnessWireArray(B_D_N_LEN);
		msg = this.createProverWitnessWireArray(MSG_BITS / OAEP_BIT_WIDTH);
		rnd = this.createProverWitnessWireArray(RND_BITS / OAEP_BIT_WIDTH);
		dIn = this.createProverWitnessWireArray(B_D_N_LEN);
		pIn = this.createProverWitnessWireArray(P_Q_LEN);
		qIn = this.createProverWitnessWireArray(P_Q_LEN);
		
		
		RSAOAEPGadget powerModGenerator = new RSAOAEPGadget(eIn, nIn, nReIn, msg, rnd, tIn, pIn, qIn, dIn);
		outputs = powerModGenerator.getOutputWires();

		makeOutput(outputs[0], "Is key matched?");
		makeOutputArray(Arrays.copyOfRange(outputs, 1, outputs.length), "rsa-oaep-ciphertext");
		//makeOutputArray(Util.concat(Util.concat(maskedMsgRnd, bIn), outputs));

	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		
		
		String message = "Ethereum plus snarks is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on...";
		
		int[] msg = RSAOAEPAlgorithms.stringTo56Integers(message);
		int[] rnd = new int[8];
		
		Random rand = new Random(0);
		RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(ENC_BITS, rand);
		
		String n = rsaKeyGenerator.getN().toString(RADIX); // bit length should be ENC_BITS
		String d = rsaKeyGenerator.getD().toString(RADIX); // bit length should be a little bit shorter than ENC_BITS
		String p = rsaKeyGenerator.getP().toString(RADIX); // bit length should be ENC_BITS / 2
		String q = rsaKeyGenerator.getQ().toString(RADIX); // bit length should be ENC_BITS / 2

		int e = rsaKeyGenerator.getE().intValue();
		

		//BigInteger biB = new BigInteger(msg.getBytes()); 
		//String b = biB.toString(RADIX);

		
		for(int i = 0; i < 56; i++){
			evaluator.setWireValue(this.msg[i], msg[i]);
		}
		for(int i = 0; i < 8; i++){
			rand = new Random(i);
			rnd[i] = rand.nextInt();
			evaluator.setWireValue(this.rnd[i], rnd[i] );
		}
		
		
		//prime p
		int lenP = p.length();
		int zeroPad2P = CHAR_WIDTH * P_Q_LEN - lenP;
		if(zeroPad2P > 0) {
			p = leftPadZero(p, zeroPad2P);
		} else if (zeroPad2P < 0){
			System.out.println("P length is not correct!");
		}
		for (int i = 0; i < P_Q_LEN; i++){			
			evaluator.setWireValue(pIn[i], new BigInteger(
					p.substring(p.length()-CHAR_WIDTH*i-CHAR_WIDTH, p.length()-CHAR_WIDTH*i), RADIX));
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
			evaluator.setWireValue(qIn[i], new BigInteger(
					q.substring(q.length()-CHAR_WIDTH*i-CHAR_WIDTH, q.length()-CHAR_WIDTH*i), RADIX));
		}
		
		//decrypt power, private key
		int lenD = d.length();
		int zeroPad2D = CHAR_WIDTH * B_D_N_LEN - lenD;
		if(zeroPad2D > 0) {
			d = leftPadZero(d, zeroPad2D);
		} else if (zeroPad2D < 0){
			System.out.println("D length is not correct!");
		}
		for (int i = 0; i < B_D_N_LEN; i++){			
			evaluator.setWireValue(dIn[i], new BigInteger(
					d.substring(d.length()-CHAR_WIDTH*i-CHAR_WIDTH, d.length()-CHAR_WIDTH*i), RADIX));
		}
		
		//modular base, public info
		int lenN = n.length();
		int zeroPad2N = CHAR_WIDTH * B_D_N_LEN - lenN;
		if(zeroPad2N > 0) {
			n = leftPadZero(n, zeroPad2N);
		} else if (zeroPad2N < 0){
			System.out.println("N length is not correct!");
		}
		for (int i = 0; i < B_D_N_LEN; i++){			
			evaluator.setWireValue(nIn[i], new BigInteger(
					n.substring(n.length()-CHAR_WIDTH*i-CHAR_WIDTH, n.length()-CHAR_WIDTH*i), RADIX));
		}
		
		//modular base n's reciprocal
		BigDecimal nDecimal = new BigDecimal(new BigInteger(n,RADIX));
		int shift = 2 * ENC_BITS + BIT_WIDTH;
		BigDecimal nDecimalReciprocal = new BigDecimal(new BigInteger("2").pow(shift)).
				divide(nDecimal, 0, RoundingMode.DOWN);
		BigInteger nReciprocal = nDecimalReciprocal.toBigInteger();
		String nRe = nReciprocal.toString(RADIX);
		int lenNRe = nRe.length();
		int zeroPad2NRe = CHAR_WIDTH * NRE_LEN - lenNRe;
		if(zeroPad2NRe > 0) {
			nRe = leftPadZero(nRe, zeroPad2NRe);
		} else if (zeroPad2NRe < 0){
			System.out.println("NRE length is not correct!");
		}
		for (int i = 0; i < NRE_LEN; i++){
			evaluator.setWireValue(nReIn[i], new BigInteger(
					nRe.substring(nRe.length()-CHAR_WIDTH*i-CHAR_WIDTH, nRe.length()-CHAR_WIDTH*i), RADIX));	
		}
		
		//encrypt power, public key
		evaluator.setWireValue(eIn, e);
		//t*(e*d) = (p-1)*(q-1)+1
		evaluator.setWireValue(tIn, 2);
		
		
		int[] maskedMsgRnd;
		try {
			String b = "";
			maskedMsgRnd = RSAOAEPAlgorithms.addMask(msg, rnd);
			for (int i = 0; i < 64; i++){
				//System.out.println(maskedMsgRnd[i] & 0xffffffffL);
				String iWordStr = BigInteger.valueOf(maskedMsgRnd[i] & 0xffffffffL).toString(16);
				iWordStr = leftPadZero(iWordStr, 8 - iWordStr.length());
				b = iWordStr + b;
			}
			BigInteger biR, biN;
			biN = new BigInteger(n, RADIX);
			biR = new BigInteger(b, RADIX).modPow(new BigInteger("3"), biN);
			System.out.println("RSA INPUT");
			System.out.println(b);
			System.out.println("RSA OUTPUT");
			System.out.println(biR.toString(16));
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
	}

	private String leftPadZero(String p, int zeroToPad){
		if(zeroToPad <= 0)
			return p;
		String ret = p;
		for(int i = 0; i < zeroToPad; i++){
			ret = "0" + ret;
		}
		return ret;
	}

	
	private void printHexOutputs(){
		System.out.println("Hex outputs:");
		BigInteger[] out = this.getCircuitEvaluator().getWiresValues(outputs);
		for (int i = 0; i < out.length; i++){
			System.out.println(out[i].toString(16));
		}
	}
	
	
	public static void main(String[] args) throws Exception {
		
		TestRSAOAEPGadgetCircuitGenerator generator = new TestRSAOAEPGadgetCircuitGenerator("rsa-oaep-2048-bitwidth-64");
		
		final boolean isCircuitGeneratorOnly = true;
		if (isCircuitGeneratorOnly) {
			generator.generateCircuit();
			generator.evalCircuit();
			generator.printHexOutputs();
			generator.prepFiles();
		} else {
			generator.runLibsnarkGenerator();
			generator.runLibsnarkProver();
			generator.runLibsnarkVerifier(); // parameter 2 can go through generator and prover
		}
		
	}


	
}
