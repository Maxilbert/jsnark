package yuan.generators;


import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import yuan.gadgets.RSAKeyPairingGadget;
import yuan.gadgets.RSAOAEPEncryptionGadget;
import yuan.util.RSAKeyComponents;
import yuan.util.RSAOAEPAlgorithms;


public class RSAOAEPBatchCircuitGenerator  extends CircuitGenerator {

	private final int PLAYER_NUM = 3;
	
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

	//Public Inputs
	private Wire eIn;
	private Wire[] nIn;
	private Wire[] nReIn;
	
	//Private Inputs for rsa-eaep-enc
	private Wire[][] msg = new Wire[PLAYER_NUM][MSG_BITS / OAEP_BIT_WIDTH];
	private Wire[][] rnd = new Wire[PLAYER_NUM][RND_BITS / OAEP_BIT_WIDTH];
	
	//Private Inputs for Key Pairing
	private Wire tIn;
	private Wire[] pIn;
	private Wire[] qIn;
	private Wire[] dIn;

	//Public Output
	private Wire[] keyPairingOutputs;
	private Wire[][] rsaOutputs = new Wire[PLAYER_NUM][];
	
	
	public RSAOAEPBatchCircuitGenerator(String circuitName) {
		super(circuitName);
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void buildCircuit() {
		
		//Public Inputs
		eIn = this.createInputWire();
		nIn = this.createInputWireArray(B_D_N_LEN);
		nReIn = this.createInputWireArray(NRE_LEN);
		//Wire[] inputWires = Util.concat(Util.concat(new Wire[]{eIn},nIn),nReIn);
		
		//Private Inputs for rsa-eaep-enc
		for (int i = 0; i < PLAYER_NUM; i++) {
			for (int j = 0; j < MSG_BITS / OAEP_BIT_WIDTH; j++) {
				msg[i][j] = this.createProverWitnessWire("Player " + i +", msg word " + j);
			}
			for (int j = 0; j < RND_BITS / OAEP_BIT_WIDTH; j++){
				rnd[i][j] = this.createProverWitnessWire("Player " + i +", rnd word " + j);
			}
		}
		
		//Private Inputs for Key Pairing
		tIn = this.createProverWitnessWire();
		dIn = this.createProverWitnessWireArray(B_D_N_LEN);
		pIn = this.createProverWitnessWireArray(P_Q_LEN);
		qIn = this.createProverWitnessWireArray(P_Q_LEN);
		
		RSAKeyPairingGadget rsaKeyPairingGadget = new RSAKeyPairingGadget(eIn, nIn, nReIn, tIn, pIn, qIn, dIn);
		keyPairingOutputs = rsaKeyPairingGadget.getOutputWires();
		//makeOutput(keyPairingOutputs[0], "Is key matched?");
		this.addEqualityAssertion(keyPairingOutputs[0], BigInteger.ONE, "Keys has to be paired");
		RSAOAEPEncryptionGadget[] rsaOAEPEncryptionGadget = new RSAOAEPEncryptionGadget[PLAYER_NUM];
		for (int i = 0; i < PLAYER_NUM; i++) {
			rsaOAEPEncryptionGadget[i] = new RSAOAEPEncryptionGadget(eIn, nIn, nReIn, msg[i], rnd[i]);
			rsaOutputs[i] = rsaOAEPEncryptionGadget[i].getOutputWires();
			makeOutputArray(rsaOutputs[i], "rsa-oaep-ciphertext for player " + i + " ");
		}
		
	}

	
	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		
		BigInteger[] pIn = new BigInteger[P_Q_LEN]; 
		BigInteger[] qIn = new BigInteger[P_Q_LEN];
		BigInteger[] dIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nReIn = new BigInteger[NRE_LEN]; 
		BigInteger[] eIn = new BigInteger[1]; 
		BigInteger[] tIn = new BigInteger[1];
		
		RSAKeyComponents rsaKeyComponents = RSAOAEPAlgorithms.generateRSAKeyComponents(pIn, qIn, dIn, nIn, nReIn, eIn, tIn);
	
		
		String[] message = new String[]{
		
		"Ethereum plus snarks is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on..."
		
		,"Ethereum plus zkSnark is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on..."
		
		,"Ethereum plus zksnarks is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on..."
		};

		evaluator.setWireValue(this.tIn, tIn[0]);
		evaluator.setWireValue(this.eIn, eIn[0]);
		evaluator.setWireValue(this.pIn, pIn);
		evaluator.setWireValue(this.qIn, qIn);	
		evaluator.setWireValue(this.dIn, dIn);
		evaluator.setWireValue(this.nIn, nIn);
		evaluator.setWireValue(this.nReIn, nReIn);

		int[] msgIndex = new int[] {1,2,0, 2,1,2, 2,0,0, 2,2,1,0};
		for (int i = 0; i < PLAYER_NUM; i++){
			int[] msg = RSAOAEPAlgorithms.stringTo56Integers(message[msgIndex[i] % 3]);
			int[] rnd = RSAOAEPAlgorithms.getRandom8Integers(i + 20*i + 10);
			try {
				setValue(evaluator, this.msg[i], msg);
				setValue(evaluator, this.rnd[i], rnd);
				BigInteger cipherText = RSAOAEPAlgorithms.enc_rsa_oaep(msg, rnd, rsaKeyComponents);
				System.out.println("Player " + i + "'s rsa-oaep chiper text:");
				System.out.println(cipherText.toString(16));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}	
	}
	
	
	private void setValue(CircuitEvaluator e, Wire[] w, int[] v) throws Exception{
		if (w.length != v.length) 
			throw new Exception("w and v should have same length");
		for (int i = 0; i < w.length; i++){
			e.setWireValue(w[i], v[i]);
		}
	}
	

	private void printHexOutputs(){
		System.out.println("Hex outputs:");
		System.out.println("Key Pairing Hex outputs:");
		System.out.println(this.getCircuitEvaluator().getWireValue(keyPairingOutputs[0]));
		for (int i = 0; i < PLAYER_NUM; i++){
			BigInteger[] rsaOutputs = this.getCircuitEvaluator().getWiresValues(this.rsaOutputs[i]);
			System.out.println("Player " + i + "'s RSA-OAEP Hex outputs:");
			for (int j = 0; j < rsaOutputs.length; j++){
				System.out.println(rsaOutputs[j].toString(16));
			}
		}
	}
	
	
	public static void main(String[] args) throws Exception {
		
		RSAOAEPBatchCircuitGenerator generator = new RSAOAEPBatchCircuitGenerator("rsa-oaep-2048-batch");
		
		final boolean isCircuitGeneratorOnly = false;
		if (isCircuitGeneratorOnly) {
			generator.generateCircuit();
			generator.evalCircuit();
			generator.printHexOutputs();
			generator.prepFiles();
		} else {
			//generator.runLibsnarkGenerator();
			//generator.runLibsnarkProver();
			generator.runLibsnarkVerifier(2); // parameter 2 can go through generator and prover
		}
	}
	
	
}
