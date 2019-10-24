package yuan.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.SHA256Gadget;

public class SHA256ForGeneratingToken extends CircuitGenerator {

	private final int SHA256_BLOCK_NUM = 8;
	private final int BLOCK_NUM = 33;
	private BigInteger[] pk;
	private BigInteger addr;
	
	private SHA256Gadget sha2Gadget;
	private Wire[] inputWires;
	private Wire[] digest;

	public SHA256ForGeneratingToken(BigInteger addr, BigInteger[] pk) throws Exception {
		
		super("sha256-" + pk + System.currentTimeMillis());
		if ((pk.length+1) != BLOCK_NUM) throw new Exception("Must have 33 inputs of BigInteger!"); 
		this.pk = pk;
		this.addr = addr;
		PrintStream console = this.cancelConsolePrint();
		this.generateCircuit();
		this.evalCircuit();
		System.setOut(console);
		
	}
	

	@Override
	protected void buildCircuit() {
		// assuming the circuit input will be 48 integers
		inputWires = createInputWireArray(BLOCK_NUM);
		// this gadget is not applying any padding.
		sha2Gadget = new SHA256Gadget(inputWires, 160, 660, false, true);
		digest = sha2Gadget.getOutputWires();
		makeOutputArray(digest, "digest");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		evaluator.setWireValue(inputWires[0], addr);
		for (int i = 1; i < BLOCK_NUM; i++) {
			evaluator.setWireValue(inputWires[i], pk[i-1]);
		}
	}
	
	private Wire[] getDigest(){
		return digest;
	}
	
	
	public int[] getHash(){
		BigInteger[] hash = this.getCircuitEvaluator().getWiresValues(this.getDigest());
		int[] sha256 = new int[SHA256_BLOCK_NUM];
		for(int i = 0; i < hash.length; i++){
			sha256[i] = hash[i].intValue();
		}
		return sha256;
	}
	
	private PrintStream cancelConsolePrint() throws FileNotFoundException{
		PrintStream printStream = null;
		printStream = new PrintStream(new FileOutputStream("/dev/null"));
		PrintStream sysout = System.out;
		System.setOut(printStream);
		return sysout;
	}
	
	
}
