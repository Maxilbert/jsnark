package yuan.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.SHA256Gadget;

public class SHA256For1792 extends CircuitGenerator {

	private final int SHA256_BLOCK_NUM = 8;
	private final int BLOCK_NUM = 56;
	private int[] msg;
	
	private SHA256Gadget sha2Gadget;
	private Wire[] inputWires;
	private Wire[] digest;

	public SHA256For1792(int[] msg) throws Exception {
		
		super("sha256-" + msg + System.currentTimeMillis());
		if (msg.length != BLOCK_NUM) throw new Exception("Must have 48 inputs of int!"); 
		this.msg = msg;
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
		sha2Gadget = new SHA256Gadget(inputWires, 32, 224, false, true);
		digest = sha2Gadget.getOutputWires();
		makeOutputArray(digest, "digest");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		for (int i = 0; i < BLOCK_NUM; i++) {
			evaluator.setWireValue(inputWires[i], msg[i]);
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
