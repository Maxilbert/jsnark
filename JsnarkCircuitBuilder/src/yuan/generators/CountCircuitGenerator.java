package yuan.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import yuan.gadgets.PinocchioGadget;

import util.Util;

public class CountCircuitGenerator extends CircuitGenerator {

	private Wire[] secretInput;
	private Wire maxCount;
	
	private Wire[] outputs;
	
	private String pathToCompiledCircuit;
	
	public CountCircuitGenerator(String circuitName, String pathToCompiledCircuit) {
		super(circuitName);
		// TODO Auto-generated constructor stub
		this.pathToCompiledCircuit  = pathToCompiledCircuit;
	}

	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		maxCount = this.createInputWire("max_count");
		secretInput = this.createProverWitnessWireArray(10);
		PinocchioGadget whileLoopTestGagdet = new PinocchioGadget(null, Util.concat(maxCount, secretInput), pathToCompiledCircuit);
		outputs = whileLoopTestGagdet.getOutputWires();
		makeOutputArray(outputs, "count");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		// TODO Auto-generated method stub
		BigInteger[] in = {
				BigInteger.TEN,
				BigInteger.ONE.add(BigInteger.ONE),
				BigInteger.TEN,
				BigInteger.ONE.add(BigInteger.ONE),
				BigInteger.TEN,
				BigInteger.ONE.add(BigInteger.ONE),
				BigInteger.TEN,
				BigInteger.ZERO,
				BigInteger.ONE.add(BigInteger.ONE),
				BigInteger.TEN
				};
		evaluator.setWireValue(maxCount, 5);
		//The output will count how many 1s are in input's binary representation
		evaluator.setWireValue(secretInput, in);
		//System.out.println(in);
	}

	public static void main(String[] args) throws Exception {
		CountCircuitGenerator generator = new CountCircuitGenerator("count_in_array", "count.arith");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.skipEvalCircuit();
		generator.prepFiles();
		generator.runLibsnark();	
		//generator.runLibsnarkGenerator();
		//generator.runLibsnarkProver();
		//generator.runLibsnarkVerifier();
	}
	
}
