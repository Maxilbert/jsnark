package yuan.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import yuan.gadgets.PinocchioGadget;

import util.Util;

public class WhileLoopTestGenerator extends CircuitGenerator {

	private Wire secretInput;
	
	private Wire[] outputs;
	
	private String pathToCompiledCircuit;
	
	public WhileLoopTestGenerator(String circuitName, String pathToCompiledCircuit) {
		super(circuitName);
		// TODO Auto-generated constructor stub
		this.pathToCompiledCircuit  = pathToCompiledCircuit;
	}

	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		secretInput = createProverWitnessWire();
		PinocchioGadget whileLoopTestGagdet = new PinocchioGadget(null, new Wire[]{secretInput}, pathToCompiledCircuit);
		outputs = whileLoopTestGagdet.getOutputWires();
		makeOutput(outputs[0], "summation");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		// TODO Auto-generated method stub
		int in = 15739;
		//The output will count how many 1s are in input's binary representation
		evaluator.setWireValue(secretInput, in);
		System.out.println(in);
	}

	public static void main(String[] args) throws Exception {
		WhileLoopTestGenerator generator = new WhileLoopTestGenerator("count_binary_one", "while-loop-test.c.arith");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.skipEvalCircuit();
		generator.prepFiles();
		//generator.runLibsnark();	
		generator.runLibsnarkGenerator();
		generator.runLibsnarkProver();
		generator.runLibsnarkVerifier();
	}
	
}
