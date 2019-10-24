package yuan.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import yuan.gadgets.PinocchioGadget;

import util.Util;

public class IsBooleanGnerator extends CircuitGenerator {

	private Wire secretInput;
	
	private Wire[] outputs;
	
	private String pathToCompiledCircuit;
	
	public IsBooleanGnerator(String circuitName, String pathToCompiledCircuit) {
		super(circuitName);
		// TODO Auto-generated constructor stub
		this.pathToCompiledCircuit  = pathToCompiledCircuit;
	}

	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		secretInput = createProverWitnessWire();
		PinocchioGadget isBooleanGagdet = new PinocchioGadget(null, new Wire[]{secretInput}, pathToCompiledCircuit);
		outputs = isBooleanGagdet.getOutputWires();
		makeOutput(outputs[0], "is a boolean?");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		// TODO Auto-generated method stub
		int in = 1;
		evaluator.setWireValue(secretInput, in);
		System.out.println(in);
	}

	public static void main(String[] args) throws Exception {
		IsBooleanGnerator generator = new IsBooleanGnerator("partial_secret_sum", "is-boolean.arith");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();	
	}
	
}
