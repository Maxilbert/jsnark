package yuan.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import yuan.gadgets.PinocchioGadget;

import util.Util;

public class PartialSumGenerator extends CircuitGenerator {

	private Wire[] secretInputValues;
	private Wire[] publicInputValues; 
	
	private Wire[] outputs;
	
	private String pathToCompiledCircuit;
	
	public PartialSumGenerator(String circuitName, String pathToCompiledCircuit) {
		super(circuitName);
		// TODO Auto-generated constructor stub
		this.pathToCompiledCircuit  = pathToCompiledCircuit;
	}

	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		secretInputValues = createProverWitnessWireArray(10);
		publicInputValues = createInputWireArray(10);
		PinocchioGadget auctionGagdet = new PinocchioGadget(publicInputValues, secretInputValues, pathToCompiledCircuit);
		outputs = auctionGagdet.getOutputWires();
		makeOutput(outputs[0], "sum of all inputs");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		// TODO Auto-generated method stub
		BigInteger sum = new BigInteger("0");
		for(int i = 0; i < 10; i++){
			BigInteger a = Util.nextRandomBigInteger(31);
			sum = sum.add(a);
			evaluator.setWireValue(secretInputValues[i], a);
		}
		for(int i = 0; i < 10; i++){
			BigInteger a = Util.nextRandomBigInteger(31);
			evaluator.setWireValue(publicInputValues[i], a);
			sum = sum.add(a);
		}
		System.out.println(sum);
	}

	public static void main(String[] args) throws Exception {
		PartialSumGenerator generator = new PartialSumGenerator("partial_secret_sum", "secret-sum.arith");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();	
	}
	
}
