package yuan.generators;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import yuan.gadgets.WitnessedSumGadget;

public class WitnessedSumGenerator extends CircuitGenerator{

	private int dimension;
	
	//Witness Wires, secret inputs
	private Wire[] secretInputs;
	//Public input
	private Wire sum;
	private Wire witnessedSum;
	//Public output
	private Wire[] result;
	
	public WitnessedSumGenerator(String circuitName, int dimension) {
		super(circuitName);
		// TODO Auto-generated constructor stub
		this.dimension = dimension;
	}

	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		witnessedSum = this.createInputWire("prover's sum");
		sum = this.createProverWitnessWire("proved sum");
		secretInputs = this.createProverWitnessWireArray(dimension, "seceret input");
		WitnessedSumGadget witnessedadget = new WitnessedSumGadget(secretInputs, sum, witnessedSum, "Witnessed sum gadget");
		result = witnessedadget.getOutputWires();
		makeOutput(result[0], "sum of inputs");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		int summation = 0;
		for (int i = 0; i < this.dimension; i++) {
			summation += i;
			getCircuitEvaluator().setWireValue(secretInputs[i], i);
		}
		//getCircuitEvaluator().setWireValue(secretInputs[0], 1);
		getCircuitEvaluator().setWireValue(witnessedSum, summation);
	}

	public static void main(String[] args) throws Exception {

		WitnessedSumGenerator generator = new WitnessedSumGenerator("witnessed_summation", 10);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}


//package yuan.generators;
//
//import circuit.eval.CircuitEvaluator;
//import circuit.structure.CircuitGenerator;
//import circuit.structure.Wire;
//import yuan.gadgets.SumGadget;

//public class SumCircuitGenerator extends CircuitGenerator{
//	
//	private Wire[] seceretInputs;
//	private Wire[] result;
//	
//	private int dimension;
//	
//	public SumCircuitGenerator(String circuitName, int dimension) {
//		super(circuitName);
//		// TODO Auto-generated constructor stub
//		this.dimension = dimension;
//	}
//
//
//	@Override
//	protected void buildCircuit() {
//		// TODO Auto-generated method stub
//		seceretInputs = this.createProverWitnessWireArray(dimension, "seceret input");
//		SumGadget averageGadget = new SumGadget(seceretInputs, "sum gadget");
//		result = averageGadget.getOutputWires();
//		makeOutput(result[0], "sum of inputs");
//	}
//
//
//	@Override
//	public void generateSampleInput(CircuitEvaluator evaluator) {
//		// TODO Auto-generated method stub
//		for (int i = 1; i < this.dimension; i++) {
//			getCircuitEvaluator().setWireValue(seceretInputs[i], i);
//		}
//		getCircuitEvaluator().setWireValue(seceretInputs[0], 1);
//	}
//	
//	
//	public static void main(String[] args) throws Exception {
//
//		SumCircuitGenerator generator = new SumCircuitGenerator("summation", 10);
//		generator.generateCircuit();
//		generator.evalCircuit();
//		generator.prepFiles();
//		generator.runLibsnark();
//	}
//
//}
