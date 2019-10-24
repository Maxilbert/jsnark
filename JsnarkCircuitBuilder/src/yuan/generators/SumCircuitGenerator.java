package yuan.generators;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import yuan.gadgets.SumGadget;

public class SumCircuitGenerator extends CircuitGenerator{
	
	private Wire[] seceretInputs;
	private Wire[] result;
	private Wire sum;
	private Wire num;
	
	private int dimension;
	
	public SumCircuitGenerator(String circuitName, int dimension) {
		super(circuitName);
		// TODO Auto-generated constructor stub
		this.dimension = dimension;
	}


	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		seceretInputs = this.createProverWitnessWireArray(dimension, "seceret input");
		sum = this.createProverWitnessWire("summation");
		num = this.createInputWire("num");
		SumGadget averageGadget = new SumGadget(seceretInputs, sum, num, "sum gadget");
		result = averageGadget.getOutputWires();
		makeOutput(result[0], "sum of inputs");
		makeOutput(result[1], "avg of inputs");
	}


	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		// TODO Auto-generated method stub
		int summation = 0;
		for (int i = 0; i < this.dimension; i++) {
			getCircuitEvaluator().setWireValue(seceretInputs[i], i);
			summation += i;
		}
		getCircuitEvaluator().setWireValue(sum, summation);
		getCircuitEvaluator().setWireValue(num, dimension);
	}
	
	
	public static void main(String[] args) throws Exception {

		SumCircuitGenerator generator = new SumCircuitGenerator("summation", 10);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
