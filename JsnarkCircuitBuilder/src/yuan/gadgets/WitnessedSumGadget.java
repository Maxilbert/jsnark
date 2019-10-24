package yuan.gadgets;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;

public class WitnessedSumGadget extends Gadget{
	
	//Witness Wires, secret inputs
	private Wire[] secretInputs;
	//Public output
	private Wire sum;
	
	private Wire witnessedSum;

	
	public WitnessedSumGadget(Wire[] seceretInputs, Wire sum, Wire witnessedSum, String... desc) {
		super(desc);
		this.secretInputs = seceretInputs;
		this.sum = sum;
		this.witnessedSum = witnessedSum;
		buildCircuit();
	}
	
	private void buildCircuit() {
		//sumOutput = generator.getZeroWire();
		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				BigInteger summation = new BigInteger("0");
				for (int i = 0; i < secretInputs.length; i ++){
					summation  = summation.add(evaluator.getWireValue(secretInputs[i]));
				}
				evaluator.setWireValue(sum, summation);
			}
		});
		generator.addEqualityAssertion(sum, witnessedSum, "Two sums are same");
	}
	

	@Override
	public Wire[] getOutputWires() {
		Wire[] outWires = new Wire[] {sum};
		return outWires;
	}
}
