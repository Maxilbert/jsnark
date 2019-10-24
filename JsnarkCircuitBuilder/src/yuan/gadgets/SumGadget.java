package yuan.gadgets;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;

public class SumGadget extends Gadget{

	private Wire[] secretInputs;
	private Wire sum;
	
	private Wire average;
	private Wire num;
	private Wire r;
	
	public SumGadget(Wire[] seceretInputs, Wire sum, Wire num, String... desc) {
		super(desc);
		this.secretInputs = seceretInputs;
		this.sum = sum;
		this.num = num;
		buildCircuit();
	}
	
	private void buildCircuit() {
		
//		for (int i = 0; i < SecretInputs.length; i++) {
//			sum = sum.add(SecretInputs[i], "add " + i);
//		}
//		
		average = generator.createProverWitnessWire("average");
		r = generator.createProverWitnessWire("remainder");
		
		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				BigInteger aValue = evaluator.getWireValue(sum);
				BigInteger bValue = evaluator.getWireValue(num);
				BigInteger rValue = aValue.mod(bValue);
				evaluator.setWireValue(r, rValue);
				BigInteger qValue = aValue.divide(bValue);
				evaluator.setWireValue(average, qValue);
			}

		});
		
		generator.addEqualityAssertion(average.mul(num).add(r), sum);
	}
	

	@Override
	public Wire[] getOutputWires() {
		Wire[] outWires = new Wire[] {sum, average};
		return outWires;
	}

}
