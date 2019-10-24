package yuan.generators;

import java.util.Arrays;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import util.Util;
import yuan.gadgets.PinocchioGadget;
import yuan.util.*;

public class MajorityCircuitGenerator extends CircuitGenerator{

	private String pathToCompiledCircuit;
	
	private final int MSG_WORD_NUM = 56;
	private final int PLAYER_NUM = 7;
	
	private Wire majCount;
	private Wire[][] data;
	
	private Wire[] outputs;
	
	public MajorityCircuitGenerator(String circuitName, String pathToCompiledCircuit) {
		super(circuitName);
		this.pathToCompiledCircuit = pathToCompiledCircuit;
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		majCount = this.createProverWitnessWire("Count of maj");
		
		Wire[] proverWitnessWires = new Wire[]{majCount};
		

		data = new Wire[PLAYER_NUM][MSG_WORD_NUM];
		for (int i = 0; i < PLAYER_NUM; i++) {
			for (int j = 0; j < MSG_WORD_NUM; j++) {
				data[i][j] = this.createProverWitnessWire("Player " + i +", word " + j);
			}
			proverWitnessWires = Util.concat(proverWitnessWires, data[i]);
		}
		PinocchioGadget majorityCircuitGenerator = new PinocchioGadget(null, proverWitnessWires, pathToCompiledCircuit);
		outputs = majorityCircuitGenerator.getOutputWires();
		
		
	

		makeOutput(outputs[0], "Is majority count matched?");
		makeOutputArray(Arrays.copyOfRange(outputs, 1, outputs.length), "majority data");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		// TODO Auto-generated method stub
		
		evaluator.setWireValue(majCount, 6);
		
		String message1 = "Ethereum plus snarks is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on...";
		
		String message2 = "Ethereum plus zkSnark is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on...";
		
		String message3 = "Ethereum plus zksnarks is a really cool idea. "
				+ "People can leverage them to achieve fantastic products. "
				+ "Amazing! Story is just started. Let's see what is going on...";
		
		int[] msg1 = RSAOAEPAlgorithms.stringTo56Integers(message1);
		System.out.println("Msg 1");
		for (int i = 0; i < msg1.length; i++){
			System.out.println(msg1[i]);
		}
		int[] msg2 = RSAOAEPAlgorithms.stringTo56Integers(message2);
		System.out.println("Msg 2");
		for (int i = 0; i < msg1.length; i++){
			System.out.println(msg2[i]);
		}
		int[] msg3 = RSAOAEPAlgorithms.stringTo56Integers(message3);
		System.out.println("Msg 3");
		for (int i = 0; i < msg1.length; i++){
			System.out.println(msg3[i]);
		}
		try {
			setValue(evaluator, data[0], msg3);
			setValue(evaluator, data[1], msg2);
			setValue(evaluator, data[2], msg1);
			setValue(evaluator, data[3], msg3);
			setValue(evaluator, data[4], msg2);
			setValue(evaluator, data[5], msg2);
			setValue(evaluator, data[6], msg2);
//			setValue(evaluator, data[7], msg3);
//			setValue(evaluator, data[8], msg2);
//			setValue(evaluator, data[9], msg3);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private void setValue(CircuitEvaluator e, Wire[] w, int[] v) throws Exception{
		if (w.length != v.length) 
			throw new Exception("w and v should have same length");
		for (int i = 0; i < w.length; i++){
			e.setWireValue(w[i], v[i]);
		}
	}
	
	public static void main(String[] args) throws Exception {
	
		MajorityCircuitGenerator generator = new MajorityCircuitGenerator("majority-among-7-players", "major.arith");
		
		final boolean isCircuitGeneratorOnly = true;
		if (isCircuitGeneratorOnly) {
			generator.generateCircuit();
			generator.evalCircuit();
			generator.prepFiles();
		} else {
			generator.runLibsnarkGenerator();
			generator.runLibsnarkProver();
			generator.runLibsnarkVerifier(); // parameter 2 can go through generator and prover
		}
	
	}
	
}
