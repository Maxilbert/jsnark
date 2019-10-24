package yuan.generators;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Random;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.SHA256Gadget;
import examples.generators.AugmentedAuctionCircuitGenerator;
import util.Util;
import yuan.util.RSAOAEPAlgorithms;


public class OAEPGenerator extends CircuitGenerator {

	final int  PADDING_LENGTH = 256;
	final int BIT_WIDTH = 32;
	
	Wire[] msg;		//
	Wire[] rnd;		//256 bit = 8 integers
	//Wire[] padding;
	
	Wire[] outputs; //2048 bit = 64 integers
	
	public OAEPGenerator(String circuitName) throws Exception {
		super(circuitName);
		// TODO Auto-generated constructor stub

		//if (outputs.length != 64 || rnd.length != 8){
		//	throw new Exception("Bad outputs or rnd length");
		//}
	}

	@Override
	protected void buildCircuit() {
		// TODO Auto-generated method stub
		msg = this.createProverWitnessWireArray(56);
		rnd = this.createProverWitnessWireArray(8);
		
		SHA256Gadget[] g = new SHA256Gadget[7];
		g[0] = new SHA256Gadget(rnd, 32, 32, false, true);
		g[1] = new SHA256Gadget(g[0].getOutputWires(), BIT_WIDTH, 32, false, true);
		g[2] = new SHA256Gadget(g[1].getOutputWires(), BIT_WIDTH, 32, false, true);
		g[3] = new SHA256Gadget(g[2].getOutputWires(), BIT_WIDTH, 32, false, true);
		g[4] = new SHA256Gadget(g[3].getOutputWires(), BIT_WIDTH, 32, false, true);
		g[5] = new SHA256Gadget(g[4].getOutputWires(), BIT_WIDTH, 32, false, true);
		g[6] = new SHA256Gadget(g[5].getOutputWires(), BIT_WIDTH, 32, false, true);
		
		Wire[] maskedMsg = new Wire[56];
		for (int i = 0; i < 7; i++){
			for (int j = 0; j < 8; j++){
				maskedMsg[8*i+j] = g[i].getOutputWires()[j].xorBitwise(msg[8*i+j], BIT_WIDTH);
			}
		}
		
		SHA256Gadget h = new SHA256Gadget(maskedMsg, 32, 224, false, true);
		Wire[] maskedMsgHash = h.getOutputWires();
		Wire[] maskedRnd = new Wire[8];
		for (int j = 0; j < 8; j++){
			maskedRnd[j] = rnd[j].xorBitwise(maskedMsgHash[j], 32);
		}
		
		outputs = Util.concat(maskedMsg, maskedRnd);
		
		makeOutputArray(outputs);
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		// TODO Auto-generated method stub
		String message = "Ethereum plus snarks is a really cool idea. People can leverage them to achieve fantastic products. Amazing... Story is just started.";
		int[] msg = RSAOAEPAlgorithms.stringTo56Integers(message);
		int[] rnd = new int[8];
		for(int i = 0; i < 56; i++){
			evaluator.setWireValue(this.msg[i], msg[i]);
		}
		Random rand;
		for(int i = 0; i < 8; i++){
			rand = new Random(i);
			rnd[i] = rand.nextInt();
			evaluator.setWireValue(this.rnd[i], rnd[i] );
		}
		
		int[] maskedMsgRnd;
		try {
			maskedMsgRnd = RSAOAEPAlgorithms.addMask(msg, rnd);
			for (int i = 0; i < 64; i++){
				System.out.println(maskedMsgRnd[i] & 0xffffffffL);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void main(String[] args) throws Exception {
		OAEPGenerator generator = new OAEPGenerator("oaep");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnarkGenerator();
		generator.runLibsnarkProver();
		generator.runLibsnarkVerifier();
	}

}
