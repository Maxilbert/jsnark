package yuan.gadgets;

import java.util.Arrays;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.SHA256Gadget;
import util.Util;

public class RSAOAEPGadget extends Gadget{
	
	private final int RADIX_BITS = 4;
	private final int RADIX = (int) Math.pow(2, RADIX_BITS);

	private final int BIT_WIDTH = 64;
	private final int CHAR_WIDTH = BIT_WIDTH / RADIX_BITS;
	private final int ENC_BITS = 2048;

	private final int OAEP_BIT_WIDTH = 32;
	private final int RND_BITS = 256;
	private final int MSG_BITS = ENC_BITS - RND_BITS;
	
	private final int P_Q_LEN = ENC_BITS / BIT_WIDTH / 2;
	private final int B_D_N_LEN = ENC_BITS / BIT_WIDTH;
	private final int NRE_LEN = ENC_BITS / BIT_WIDTH + 2;
	

	private Wire eIn;
	private Wire[] nIn;
	private Wire[] nReIn;
	
	private Wire[] msg;		//
	private Wire[] rnd;		//256 bit = 8 integers

	
	private Wire tIn;
	private Wire[] pIn;
	private Wire[] qIn;
	private Wire[] bIn;
	private Wire[] dIn;

	private Wire[] outputs;
	
	public RSAOAEPGadget(Wire eIn, Wire[] nIn, Wire[] nReIn, Wire[] msg, Wire[] rnd, Wire tIn, Wire[] pIn, Wire[] qIn, Wire[] dIn) {
		//Public inputs
		this.eIn = eIn;
		this.nIn = nIn;
		this.nReIn = nReIn;
		//Private inputs
		this.tIn = tIn;
		this.pIn = pIn;
		this.qIn = qIn;
		this.dIn = dIn;
		this.msg = msg;
		this.rnd = rnd;
		//Medium variable - maskedMsgRnd
		this.bIn = new Wire[B_D_N_LEN];
		buildCircuit();
	}
	
	private void buildCircuit(){
		
		
		Wire[] inputWires = Util.concat(Util.concat(new Wire[]{eIn},nIn),nReIn);
		
		//OAEP circuit
		//Mask for msg
		SHA256Gadget[] g = new SHA256Gadget[7];
		g[0] = new SHA256Gadget(rnd, OAEP_BIT_WIDTH, 32, false, true);
		g[1] = new SHA256Gadget(g[0].getOutputWires(), OAEP_BIT_WIDTH, 32, false, true);
		g[2] = new SHA256Gadget(g[1].getOutputWires(), OAEP_BIT_WIDTH, 32, false, true);
		g[3] = new SHA256Gadget(g[2].getOutputWires(), OAEP_BIT_WIDTH, 32, false, true);
		g[4] = new SHA256Gadget(g[3].getOutputWires(), OAEP_BIT_WIDTH, 32, false, true);
		g[5] = new SHA256Gadget(g[4].getOutputWires(), OAEP_BIT_WIDTH, 32, false, true);
		g[6] = new SHA256Gadget(g[5].getOutputWires(), OAEP_BIT_WIDTH, 32, false, true);
		Wire[] maskedMsg = new Wire[56];
		for (int i = 0; i < 7; i++){
			for (int j = 0; j < 8; j++){
				maskedMsg[8*i+j] = g[i].getOutputWires()[j].xorBitwise(msg[8*i+j], OAEP_BIT_WIDTH);
			}
		}
		
		//Mask for rnd
		SHA256Gadget h = new SHA256Gadget(maskedMsg, OAEP_BIT_WIDTH, 224, false, true);
		Wire[] maskedMsgHash = h.getOutputWires();
		Wire[] maskedRnd = new Wire[8];
		for (int j = 0; j < 8; j++){
			maskedRnd[j] = rnd[j].xorBitwise(maskedMsgHash[j], OAEP_BIT_WIDTH);
		}
		
		//Merge maskedMsg and maskedRnd
		Wire[] maskedMsgRnd = Util.concat(maskedMsg, maskedRnd);
		for (int i = 0; i < B_D_N_LEN; i++){
			Wire[] a = maskedMsgRnd[2*i].getBitWires(OAEP_BIT_WIDTH).asArray();
			Wire[] b = maskedMsgRnd[2*i+1].getBitWires(OAEP_BIT_WIDTH).asArray();
			WireArray bIn_i = new WireArray(Util.concat(a, b));
			bIn[i] = bIn_i.packAsBits(BIT_WIDTH);
		}
		
		Wire[] proverWitnessWires = Util.concat(Util.concat(Util.concat(Util.concat(new Wire[]{tIn}, pIn), qIn), dIn), bIn);
		PinocchioGadget powerModGenerator = new PinocchioGadget(inputWires, proverWitnessWires, "exp-mod-64.2048.arith");
		outputs = powerModGenerator.getOutputWires();

	}
	
	
	@Override
	public Wire[] getOutputWires() {
		// TODO Auto-generated method stub
		return outputs;
	}

}
