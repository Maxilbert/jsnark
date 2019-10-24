package yuan.gadgets;

import java.util.Arrays;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.SHA256Gadget;
import util.Util;

public class RSAKeyPairingGadget extends Gadget{
	
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
	
	private Wire tIn;
	private Wire[] pIn;
	private Wire[] qIn;
	private Wire[] dIn;

	private Wire[] outputs;
	
	public RSAKeyPairingGadget(Wire eIn, Wire[] nIn, Wire[] nReIn, Wire tIn, Wire[] pIn, Wire[] qIn, Wire[] dIn) {
		//Public inputs
		this.eIn = eIn;
		this.nIn = nIn;
		this.nReIn = nReIn;
		//Private inputs
		this.tIn = tIn;
		this.pIn = pIn;
		this.qIn = qIn;
		this.dIn = dIn;
		buildCircuit();
	}
	
	private void buildCircuit(){
		Wire[] inputWires = Util.concat(Util.concat(new Wire[]{eIn},nIn),nReIn);
		Wire[] proverWitnessWires = Util.concat(Util.concat(Util.concat(new Wire[]{tIn}, pIn), qIn), dIn);
		PinocchioGadget rsaKeyPairingGenerator = new PinocchioGadget(inputWires, proverWitnessWires, "rsa-key-pairing.2048.arith");
		outputs = rsaKeyPairingGenerator.getOutputWires();

	}
	
	
	@Override
	public Wire[] getOutputWires() {
		// TODO Auto-generated method stub
		return outputs;
	}

}
