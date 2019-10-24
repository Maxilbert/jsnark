package yuan.generators;


import java.math.BigInteger;
import java.util.Arrays;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.SHA256Gadget;
import util.Util;
import yuan.gadgets.PinocchioGadget;
import yuan.gadgets.RSAKeyPairingGadget;
import yuan.gadgets.RSAOAEPEncryptionGadget;
import yuan.util.RSAKeyComponents;
import yuan.util.RSAKeyGenerator;
import yuan.util.RSAOAEPAlgorithms;
import yuan.util.SHA256ForGeneratingToken;


public class AnonymousCertificateCircuitGenerator  extends CircuitGenerator {
	
	BigInteger p;
	BigInteger q;

	private final int PLAYER_NUM = 11;
	
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

	
	//Private inputs for proving the hold of a certificate
	private Wire[] cIn; //certificate
	
	//Public inputs for proving the hold of a certificate
	private Wire eCAIn;
	private Wire[] nCAIn;
	private Wire[] nReCAIn;

	//Output of proving the hold of a certificate
	//Input for prove key pairing
	private Wire[] nIn;
	
	//Private inputs for prove key paring
	private Wire eIn;
	private Wire[] nReIn;
	private Wire tIn;
	private Wire[] pIn;
	private Wire[] qIn;
	private Wire[] dIn;
	
	//Public contract address
	private Wire addrIn;
	
	//Public Output
	private Wire[] keyPairingOutputs;
	
	public AnonymousCertificateCircuitGenerator(BigInteger p, BigInteger q, String circuitName) {
		this(circuitName);
		// TODO Auto-generated constructor stub
		this.p = p;
		this.q = q;
	}
	
	public AnonymousCertificateCircuitGenerator(String circuitName) {
		super(circuitName);
		// TODO Auto-generated constructor stub
		this.p = new BigInteger("fe27650b5653746c1e3b5baa756511fcf4874c013d6a88f392f658645c2a6acfbc4e3e492e00d47ba1abe9c41730cf49eddfc001a1f3cbbbfb8e21e4c8e253e9f8335a965766004d267e511a490f93b6b0e1611f8862c76aa20e0ce380ada0a60bbc2baf5e1fd07f4eeb4927f77b9da82908187ca69841e30a24ac31ab40b3d1",16);
		this.q = new BigInteger("f89e579f27d48d7a4bd542a067e8d4d1192bb58873fcd455634dffd220901af04c766ee68f9020f45843d5455f3ec5e3135b2bab13832671530afdb036f522b2e815339001ea198af5cb74699244ef5f4978aae7f5851ffa77d1062c8cc6e6ad775083de9a08274513bb083cfe8c25c4790994a660ce6dd9a249cc6459548745",16);
	}

	@Override
	protected void buildCircuit() {
		
		//Public Inputs of Contract Address
		addrIn = this.createInputWire("addrIn");
		
		//Public Inputs for certificate
		eCAIn = this.createInputWire("eCAIn");
		nCAIn = this.createInputWireArray(B_D_N_LEN,"nCAIn");
		nReCAIn = this.createInputWireArray(NRE_LEN,"nReCAIn");
		
		//Private Inputs for certificate
		cIn = this.createProverWitnessWireArray(ENC_BITS / BIT_WIDTH, "Certificate");
		
		//Private Inputs for key pairing
		eIn = this.createProverWitnessWire("eIn");
		tIn = this.createProverWitnessWire("tIn");
		nReIn = this.createProverWitnessWireArray(NRE_LEN,"nReIn");
		dIn = this.createProverWitnessWireArray(B_D_N_LEN,"dIn");
		pIn = this.createProverWitnessWireArray(P_Q_LEN,"pIn");
		qIn = this.createProverWitnessWireArray(P_Q_LEN,"qIn");
		//Wire[] inputWires = Util.concat(Util.concat(new Wire[]{eIn},nIn),nReIn);
		
		PinocchioGadget powerModGenerator = new PinocchioGadget(Util.concat(Util.concat(new Wire[]{eCAIn}, nCAIn), nReCAIn), cIn, "rsa-enc.2048.arith");
		nIn = powerModGenerator.getOutputWires();
		//makeOutputArray(nIn, "Public Key");
		
		SHA256Gadget commitment = new SHA256Gadget(Util.concat(addrIn, nIn), 160, 660, false, true);
		
		RSAKeyPairingGadget rsaKeyPairingGadget = new RSAKeyPairingGadget(eIn, nIn, nReIn, tIn, pIn, qIn, dIn);
		keyPairingOutputs = rsaKeyPairingGadget.getOutputWires();
		
		this.addEqualityAssertion(keyPairingOutputs[0], BigInteger.ONE, "Keys has to be paired to prove the hold of certificate");
		makeOutputArray(commitment.getOutputWires(), "Token");
		//makeOutput(keyPairingOutputs[0], "Is there a certificate?");
	}

	
	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		
		BigInteger pCA = new BigInteger("fc904278ac2f9c62c2788f8969437f003f962e8de3c3680bf9174c2e49a7cdf0d5ec5214c179e5733ef0fe55f460ba8695d14bb1c309eaccbb1e98dd7964fc157b54eaa9f6a01ceea57bc44b9e4b7e1608b84e03158d838ac0d6fd0d14b256fc676b6eb1d6157d9c28f8c34feca06dbed102fd3080174bf14d695eaa49bd48db",16);
		BigInteger qCA = new BigInteger("fd83db33c1cd2c10822719cf233773778923211ea8237a4cadab20197bb1baec72a378947d8e28f5817e6c1ca306814e9ca25ffafd8053794357f202b9234b60a969b8769a0497a6e0ef6517b7da36a3661407288e67ed307a1b729b9f103410e7f53c7e3238713323418e6bf41ae6caf09a939d8f21f3f7e73e6a4e6c003bff",16);

		
		BigInteger[] pCAIn = new BigInteger[P_Q_LEN]; 
		BigInteger[] qCAIn = new BigInteger[P_Q_LEN];
		BigInteger[] dCAIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nCAIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nReCAIn = new BigInteger[NRE_LEN]; 
		BigInteger[] eCAIn = new BigInteger[1]; 
		BigInteger[] tCAIn = new BigInteger[1];		
		RSAKeyComponents rsaCA = RSAOAEPAlgorithms.generateRSAKeyComponents(pCA, qCA, pCAIn, qCAIn, dCAIn, nCAIn, nReCAIn, eCAIn, tCAIn);
	
		BigInteger[] pIn = new BigInteger[P_Q_LEN];
		BigInteger[] qIn = new BigInteger[P_Q_LEN];
		BigInteger[] dIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nIn = new BigInteger[B_D_N_LEN]; 
		BigInteger[] nReIn = new BigInteger[NRE_LEN]; 
		BigInteger[] eIn = new BigInteger[1]; 
		BigInteger[] tIn = new BigInteger[1];		
		RSAKeyComponents rsaPlayer = RSAOAEPAlgorithms.generateRSAKeyComponents(p, q, pIn, qIn, dIn, nIn, nReIn, eIn, tIn);
		
		BigInteger certificate = rsaPlayer.rsa.getN().modPow(rsaCA.rsa.getD(), rsaCA.rsa.getN());
		BigInteger[] cIn = RSAOAEPAlgorithms.bigIntegerTo32BigIntegers(certificate);
		//Public
		evaluator.setWireValue(this.eCAIn, eCAIn[0]);
		evaluator.setWireValue(this.nCAIn, nCAIn);
		evaluator.setWireValue(this.nReCAIn, nReCAIn);
		evaluator.setWireValue(this.cIn, cIn);
		//Private
		evaluator.setWireValue(this.eIn, eIn[0]);	
		evaluator.setWireValue(this.tIn, tIn[0]);
		evaluator.setWireValue(this.pIn, pIn);
		evaluator.setWireValue(this.qIn, qIn);	
		evaluator.setWireValue(this.dIn, dIn);
		evaluator.setWireValue(this.nReIn, nReIn);
		
		BigInteger addrIn = new BigInteger("3d7a1426ddbdbf8ddfa23ae5adf5cdc93d801ab1",16);
		evaluator.setWireValue(this.addrIn, addrIn);
		
		SHA256ForGeneratingToken token = null;
		try {
			token = new SHA256ForGeneratingToken(addrIn, nIn);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		int[] t = token.getHash();
		for(int i = 0; i < 8; i++){
			System.out.println(t[i] & 0xffffffffL);
		}
	}
	
	

//	private void printHexOutputs(){
//		System.out.println("Hex outputs:");
//		System.out.println("Key Pairing Hex outputs:");
//		System.out.println(this.getCircuitEvaluator().getWireValue(keyPairingOutputs[0]));
//		for (int i = 0; i < PLAYER_NUM; i++){
//			BigInteger[] rsaOutputs = this.getCircuitEvaluator().getWiresValues(this.rsaOutputs[i]);
//			System.out.println("Player " + i + "'s RSA-OAEP Hex outputs:");
//			for (int j = 0; j < rsaOutputs.length; j++){
//				System.out.println(rsaOutputs[j].toString(16));
//			}
//		}
//	}
	
	
	public static void main(String[] args) throws Exception {
		
		String[] p = {
				"fe27650b5653746c1e3b5baa756511fcf4874c013d6a88f392f658645c2a6acfbc4e3e492e00d47ba1abe9c41730cf49eddfc001a1f3cbbbfb8e21e4c8e253e9f8335a965766004d267e511a490f93b6b0e1611f8862c76aa20e0ce380ada0a60bbc2baf5e1fd07f4eeb4927f77b9da82908187ca69841e30a24ac31ab40b3d1",	
				"fbc30ebf1ad5601fe1edfdc24fe2b1963a57baea80e3c22ce09deb9228d421707739c6ac271f94ff3051c93b6e3e7345e71c6117dd0be39815be977641a99d8c70e443438a5b6105336ba48baeb5ab715bb74495dd09a76263cc218eecdbd54b471c5b00270e191ccad86344e34994a0604fd6fb86c76e21286e0727eda5132d",
				"faa045aa56c02a8c6974397288d5b1b71b3be629f8cfb3a8801d9de7d321c07532503d7649ccc363800ebe074125979b64f6bb6b06d3987de448171766f82f41281d4ce1dd5565b9ce316ad6b698d90f3f0793f5553f1f81171f461703f21fafe1ef8c3dee0122f8a721d371437c5bbb384f213087f5bfb107a1ce6a97717c7b",
				"f2f68aa533911ddde9ebb1897c6a7a12b9893d0b83b8c6236c913f1641d2d007eaecbd905f9e6a289a571ab85c3f161292de9d62a1318ef7666afea5748f22db5e5cb2abec545dd514126ca547ae25d8cd2dd38d58a5c6330b9f2220ee764e1e25e6fb3d55873ab9eebe3d4365e527c3aa9126e4c89d53ccec8e2ade4b5cde17",
				"f79752e4361c4313b579e0c3ca24c52e1768fe2f23094fbfb8e0fe6339a9e32a78c9a8628c5215f5a636ca73c1eb58259df4e49d3a44e3424d4b6f8cd76176285b9c83547c246c61b350f1b319762241be18b2303b4fc771a15a1f5d7e6ba0102cdc26484c6ecc5a64d2e3c7cebf16e1cb96bdf005638aefd2e230e455c1f541",
				"facec72eb544048d731185c00fc717321e9dc2b2ac7f8b0c36e8b2b52dc7f99f30d673f3ae8ae8a098c38bcad0c6a5323d020b6b3098b0ab66afdd5a468481116b7ed624fa28754f60dc81427d1eb64ebc4500501bd6a8091cd527b622726a41948a77401c46b2f32b9da424eab39d7778e41bed78c11c6f791ef29f2edc6343",
				"f5d613a94dc4cf8e709e3fc2d362c310966292d0a95836ea8f39f78689943884fd97f9a38a339d9eb9f11eae1179c6786de101cf2df11964eeb4ede7021276f9ce59f2472da59bd3f524fa4a4af0c36844a11043048c684d91c4eb82522b9d547d6f90c8d2d006cbf243f59a602612a04a7739c35d6bc54a6ea042e23dc8a673",
				"fda9d663c23b549397d4da0c505fa9eee111ca094df16a2e3259a20a143dbc194f578f3a9ca05d3ca8da04f0a0c317251c9c602b4dae7852104b89bd20e940f96b89ef3de24bc0da2febf839de97b83ec2e6ea76c7f970a52e3e96aee72945a2da968dc992a577778c04235aee7ae51eb50d602c8ce856e3557256da6fb4caeb",
				"ffd30fb71f5382021b4c5ef0920cbbaf9c8eba1e8b9f466c781ee0f481bb4f7cfce67cd74aa7fc8f825c170a1df95dc01e3ebaf3b124d41f988f537a43fd6f19f32929638532a8fcd31069c5c6fa96c67ca52eabd259b6b146647e5b5e138accb1272994fa28588686843d85df162c32a4c41b7410a8d6cd6ce2cf70ad81532b",
				"fd0ecf31407b852d1f020a962d9bb16f0ae6e1be45779542dd9001b5b9a40c9a11be724144dc3b475def308c7e73d21ae3f6f1fa4f16ae838042e87ae2942cbdf1fae0af8da790a8b22db22e8479a9b1b6964895516c81fb72c7cced6c291bd1d46a6217688cf99a12d29ece848730d77ddc6446b2ad4c5fbb3c41c447d89c53",
				"f4e9f4fd6f95fff60e0024ec93bed0dd9dc62775fb1463b28ddd4b7a8180ad3b1f3f92a711c76113e78acb89eb0ea78a90e41c35f1ac1b95981598ff98f9ed5bdb8d4ebc3bfe88872945de9adfd5385c40f02554a4e749f8d685bca07e7eec019e44058ce70027b37059ded1a9fce791f47c5ce0f8ad4ea88472e3cb666efdbd"
			};
		String[] q = {
				"f89e579f27d48d7a4bd542a067e8d4d1192bb58873fcd455634dffd220901af04c766ee68f9020f45843d5455f3ec5e3135b2bab13832671530afdb036f522b2e815339001ea198af5cb74699244ef5f4978aae7f5851ffa77d1062c8cc6e6ad775083de9a08274513bb083cfe8c25c4790994a660ce6dd9a249cc6459548745",
				"f4dcd7f3849edda2844f474335c427ed1160266e89aa4d4c6a4167e139f4ae5d9a54ec2a9310d753a977e79aa496c3f2363c76819e7d4bc2f351226649f80423bad8e17ec32fdbf85d277a13e219df055f2fb312e141cb0f31d31c5c561ec4f8b49309a0798dd20203bbb22e3ed99777d6ed259fda4648ea02a2af11a5416d61",
				"f71569d034d69cd24ae072cbaecbe070a35301ccd61206ff921105410c8ae820673221c16a91277b817d2ac93b9b99420099b49665d012f1e9a3e3d94af366bcfdb855ebaff58743c5f5d1a6a3aac8a6b420050d85ab668c46baea37907fa7367a78fc3c9f6755d72bb1caf9016c40d20d5fd315958073905506f14e8c538787",
				"fdf58ea199542e6ee7b670148d2733d06925d53cdfe56c6a939d8f75c868438d749e0f45255c2d950c99905b34e44d1dcc123706bab7927735e2a8f881666ec95f43088d5f4abcfb656bc8681871c48b106d8c3ae4b7751d367e4ddc5de529f5a74c6f8b13dd534e9ce2f3c133a0924308ee1c5acdc07e8039e3a652c4c9d01b",
				"fc9ea6590d11d81d3e1c85a621b4bb62512e793e6bf26c5d622d11256aebaeca88a2af0bc021e9e6649ad8afd6af961ac503e4aa7348fd2f2fd0f4ba7b1d2ec2fdb61604764434a6ec4fee85950fb5c25cc839ba4ee3badd844e4b47bda3aae369806b3c72ba7f3e6248eac45a3cd02267a76206d9b0078f7d8d8b9057b6360b",
				"fdd351883367265437595d259d3fc452109405d4ccd6f0e1248042fe9e251b909c552674f91401af05227d1b57cb7c8101e59621bf13edc1f83a083f22211919345077ef757c29560ba1a6380189daf307803b76bb090cc52689a4bdad43604eada1bb06ab0c45c027f63160ee1a8a437d2423a44e914f5d4e76d2612ddd63f9",
				"fa2f5fd1bd1e6215e191f90f40f3767ba891e13286516892020240fd6c213a3e83fd4216691a241fa45f593c097f2b94b2905de35e15a042f89606c5f8348eaa9e9cbfc65a57eea817b9f49111e607e50d9efbc8d199a006351bb00746b01dfd701118cb7c1a99a217b54d8c089c1d6b78b837545c33a391c272a79be91d30f1",
				"f9a40d42e77aa15fbcdaf96bb46cbce1bfac41bc5a2bdfb152cae8dc8b8330a7abe24527534376819021710c70dadcfa8ae1ff30ae75b733f2d66250faea5831551c806e0a28a1e003508a5dc42b0eb8c62b6fa5d2728ca612fb0cd2083aadfa2ee1895d7b9d5b48255089d98679997e85324b5d0a9b5de62e6d8189aa4e96ab",
				"f530e19fcb71dd41c34298b63b307aa402444be2e377e5295f3565f4c8420c37d4c7a7a131fd1eaa7d401e364d12be706082a469edef099990dd07d92d0786bbca494f99007946eb05c3c113fd8855c288a89bb0da6d97c683d305087bf60b1545a88b96828bb9c9743dd086bea88c3f07e75f40eece0a24c48e6bc1af755949",
				"f5c872c2440bafe967aa41efaa04e9a125dd45c01df08e9b01c0e4957b12a22d5adca38bad06210d7535399e25a6b649184a11fd053d983bcabc71543e8a9e3b69f1be812bf95359f4720d207251b641bbb2faea2e9b1200563aa786b7788bfa08cc44707a8c01ec87b90139c4f88b8e37ffaeda6d70ee0b58020e4ac3fa9b83",
				"fbb6cbfd9a271f01009232ebb784510146703420ef83005477847f5dd3e84bdf906cc7ee2dc524351150e6eeb206c74f6e3d411a3c56897af921957a313f2425268413b3c20c97f9466e2da01f34b7a7394815fcd9cd145aa2c8fd820c5e3ae9a33a33a9024a531e2c236e6c67ab96df6069ca9d5804c4229f97b68bc77c9e45"
		};
		
		for (int i = 0; i < 11; i++) {
			AnonymousCertificateCircuitGenerator generator = new AnonymousCertificateCircuitGenerator(new BigInteger(p[i],16), new BigInteger(q[i],16), "player-" + i + "-anonymous-certificate-rsa-2048");			
			final boolean isCircuitGeneratorOnly = true;
			if (isCircuitGeneratorOnly) {
				generator.generateCircuit();
				generator.evalCircuit();
				//generator.printHexOutputs();
				generator.prepFiles();
			} else {
				generator.runLibsnarkGenerator();
				generator.runLibsnarkProver();
				generator.runLibsnarkVerifier(); // parameter 2 can go through generator and prover
			}
		}
	}
	
	
}
