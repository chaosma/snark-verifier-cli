use snark_verifier_sdk::Snark;
use snark_verifier::verifier::{self, SnarkVerifier};
use snark_verifier::pcs::kzg::{Gwc19, KzgAs, LimbsEncoding};
use halo2_base::utils::fs::gen_srs;
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::transcript::{Blake2bRead, TranscriptReadBuffer};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
// use snark_verifier::loader::evm::EvmLoader;

const LIMBS: usize = 3;
const BITS: usize = 88;
type As = KzgAs<Bn256, Gwc19>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;

pub fn verify(snark: &Snark) {
    let protocol = &snark.protocol;
    let instances = &snark.instances;
    let params = gen_srs(protocol.domain.k as u32);
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();
    // choice 1
    // let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);
    //choice 2
    let mut transcript = Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice());
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    let res = PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();
    dbg!(res);
}
