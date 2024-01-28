use snark_verifier_sdk::{Snark, SHPLONK, halo2::{POSEIDON_SPEC, PoseidonTranscript}};
use snark_verifier::verifier::{self, plonk::PlonkProof, SnarkVerifier};
use snark_verifier::pcs::kzg::{Bdfg21, KzgAs, LimbsEncoding};
use snark_verifier::loader::native::NativeLoader;
use halo2_base::utils::fs::gen_srs;
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;

const LIMBS: usize = 3;
const BITS: usize = 88;
// type As = KzgAs<Bn256, Gwc19>;
type As = KzgAs<Bn256, Bdfg21>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;

pub fn verify(snark: &Snark) {
    let protocol = &snark.protocol;
    let instances = &snark.instances;
    let params = gen_srs(protocol.domain.k as u32);
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();
    // dbg!(&vk);
    // let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);
    let mut transcript = PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(snark.proof(), POSEIDON_SPEC.clone());
    let proof: PlonkProof<_, _, SHPLONK> = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    // dbg!(&proof);
    let res = PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();
    dbg!(res);
}
