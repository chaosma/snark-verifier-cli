use anyhow::{anyhow, Result};
use halo2_base::gates::builder::CircuitBuilderStage;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::utils::fs::gen_srs;
use snark_verifier::loader::native::NativeLoader;
use snark_verifier::pcs::kzg::{Bdfg21, KzgAs, LimbsEncoding};
use snark_verifier::verifier::{self, plonk::PlonkProof, SnarkVerifier};
use snark_verifier_sdk::halo2::{aggregation::AggregationCircuit, gen_snark_shplonk, read_snark};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{PoseidonTranscript, POSEIDON_SPEC},
    Snark, SHPLONK,
};
use std::fs;
use std::path::Path;

const LIMBS: usize = 3;
const BITS: usize = 88;
// type As = KzgAs<Bn256, Gwc19>;
type As = KzgAs<Bn256, Bdfg21>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;

pub fn verify(snark: &Snark) -> Result<()> {
    let protocol = &snark.protocol;
    let instances = &snark.instances;
    let params = gen_srs(protocol.domain.k as u32);
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();
    // dbg!(&vk);
    // let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);
    let mut transcript =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(snark.proof(), POSEIDON_SPEC.clone());
    let proof: PlonkProof<_, _, SHPLONK> =
        PlonkVerifier::read_proof(&vk, protocol, instances, &mut transcript).unwrap();
    // dbg!(&proof);
    PlonkVerifier::verify(&vk, protocol, instances, &proof)
        .map_err(|e| anyhow!("Verification Failed: {:?}", e))
}

fn read_snarks(path: impl AsRef<Path>) -> Result<Vec<Snark>> {
    fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(std::ffi::OsStr::to_str) == Some("snark"))
        .map(|path| read_snark(path).map_err(|e| anyhow!("Read Snark Failed: {:?}", e)))
        .collect()
}

pub fn aggregate(path: impl AsRef<Path>, _is_recursive: bool) -> Result<()> {
    // build aggregation circuit
    let snarks = read_snarks(path)?;
    assert!(!snarks.is_empty());
    let k = snarks
        .iter()
        .map(|snark| snark.protocol.domain.k)
        .max()
        .unwrap();
    let params = gen_srs(k as u32);

    let agg_circuit = AggregationCircuit::keygen::<SHPLONK>(&params, snarks.clone());
    let pk = gen_pk(
        &params,
        &agg_circuit,
        Some(Path::new("data/agg_circuit.pkey")),
    );
    let break_points = agg_circuit.break_points();
    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Prover,
        Some(break_points), // TODO: check meaning
        k - 1,              // TODO: check meaning
        &params,
        snarks,
    );
    gen_snark_shplonk(&params, &pk, agg_circuit, Some(Path::new("data/agg.snark")));
    Ok(())
}
