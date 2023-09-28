use super::super::bls::Signature;
use super::Bls12G2;
use ark_ec::CurveGroup;
use serde::Serialize;
use tinytemplate::TinyTemplate;

#[derive(Serialize)]
struct AggregateSignature {
    p: Bls12G2,
}

static ASIG_TEMPLATE: &str = "
    function build_aggregate_signature() public pure returns (Bls12G2 memory) \\{
        return Bls12G2(
            Bls12Fp2(
                Bls12Fp(
					{p.x.c0.a}, {p.x.c0.b}
                ),
                Bls12Fp(
					{p.x.c1.a}, {p.x.c1.b}
                )
            ),
            Bls12Fp2(
                Bls12Fp(
					{p.y.c0.a}, {p.y.c0.b}
                ),
                Bls12Fp(
					{p.y.c1.a}, {p.y.c1.b}
                )
            )
        );
    }
";

pub fn print_asig(asig: Signature) {
    let mut tt = TinyTemplate::new();
    tt.add_template("asig", ASIG_TEMPLATE).unwrap();

    let sig = asig.as_ref().into_affine();

    let context = AggregateSignature {
        p: Bls12G2::from(sig),
    };

    let rendered = tt.render("asig", &context).unwrap();
    println!("{}", rendered);
}
