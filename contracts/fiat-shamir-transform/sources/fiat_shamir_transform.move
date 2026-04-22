module ace::fiat_shamir_transform {
    use std::bcs;
    use ace::group;

    struct Transcript has copy, drop {
        recorded: vector<u8>,
    }

    public fun new_transcript(): Transcript {
        Transcript { recorded: vector[] }
    }

    public fun append_group_element(trx: &mut Transcript, element: &group::Element) {
        append_raw_bytes(trx, bcs::to_bytes(element))
    }

    public fun append_raw_bytes(trx: &mut Transcript, raw: vector<u8>) {
        trx.recorded.append(raw)
    }

    public fun hash_to_scalar(trx: &Transcript, scheme: u8): group::Scalar {
        group::hash_to_scalar(scheme, trx.recorded)
    }
}
