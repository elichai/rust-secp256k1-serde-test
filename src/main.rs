use core::fmt::Debug;
use secp256k1::{
    schnorrsig::{self, KeyPair},
    *,
};
use serde::{Deserialize, Serialize};
use std::iter::successors;
use std::{fs, str};

// NOTE: Current serializations in `serialized/` are from 0.20.1 in crates.io.

fn main() {
    let bytes_1_to_32: Vec<u8> = successors(Some(1), |n| Some(n + 1)).take(32).collect();
    let seckey = SecretKey::from_slice(&bytes_1_to_32).unwrap();
    let pubkey = PublicKey::from_secret_key(SECP256K1, &seckey);
    let keypair = KeyPair::from_seckey_slice(SECP256K1, &bytes_1_to_32).unwrap();
    let schnorr_pubkey = schnorrsig::PublicKey::from_keypair(SECP256K1, &keypair);
    let msg = Message::from_slice(&bytes_1_to_32).unwrap();
    let sig = SECP256K1.sign(&msg, &seckey);
    let schnorr_sig = SECP256K1.schnorrsig_sign_no_aux_rand(&msg, &keypair);
    let to_serialize = ToSerialize { seckey, pubkey, schnorr_pubkey, sig, schnorr_sig };


    // serialize_all(&to_serialize);
    verify_all(&to_serialize);
}

fn verify_all(t: &ToSerialize) {
    verify_from_file("serde_json", serde_json::to_vec, |s| serde_json::from_slice(s), t);
    verify_from_file("bincode", bincode::serialize, |s| bincode::deserialize(s), t);
    verify_from_file("cbor", serde_cbor::to_vec, |s| serde_cbor::from_slice(s), t);
    // crashes on 9.20.1
    verify_from_file("yaml", serde_yaml::to_vec, |s|serde_yaml::from_slice(s), t);
    verify_from_file("msgpack", rmp_serde::to_vec, |s| rmp_serde::from_slice(s), t);
    verify_from_file("toml", toml::to_vec, |s| toml::from_slice(s), t);
    verify_from_file("serde_json", serde_json::to_vec, |s| serde_json::from_slice(s), t);
    // crashes on 9.20.1
    verify_from_file("pickle_proto3_true", |t| serde_pickle::to_vec(t, true), |t| serde_pickle::from_slice(t), t);
    // crashes on 9.20.1
    verify_from_file("pickle_proto3_false", |t| serde_pickle::to_vec(t, false), |t| serde_pickle::from_slice(t), t);
    verify_from_file("flexbuffers", |t| flexbuffers::to_vec(*t), |t| flexbuffers::from_slice(t), t);
    // crashes on 9.20.1
    verify_from_file("json5", |t| json5::to_string(t).map(String::into_bytes), |t| json5::from_str(str::from_utf8(t).unwrap()), t);

    verify_from_file("ron", |t| ron::to_string(t).map(String::into_bytes), |t| ron::from_str(str::from_utf8(t).unwrap()), t);
    // crashes on 9.20.1
    verify_from_file(
        "bson",
        |t| {
            let mut bson = Vec::with_capacity(128);
            bson::to_document(t).map(|b| b.to_writer(&mut bson).unwrap()).map(|_| bson)
        },
        |mut t|bson::from_document(bson::Document::from_reader(&mut t)?),
        t,
    );
}

fn serialize_all(t: &ToSerialize) {
    serialize_to_file("serde_json", serde_json::to_vec, t);
    serialize_to_file("bincode", bincode::serialize, t);
    serialize_to_file("cbor", serde_cbor::to_vec, t);
    serialize_to_file("yaml", serde_yaml::to_vec, t);
    serialize_to_file("msgpack", rmp_serde::to_vec, t);
    serialize_to_file("toml", toml::to_vec, t);
    serialize_to_file("serde_json", serde_json::to_vec, t);
    serialize_to_file("pickle_proto3_true", |t| serde_pickle::to_vec(t, true), t);
    serialize_to_file("pickle_proto3_false", |t| serde_pickle::to_vec(t, false), t);
    serialize_to_file("flexbuffers", |t| flexbuffers::to_vec(*t), t);
    serialize_to_file("json5", |t| json5::to_string(t).map(String::into_bytes), t);
    serialize_to_file("ron", |t| ron::to_string(t).map(String::into_bytes), t);
    serialize_to_file(
        "bson",
        |t| {
            let mut bson = Vec::with_capacity(128);
            bson::to_document(t).map(|b| b.to_writer(&mut bson).unwrap()).map(|_| bson)
        },
        t,
    );
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
struct ToSerialize {
    seckey: SecretKey,
    pubkey: PublicKey,
    schnorr_pubkey: schnorrsig::PublicKey,
    sig: Signature,
    schnorr_sig: schnorrsig::Signature,
}

fn serialize_to_file<E, Ser>(name: &str, ser: Ser, to_serialize: &ToSerialize)
where
    E: Debug,
    Ser: FnOnce(&ToSerialize) -> Result<Vec<u8>, E>,
{
    let serialized = ser(to_serialize).expect(name);
    fs::write(format!("./serialized/{}", name), serialized).expect(name);
}

fn verify_from_file<E1, E2, Ser, Der>(name: &str, ser: Ser, der: Der, original: &ToSerialize)
where
    E1: Debug,
    E2: Debug,
    Ser: FnOnce(&ToSerialize) -> Result<Vec<u8>, E1>,
    Der: FnOnce(&[u8]) -> Result<ToSerialize, E2>,
{
    let serialized = fs::read(format!("./serialized/{}", name)).expect(name);

    let restored = der(&serialized).expect(name);
    assert_eq!(&restored, original);

    let reserialized = ser(original).expect(name);
    assert_eq!(serialized, reserialized);
}
