use nsm::{ByteBuf, Nsm};

fn main() {
    let mut nsm = Nsm::new().unwrap();
    let user_data = ByteBuf::from(vec![0, 1, 2]);
    let nonce = ByteBuf::from(vec![3, 4, 5]);
    let pub_key = ByteBuf::from(vec![6, 7, 8]);
    let doc = nsm.attest(Some(user_data.clone()), Some(nonce.clone()), Some(pub_key.clone())).unwrap();
    println!("#module_id: {}", doc.module_id);
    println!("#timestamp: {}", doc.timestamp);
    println!("digest: {}", doc.digest);
    assert_eq!(doc.digest, "SHA384");
    for (idx, val) in doc.pcrs.iter() {
        println!("# pcr{} = {:?}", idx, val);
    }
    println!("#certificate: {}", pkix::pem::der_to_pem(&doc.certificate, pkix::pem::PEM_CERTIFICATE));
    println!("#cabundle: {:?}", doc.cabundle.iter().map(|cert| pkix::pem::der_to_pem(cert, pkix::pem::PEM_CERTIFICATE)).collect::<Vec::<String>>());
    println!("public_key: {:?}", pkix::pem::der_to_pem(doc.public_key.as_ref().unwrap(), pkix::pem::PEM_CERTIFICATE));
    assert_eq!(doc.public_key.unwrap(), pub_key);
    println!("user_data: {:?}", doc.user_data);
    assert_eq!(doc.user_data.unwrap(), user_data);
    println!("nonce: {:?}", doc.nonce);
    assert_eq!(doc.nonce.unwrap(), nonce);

    for idx in 0..32 {
        let pcr = nsm.describe_pcr(idx).unwrap();
        println!("# pcr{} = {:?}", idx, pcr);
        assert_eq!(pcr.locked, idx <= 15);
    }

    let pcr16 = nsm.extend_pcr(16, vec![41, 41, 41]);
    println!("pcr16 = {:?}", pcr16);
    let pcr16 = nsm.extend_pcr(16, vec![42, 42, 42]);
    println!("pcr16 = {:?}", pcr16);
    println!("pcr16 = {:?}", nsm.describe_pcr(16));
    assert_eq!(nsm.describe_pcr(16).unwrap().locked, false);

    nsm.lock_pcr(16).unwrap();
    println!("pcr16 = {:?}", nsm.describe_pcr(10));
    assert_eq!(nsm.describe_pcr(16).unwrap().locked, true);

    nsm.lock_pcrs(18).unwrap();
    for pcr in 0..=18 {
        println!("#pcr{} = {:?}", pcr, nsm.describe_pcr(pcr));
        assert_eq!(nsm.describe_pcr(pcr).map(|val| val.locked), Ok(pcr < 18));
    }
}
