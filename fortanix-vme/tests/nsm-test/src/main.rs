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
}
