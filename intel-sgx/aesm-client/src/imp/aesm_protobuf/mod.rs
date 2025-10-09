use imp::AesmClient;
pub use error::{Error, Result};
use protobuf::Message;
use std::io::{Read, Write};
use std::mem::size_of;
use byteorder::{LittleEndian, NativeEndian, ReadBytesExt, WriteBytesExt};
use request::{GetQuoteRequest, InitQuoteRequest, GetSupportedAttKeyIDNumRequest, GetSupportedAttKeyIDsRequest, InitQuoteExRequest, GetQuoteSizeExRequest, GetQuoteExRequest};
use {
    quote_buffer_size, AesmRequest, FromResponse, QuoteInfo, QuoteResult, QuoteType
};
// FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
#[cfg(not(target_env = "sgx"))]
use std::time::Duration;


/// This timeout is an argument in AESM request protobufs.
///
/// This value should be used for operations that can be completed locally, i.e.
/// without network interaction. Only the `try_connect()` operation falls into this
/// category.
#[allow(unused)]
pub(super) const LOCAL_AESM_TIMEOUT_US: u32 = 1_000_000;
/// This timeout is an argument in AESM request protobufs.
///
/// This value should be used for operations that might need interaction with
/// remote servers. All AESM requests fall into this category, because they either
/// always require interaction with a remote server or can trigger an initialization
/// step that involves communication with a remote server.
pub(super) const REMOTE_AESM_TIMEOUT_US: u32 = 30_000_000;

impl AesmClient {
    pub fn try_connect(&self) -> Result<()> {
        self.open_socket().map(|_| ())
    }

    pub(super) fn transact<T: AesmRequest>(&self, req: T) -> Result<T::Response> {
        let mut sock = self.open_socket()?;

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        let _ = sock.set_read_timeout(req.get_timeout().map(|t| Duration::from_micros(t as _)))?;

        // impl Write appends to the vector. Reserve space to fill in the
        // length after serializing.
        let mut req_bytes = vec![0u8; size_of::<u32>()];
        req.into()
            .write_to_writer(&mut req_bytes)
            .expect("Failed to serialize protobuf");
        let req_len = (req_bytes.len() - size_of::<u32>()) as u32;
        (&mut req_bytes[0..size_of::<u32>()]).write_u32::<NativeEndian>(req_len)?;
        sock.write_all(&req_bytes)?;

        let res_len = sock.read_u32::<NativeEndian>()?;
        let mut res_bytes = vec![0; res_len as usize];
        sock.read_exact(&mut res_bytes)?;

        let res = T::Response::from_response(Message::parse_from_bytes(&res_bytes))?;
        Ok(res)
    }

    pub fn init_quote(&self) -> Result<QuoteInfo> {
        let mut req = InitQuoteRequest::new();
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);
        let mut res = self.transact(req)?;

        let (target_info, gid) = (res.take_targetInfo(), res.take_gid());

        Ok(QuoteInfo { target_info, pub_key_id: gid })
    }

    pub fn get_quote(
        &self,
        report: Vec<u8>,
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
        quote_type: QuoteType,
        nonce: Vec<u8>,
    ) -> Result<QuoteResult> {
        let mut req = GetQuoteRequest::new();
        req.set_report(report);
        req.set_quote_type(quote_type.into());
        req.set_spid(spid);
        req.set_nonce(nonce);
        req.set_buf_size(quote_buffer_size(&sig_rl));
        if sig_rl.len() != 0 {
            req.set_sig_rl(sig_rl);
        }
        req.set_qe_report(true);

        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        let mut res = self.transact(req)?;

        let (mut quote, qe_report) = (res.take_quote(), res.take_qe_report());

        // AESM allocates a buffer of the size we supplied and returns the whole
        // thing to us, regardless of how much space QE needed. Trim the excess.
        // The signature length is a little endian word at offset 432 in the quote
        // structure. See "QUOTE Structure" in the IAS API Spec.
        let sig_len = (&quote[432..436]).read_u32::<LittleEndian>().unwrap();
        let new_len = 436 + sig_len as usize;
        if quote.len() < new_len {
            // Quote is already too short, should not happen.
            // Probably we are interpreting the quote structure incorrectly.
            return Err(Error::InvalidQuoteSize);
        }
        quote.truncate(new_len);

        Ok(QuoteResult::new(quote, qe_report))
    }

    // Similar functionality to sgx_get_supported_att_key_ids in page 177 at https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Developer_Reference_Linux_2.9.1_Open_Source.pdf
    pub fn get_supported_att_key_ids(&self) -> Result<Vec<Vec<u8>>> {
        // expected key id length - size of C structure - sgx_att_key_id_ext_t
        const SGX_KEY_ID_SIZE : u32 = 256;

        #[allow(unused_mut)]
        let mut req = GetSupportedAttKeyIDNumRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        let res = self.transact(req)?;
        let num_key_ids : u32 = res.att_key_id_num();

        let mut req = GetSupportedAttKeyIDsRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        // sgx defined protobuf returns an opaque byte array with size we give it. Byte array MUST have expected size of structure size*num.
        let expected_buffer_size : u32 = num_key_ids * SGX_KEY_ID_SIZE;
        req.set_buf_size(expected_buffer_size);

        let mut res = self.transact(req)?;

        let key_ids_blob = res.take_att_key_ids();
        if key_ids_blob.len() as u32 != expected_buffer_size {
            return Err(Error::aesm_bad_response("wrong buffer size returned by aesm service"));
        }

        let key_ids = key_ids_blob.chunks_exact(SGX_KEY_ID_SIZE as usize).map(Vec::from).collect();
        
        Ok(key_ids)
    }
    
    // Similar functionality to sgx_init_quote_ex in page 165 at https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Developer_Reference_Linux_2.9.1_Open_Source.pdf 
    pub fn init_quote_ex(&self, att_key_id: Vec<u8>) -> Result<QuoteInfo> {
        let mut req = InitQuoteExRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        req.set_att_key_id(att_key_id.clone());
        req.set_b_pub_key_id(false);
        
        let res = self.transact(req)?;
        let buf_size = res.pub_key_id_size();

        let mut req = InitQuoteExRequest::new();
        
        req.set_att_key_id(att_key_id);
        req.set_b_pub_key_id(true);
        req.set_buf_size(buf_size);
        let mut res = self.transact(req)?;

        Ok(QuoteInfo { target_info : res.take_target_info(),
                         pub_key_id : res.take_pub_key_id(),
        })
    }

    // Similar functionality to sgx_get_quote_ex in page 173 at https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Developer_Reference_Linux_2.9.1_Open_Source.pdf
    pub fn get_quote_ex(
        &self,
        att_key_id: Vec<u8>,
        report: Vec<u8>,
        target_info: Vec<u8>,
        nonce: Vec<u8>
    ) -> Result<QuoteResult> {
        // First request - get the expected quote size for given key id.
        let mut req = GetQuoteSizeExRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);
        req.set_att_key_id(att_key_id.clone());

        let res = self.transact(req)?;

        if !res.has_quote_size() {
            return Err(Error::AesmBadResponse("Size is not provided by AESM Service in GetQuoteSizeEx reply".to_string()));
        }
        let buf_size = res.quote_size();

        // second request - get the actual quote
        let mut req = GetQuoteExRequest::new();
        
        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        req.set_att_key_id(att_key_id);
        req.set_buf_size(buf_size);

        // qe_report_info is of type sgx_ql_qe_report_info_t
        // - nonce: sgx_quote_nonce_t
        // - app_enclave_target_info: sgx_target_info_t
        // - qe_report: sgx_report_t

        let mut qe_report_info : Vec<u8> = Vec::new();
        qe_report_info.extend(nonce);
        qe_report_info.extend(target_info);
        let report_start = qe_report_info.len();
        qe_report_info.resize(report_start + sgx_isa::Report::UNPADDED_SIZE, 0);
        req.set_qe_report_info(qe_report_info);

        req.set_report(report);

        let mut res = self.transact(req)?;

        let (quote, qe_report_info) = (res.take_quote(), res.take_qe_report_info());

        Ok(QuoteResult::new(quote, &qe_report_info[report_start..]))
    }
}
