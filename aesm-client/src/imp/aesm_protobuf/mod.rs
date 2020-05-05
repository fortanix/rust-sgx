use imp::AesmClient;
pub use error::{AesmError, Error, Result};
use protobuf::Message;
use std::io::{Read, Write};
use std::mem::size_of;
use byteorder::{LittleEndian, NativeEndian, ReadBytesExt, WriteBytesExt};
use {
    AesmRequest, FromResponse, QuoteInfo, QuoteInfoEx, QuoteResult, QuoteType, 
    Request_GetQuoteRequest, Request_InitQuoteRequest, Request_GetSupportedAttKeyIDNumRequest, Request_GetSupportedAttKeyIDsRequest, Request_InitQuoteExRequest, Request_GetQuoteSizeExRequest, Request_GetQuoteExRequest
};
// FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
#[cfg(not(target_env = "sgx"))]
use imp::{LOCAL_AESM_TIMEOUT_US, REMOTE_AESM_TIMEOUT_US};
// FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
#[cfg(not(target_env = "sgx"))]
use std::time::Duration;

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

        let res = T::Response::from_response(protobuf::parse_from_bytes(&res_bytes))?;
        Ok(res)
    }

    /// Obtain target info from QE.
    pub fn init_quote(&self) -> Result<QuoteInfo> {
        #[allow(unused_mut)]
        let mut req = Request_InitQuoteRequest::new();
        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(LOCAL_AESM_TIMEOUT_US);
        let mut res = self.transact(req)?;

        let (target_info, mut gid) = (res.take_targetInfo(), res.take_gid());

        // AESM gives it to us little-endian, we want big-endian for writing into IAS URL with to_hex()
        gid.reverse();

        Ok(QuoteInfo { target_info, gid })
    }

    /// Obtain remote attestation quote from QE.
    pub fn get_quote(
        &self,
        session: &QuoteInfo,
        report: Vec<u8>,
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
        quote_type: QuoteType,
        nonce: Vec<u8>,
    ) -> Result<QuoteResult> {
        let mut req = Request_GetQuoteRequest::new();
        req.set_report(report);
        req.set_quote_type(quote_type.into());
        req.set_spid(spid);
        req.set_nonce(nonce);
        req.set_buf_size(session.quote_buffer_size(&sig_rl));
        if sig_rl.len() != 0 {
            req.set_sig_rl(sig_rl);
        }
        req.set_qe_report(true);

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
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
    
    ///
    /// Returns all keys supported by AESM service. 
    /// Similar functionality to sgx_get_supported_att_key_ids in page 177 at https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Developer_Reference_Linux_2.9.1_Open_Source.pdf
    ///
    /// returns structure containing set of keys that can serve as input for init_quote_ex/get_quote_size_ex operations. (see aesm-client/tests/live_quote.rs for examples how to extract a specific key)
    ///
    pub fn get_supported_att_key_ids(&self) -> Result<Vec<Vec<u8>>> {

        // expected key id length - size of C structure - sgx_att_key_id_ext_t
        const SGX_KEY_ID_SIZE : u32 = 256;

        #[allow(unused_mut)]
        let mut req = Request_GetSupportedAttKeyIDNumRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        let res = self.transact(req)?;
        let num_key_ids : u32 = res.get_att_key_id_num();

        let mut req = Request_GetSupportedAttKeyIDsRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        // sgx defined protobuf returns an opaque byte array with size we give it. Byte array MUST have expected size of structure size*num.
        let expected_buffer_size : u32 = num_key_ids * SGX_KEY_ID_SIZE;
        req.set_buf_size(expected_buffer_size);

        // fetch requested data
        let mut res = self.transact(req)?;

        // Interpret the byte array as defined in C header at linux-sgx/common/inc/sgx_quote.h, this is converted to sgx_quote.rs via bindgen.
        let key_ids_blob = res.take_att_key_ids();

        if key_ids_blob.len() as u32 != expected_buffer_size {
            return Err(Error::aesm_bad_response("wrong buffer size returned by aesm service"));
        }

        let mut key_ids : Vec<Vec<u8>> = Vec::new();
        
        for i in key_ids_blob.chunks_exact(SGX_KEY_ID_SIZE as usize) {
            key_ids.push(i.to_vec());
        }
        
        Ok(key_ids)
    }
    
    ///
    /// Returns information needed by an intel SGX application to get a quote of one of its enclaves.
    /// Similar functionality to sgx_init_quote_ex in page 165 at https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Developer_Reference_Linux_2.9.1_Open_Source.pdf
    ///
    /// att_key_id - a byte array with hidden type 'sgx_att_key_id_ext_t' returned by AesmClient::select_att_key_id or AesmKeyIds::select_algorithm_id or similar.
    ///
    /// returns information to use for get_quote_ex
    ///
    pub fn init_quote_ex(&self, att_key_id: Vec<u8>) -> Result<QuoteInfoEx> {
        let mut req = Request_InitQuoteExRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        req.set_att_key_id(att_key_id.clone());
        req.set_b_pub_key_id(false);
        
        let res = self.transact(req)?;
        let buf_size = res.get_pub_key_id_size();

        let mut req = Request_InitQuoteExRequest::new();
        
        req.set_att_key_id(att_key_id);
        req.set_b_pub_key_id(true);
        req.set_buf_size(buf_size);
        let mut res = self.transact(req)?;

        Ok(QuoteInfoEx { target_info : res.take_target_info(),
                         pub_key_id : res.take_pub_key_id(),
        })
    }

    ///
    /// takes the application enclave REPORT and generates a QUOTE.
    /// Similar functionality to sgx_get_quote_ex in page 173 at https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Developer_Reference_Linux_2.9.1_Open_Source.pdf
    ///
    /// att_key_id - Selected attestation key ID returned by sgx_select_att_key_id (or one selected from output of get_supported_att_key_ids). 
    /// report     - Report of the enclave for that the quote is being calculated.
    /// quote_info - Data returned by init_quote_ex.
    /// nonce      - information required to generate a REPORT that can be verified by the application enclave.
    ///
    pub fn get_quote_ex(&self, att_key_id: Vec<u8>, report: Vec<u8>, quote_info : QuoteInfoEx, nonce: &[u8; 16]) -> Result<QuoteResult> {

        // First request - get the expected quote size for given key id.
        let mut req = Request_GetQuoteSizeExRequest::new();

        // FIXME: remove conditional compilation after resolving https://github.com/fortanix/rust-sgx/issues/31
        #[cfg(not(target_env = "sgx"))]
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);
        req.set_att_key_id(att_key_id.clone());

        let res = self.transact(req)?;

        if !res.has_quote_size() {
            return Err(Error::AesmBadResponse("Size is not provided by AESM Service in GetQuoteSizeEx reply".to_string()));
        }
        let buf_size = res.get_quote_size();

        // second request - get the actual quote
        let mut req = Request_GetQuoteExRequest::new();
        
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
        qe_report_info.extend(quote_info.target_info);
        qe_report_info.extend_from_slice(&report);
        req.set_qe_report_info(qe_report_info);

        req.set_report(report);

        let mut res = self.transact(req)?;

        let (quote, qe_report) = (res.take_quote(), res.take_qe_report_info());

        Ok(QuoteResult::new(quote, qe_report))
    }
}
