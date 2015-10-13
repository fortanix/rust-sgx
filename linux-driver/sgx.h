// This file is part of OpenSGX, based on commit aa9466f1 with only minor
// modifications. See OpenSGX for copyright information.

#pragma once
#pragma pack(push, 1)

#define CPU_SVN                  (1)              //!< Default CPU SVN
#ifndef PAGE_SIZE
#define PAGE_SIZE                (4096)
#endif
#define EPC_SIZE                 (PAGE_SIZE)      // from 1.5
//#define NUM_EPC                (100)            // XXX. where?
#define NUM_EPC                  (1500)           // XXX. where?
#define ENCLAVE_SIZE             (16)             // XXX : Set temporarily
#define MEASUREMENT_SIZE         (256)
#define MIN_ALLOC                (2)

// For ALIGNMENT
#define EINITTOKEN_ALIGN_SIZE    (512)
#define PAGEINFO_ALIGN_SIZE      (32)
#define SECINFO_ALIGN_SIZE       (64)
#define KEYREQUEST_ALIGN_SIZE    (128)

// For RSA
// XXX. append "SGX_RSA_"
#define KEY_LENGTH               (384)
#define KEY_LENGTH_BITS          (3072)
#define DEVICE_KEY_LENGTH        (16)
#define DEVICE_KEY_LENGTH_BITS   (128)
#define SGX_RSA_EXPONENT         (3)
#define HASH_SIZE                (20)

/// EINITTOKEN MAC size
#define MAC_SIZE                 (16)
#define DSLIMIT                  (4294967295)     //!< 2^32-1 -> 2^32 => overflow
#define NO_OF_TCS_FLAGS          (64)
#define STACK_PAGE_FRAMES_PER_THREAD (250)
#define HEAP_PAGE_FRAMES         (100)              // Need to decide how many initial Heap pages are required

/// custom format
#define PRIfptr "0x%016"PRIxPTR

/// QEMU resource management for enclave
#define MAX_ENCLAVES 16

typedef uint8_t rsa_key_t[KEY_LENGTH];
typedef uint8_t rsa_sig_t[KEY_LENGTH];
typedef uint16_t oneDigit;                        //!< Get one digit.
typedef uint32_t twoDigits;                       //!< Get two digits.
// XXX : disable global variable
//uint64_t _tcs_app;

#define NUM_BITS (sizeof(char) * sizeof (oneDigit))
#define extractBitVal(no, pos)  ((no >> pos) & 0x01)
#define NO_OF_BITS(size_of_data_type, no_of_bits)  (size_of_data_type << no_of_bits)

//====--------------------------------------------------------------
/// SGX ENCLS related Structures
/// Expected from kernel.
/// Currently being emulated from User space.
//====--------------------------------------------------------------

// from 2.6.5.2
typedef enum {
    PT_SECS = 0x00,                     //!< Page is SECS
    PT_TCS  = 0x01,                     //!< Page is TCS
    PT_REG  = 0x02,                     //!< Page is a normal page
    PT_VA   = 0x03,                     //!< Page is a Version Array
    PT_TRIM = 0x04			//!< Page is in trimmed state
} page_type_t;

typedef enum {
    LAUNCH_KEY         = 0x00,          //!< Launch key
    PROVISION_KEY      = 0x01,          //!< Provisioning Key
    PROVISION_SEAL_KEY = 0x02,          //!< Provisioning Seal Key
    REPORT_KEY         = 0x03,          //!< Report Key
    SEAL_KEY           = 0x04,          //!< Report seal key
} keyname_type_t;

// from 5.1.1
typedef enum {
    ENCLS_ECREATE      = 0x00,
    ENCLS_EADD         = 0x01,
    ENCLS_EINIT        = 0x02,
    ENCLS_EREMOVE      = 0x03,
    ENCLS_EDBGRD       = 0x04,
    ENCLS_EDBGWR       = 0x05,
    ENCLS_EEXTEND      = 0x06,
    ENCLS_ELDB         = 0x07,
    ENCLS_ELDU         = 0x08,
    ENCLS_EBLOCK       = 0x09,
    ENCLS_EPA          = 0x0A,
    ENCLS_EWB          = 0x0B,
    ENCLS_ETRACK       = 0x0C,
    ENCLS_EAUG         = 0x0D,
    ENCLS_EMODPR       = 0x0E,
    ENCLS_EMODT        = 0x0F,

/* TODO EDBGRD, EDBGWR, ETRACK, EWB, EMODPR
        ELDB, EDLU ... would be implemented */

    // custom hypercalls
    ENCLS_OSGX_INIT      = 0x10,          // XXX?
    ENCLS_OSGX_PUBKEY    = 0x11,          // XXX?
    ENCLS_OSGX_EPCM_CLR  = 0x12,          // XXX?
    ENCLS_OSGX_CPUSVN    = 0x13,          // XXX?
    ENCLS_OSGX_STAT      = 0x14,
    ENCLS_OSGX_SET_STACK = 0x15,
} encls_cmd_t;

// from 5.1.2
typedef enum {
    ENCLU_EREPORT      = 0x00,
    ENCLU_EGETKEY      = 0x01,
    ENCLU_EENTER       = 0x02,
    ENCLU_ERESUME      = 0x03,
    ENCLU_EEXIT        = 0x04,
    ENCLU_EACCEPT      = 0x05,
    ENCLU_EMODPE       = 0x06,
    ENCLU_EACCEPTCOPY  = 0x07,

/* TODO EMODEPE, EACCEPTCOPY ... would be implemented */

} enclu_cmd_t;

// from 5.1.3
#define ERR_SGX_NOERROR             (0x00)
#define ERR_SGX_INVALID_SIG_STRUCT  (0x01)        //!< EINIT
#define ERR_SGX_INVALID_ATTRIBUTE   (0x02)        //!< EINIT, EGETKEY
#define ERR_SGX_BLSTATE             (0x03)        //!< EBLOCK
#define ERR_SGX_BLKSTATE            (0x03)        //!< EBLOCK
#define ERR_SGX_INVALID_MEASUREMENT (0x04)        //!< EINIT
#define ERR_SGX_NOTBLOCKABLE        (0x05)        //!< EBLOCK
#define ERR_SGX_PG_INVLD            (0x06)        //!< EBLOCK
#define ERR_SGX_LOCKFAIL            (0x07)        //!< EBLOCK
#define ERR_SGX_INVALID_SIGNATURE   (0x08)        //!< EINIT
#define ERR_SGX_MAC_COMPARE_FAIL    (0x09)        //!< ELDB, ELDU
#define ERR_SGX_PAGE_NOT_BLOCKED    (0x10)        //!< EWB
#define ERR_SGX_NOT_TRACKED         (0x11)        //!< EWB
#define ERR_SGX_VA_SLOT_OCCUPIED    (0x12)        //!< EWB
#define ERR_SGX_CHILD_PRESENT       (0x13)        //!< EWB, EREMOVE
#define ERR_SGX_ENCLAVE_ACT         (0x14)        //!< EREMOVE
#define ERR_SGX_ENTRYEPOCH_LOCKED   (0x15)        //!< EBLOCK
#define ERR_SGX_INVALID_EINIT_TOKEN (0x16)        //!< EINIT
#define ERR_SGX_PREV_TRK_INCMPL     (0x17)        //!< ETRACK
#define ERR_SGX_PG_IS_SECS          (0x18)        //!< EBLOCK
#define ERR_SGX_PAGE_ATTRIBUTES_MISMATCH (0x19)   //!< EACCEPT, EACCEPTCOPY
#define ERR_SGX_PAGE_NOT_MODIFIABLE (0x20)        //!< EMODPR, EMODT
#define ERR_SGX_INVALID_CPUSVN      (0x32)        //!< EINIT, EGETKEY
#define ERR_SGX_INVALID_ISVSVN      (0x64)        //!< EGETKEY
#define ERR_SGX_UNMASKED_EVENT      (0x128)       //!< EINIT
#define ERR_SGX_INVALID_KEYNAME     (0x256)       //!< EGETKEY

//====--------------------------------------------------------------
/// SGX ENCLS related Structures
/// Expected from kernel.
/// Currently being emulated from User space.
//====--------------------------------------------------------------

//typedef struct epc_t { char _epc_[EPC_SIZE]; } epc_t;
typedef struct {
    uint8_t byte_in_page[512];
    } epcpage_t;
typedef unsigned char epc_t[EPC_SIZE];

// from 2.19 (r2:p15)
typedef struct {
    unsigned int valid:1;               //!< Indicates whether EPCM entry is valid
    unsigned int read:1;                //!< Enclave Read accesses allowed for page
    unsigned int write:1;               //!< Enclave Write accesses allowed for page
    unsigned int execute:1;             //!< Enclave Execute accesses allowed for page
    page_type_t  page_type;             //!< EPCM page type (PT_SECS, PT_TCS, PT_REG, PT_VA, PT_TRIM)
    uint64_t enclave_secs;              //!< SECS identifier of enclave to which page belongs
    uint64_t enclave_addr;              //!< Linear enclave address of the page
    unsigned int blocked:1;             //!< Indicates whether the page is in the blocked state
    unsigned int pending:1;             //!< Indicates whether the page is in the pending state
    unsigned int modified:1;            //!< Indicates whether the page is in the modified state

    // XXX?
    uint64_t epcPageAddress;            //!< Maps EPCM <-> EPC ( enclaveAddress seems to have a different functionality
    uint64_t appAddress;                //!< Track App address - EPC address
} epcm_entry_t;

typedef struct {
    uint8_t vector;
    unsigned int exit_type : 3;
    unsigned int reserved : 4;
    uint8_t reserved2;
    unsigned int valid : 1;
} exitinfo_t;

typedef struct {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;                    // Flag register
    uint64_t rip;                       // Instruction Pointer
    uint64_t ursp;                      //!< Untruster (outside) Stack Pointer. Saved by EENTER, restored on AEX
    uint64_t urbp;                      //!< Untrusted (outside) RBP pointer. Saved by EENTER, restored on AEX
    exitinfo_t exitinfo;                  //!< Contains information about exceptions that cause AEXs, which might be needed by enclave software
    uint32_t reserved;
    uint64_t fsbase;
    uint64_t gsbase;
    // Customized hack.
    uint64_t SAVED_EXIT_EIP; // Total: 184 + 8 = 192 bytes
} gprsgx_t;

typedef struct {
    uint64_t maddr; // Page fault address
    uint32_t errcd; // exception error code for either #GP or #PF
    uint32_t reserved;
} exinfo_t;

typedef struct {
    exinfo_t exinfo;
    // Could add for future extension.
} misc_t;

typedef struct {
    // TODO: Implement - xsave_t xsave;
    uint8_t pad[3888]; // padding to one page size
    misc_t misc;     // 16 bytes
    gprsgx_t gprsgx; // 192 bytes
} ssa_t;

typedef struct {
    uint64_t linaddr;                   //!< Enclave Linear Address
    uint64_t srcpge;                    //!< Eff. addr. of the pg from where page contents are located
    uint64_t secinfo;                   //!< Eff. addr of SECINFO || PCMD structure associated with the page
    uint64_t secs;                      //!< Eff. addr. of EPC slot that currently contains a copy of the SECS
} pageinfo_t;

typedef struct  {
    unsigned int reserved1 : 1;
    unsigned int debug : 1;             //!< If 1, enclave permits debugger to r/w
    unsigned int mode64bit : 1;         //!< Enclave runs in 64- bit mode
    unsigned int reserved2 : 1;
    unsigned int provisionkey : 1;      //!< "" available from EGETKEY
    unsigned int einittokenkey : 1;     //!< "" available from EGETKEY
    unsigned int reserved3 : 2;         //!< 63:6 (58 bits) is reserved
    uint8_t      reserved4[7];
    uint64_t     xfrm;                  //!< XSAVE Feature Request Mask
} attributes_t;

typedef struct {
    unsigned int exinfo : 1;
    unsigned int reserved1 : 7;
    uint8_t      reserved2[3];
} miscselect_t;

// (ref 2.7, table 2-2)
typedef struct {
    uint64_t eid;                       //!< Enclave Identifier
    uint64_t padding[44];               //!< Padding pattern from Signature
} secs_eid_pad_t;

// reserved and eid/pad should overlap according to the sgx reference
typedef union {
    secs_eid_pad_t eid_pad;
    uint8_t reserved[3828];             //!< Reserve 8 bytes for update counter.
} secs_eid_reserved_t;

typedef struct {
    uint64_t            size;           //!< Size of enclave in bytes; must be power of 2
    uint64_t            baseAddr;       //!< Enclave base linear address must be naturally aligned to size
    uint32_t            ssaFrameSize;   //!< Size of 1 SSA frame in pages(incl. XSAVE)
    miscselect_t        miscselect;
    uint8_t             reserved1[24];
    attributes_t        attributes;     //!< Attributes of Enclave: (pg 2-4)
    uint8_t             mrEnclave[32];  //!< Measurement Reg of encl. build process
    uint8_t             reserved2[32];
    uint8_t             mrSigner[32];   //!< Measurement Reg extended with pub key that verified the enclave
    uint8_t             reserved3[96];
    uint16_t            isvprodID;      //!< Product ID of enclave
    uint16_t            isvsvn;         //!< Security Version Number (SVN) of enclave
    uint64_t            mrEnclaveUpdateCounter; 
                                        //!< Hack: place update counter here
    secs_eid_reserved_t eid_reserved;
} secs_t;

#define SIG_HEADER1 \
    {0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
#define SIG_HEADER2 \
    {0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}

typedef struct {
    uint8_t      header[16];            //!< Must be byte stream
    uint32_t     vendor;                //!< Intel Enclave: 00008086H; Non-Intel Enclave: 00000000H
    uint32_t     date;                  //!< Build date is yyyymmdd in hex
    uint8_t      header2[16];           //!< Must be byte stream
    uint32_t     swdefined;             //!< Available for software use
    uint8_t      reserved1[84];         //!< Must be zero
    uint8_t      modulus[384];          //!< Module Public Key (keylength=3072 bits)
    uint32_t     exponent;              //!< RSA Exponent = 3
    uint8_t      signature[384];        //!< Signature over Header and Body
    miscselect_t miscselect;
    miscselect_t miscmask;
    uint8_t      reserved2[20];         //!< Must be zero
    attributes_t attributes;            //!< Enclave Attributes that must be set
    attributes_t attributeMask;         //!< Mask of Attributes to enforce
    uint8_t      enclaveHash[32];       //!< MRENCLAVE of enclave this structure applies to
    uint8_t      reserved3[32];         //!< Must be zero
    uint16_t     isvProdID;             //!< ISV assigned Product ID
    uint16_t     isvSvn;                //!< ISV assigned SVN (security version number)
    uint8_t      reserved4[12];         //!< Must be zero
    uint8_t      q1[384];               //!< Q1 value for RSA Signature Verification
    uint8_t      q2[384];               //!< Q2 value for RSA Signature Verification
} sigstruct_t;

typedef struct {
    uint32_t     valid;                 //!< |CMACed| Bits 0: 1: Valid 0: Debug - rest reserved
    uint8_t      reserved1[44];         //!< |CMACed| Must be 0
    attributes_t attributes;            //!< |CMACed| Attributes of the Enclave
    uint8_t      mrEnclave[32];         //!< |CMACed| MRENCLAVE of the Enclave
    uint8_t      reserved2[32];         //!< |CMACed| Reserved
    uint8_t      mrSigner[32];          //!< |CMACed| MRSIGNER
    uint8_t      reserved3[32];         //!< |CMACed|
    uint8_t      cpuSvnLE[16];          //!< Launch Enclave's CPUSVN
    uint16_t     isvprodIDLE;           //!< Launch Enclave's ISVPRODID
    uint16_t     isvsvnLE;              //!< Launch Enclave's ISVSVN
    uint8_t      reserved4[24];         //
    miscselect_t maskedmiscSelectLE;
    attributes_t maskedAttributesLE;    //!< MaskedAttributes of Launch Enclave. This
                                        //!< should be set to the LE's attributes
                                        //!< masked with MASK the LE's KEYREQUEST.
    uint8_t      keyid[32];             //!< Value for key wear-out protection
    uint8_t      mac[16];               //!< A cryptographic mac on EINITTOKEN using launch key
} einittoken_t;

//!< from 2.6.5.2
typedef struct  {
    unsigned int r:1;                   //!< If 1, page can be read from inside enclave.
    unsigned int w:1;                   //!< If 1, page can be written inside enclave.
    unsigned int x:1;                   //!< If 1, page can be exec inside enclave.
    unsigned int pending:1;             //!< If 1, page is in the PENDING state.
    unsigned int modified:1;            //!< If 1, page is in the MODIFIED state.
    unsigned int reserved1:3;
    uint8_t page_type;                  //!< The type of page SECINFO is associated with.
    uint8_t reserved2[6];
} secinfo_flags_t;

typedef struct {
    secinfo_flags_t flags;
    uint64_t reserved[7];
} secinfo_t;

typedef struct {
    secinfo_t secinfo;
    uint64_t  enclaveid;
    uint8_t   reserved[40];
    uint64_t  mac[2]; 
} pcmd_t;

// XXX:Separate reserved -> reserved1, reserved2 to remove warning
typedef struct {
    unsigned int dbgoptin:1;
    unsigned int reserved1:31;
    uint32_t reserved2;
} tcs_flags_t;

typedef struct {
    uint64_t reserved1;
    tcs_flags_t flags;                  //!< Thread's Execution Flags
    uint64_t ossa;
    uint32_t cssa;
    uint32_t nssa;
    uint64_t oentry;
    uint64_t reserved2;
    uint64_t ofsbasgx;                  //!< Added to Base Address of Enclave to get FS Address
    uint64_t ogsbasgx;                  //!< Added to Base Address of Enclave to get GS Address
    uint32_t fslimit;
    uint32_t gslimit;
    uint64_t reserved3[503];
} tcs_t;

typedef struct {
    uint8_t      cpusvn[16];            //!< Security Version Number of processor
    miscselect_t miscselect;
    uint8_t      reserved[28];          //!< Must be 0
    attributes_t attributes;            //!< Value of attribute flags : attributes_t
    uint8_t      mrenclave[32];         //!< Value of SECS.MRENCLAVE
    uint8_t      reserved2[32];         //!< Reserved
    uint8_t      mrsigner[32];          //!< Value of SECS.MRSIGNER
    uint8_t      reserved3[96];         //!< 0
    uint16_t     isvProdID;             //!< Enclave Product ID
    uint16_t     isvsvn;                //!< Security Version Number of the Enclave
    uint8_t      reserved4[60];         //!< 0
    uint8_t      reportData[64];        //!< Set of Data used for communication between the enclave and the target enclave. Provided by EREPORT in RCX (out)
    uint8_t      keyid[32];             //!< Value for key wear-out protection
    uint8_t      mac[16];               //!< CMAC on the report using report key
} report_t;

typedef struct {
    uint8_t      measurement[32];       //!< MRENCLAVE of target enclave
    attributes_t attributes;            //!< Attributes field of target enclave
    uint8_t      reserved1[4];
    miscselect_t miscselect;
    uint8_t      reserved2[456];
} targetinfo_t;

#define FIRST_PKCS1_5_PADDING \
    {0x00, 0x01}

#define LAST_PKCS1_5_PADDING \
    {0x00, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

typedef struct {
    unsigned int mrenclave:1;
    unsigned int mrsigner:1;
    unsigned int reserved:14;
} keypolicy_t;

typedef struct {
    uint16_t     keyname;               //!< Identifies the key required
    keypolicy_t  keypolicy;             //!< Identifies which inputs are required to be used in the key derivation
    uint16_t     isvsvn;                //!< The ISV security version number used in the key derivation
    uint16_t     reserved1;
    uint8_t      cpusvn[16];            //!< The security version number of the processor used in the key derivation
    attributes_t attributeMask;         //!< A mask defining which ATTRIBUTES bits will be included in the derivation of the Seal key
    uint8_t      keyid[32];             //!< value for key wear-out protection
    miscselect_t miscmask;
    uint8_t      reserved2[436];
} keyrequest_t;

typedef struct {
    keyname_type_t keyname;
    uint16_t       isvprodID;           //!< Product ID of enclave
    uint16_t       isvsvn;              //!< Security Version Number (SVN) of enclave
    uint64_t       ownerEpoch[2];       //!< owner epoch
    attributes_t   attributes;          //!< Enclave Attributes that must be set
    attributes_t   attributesMask;      //!< Mask of Attributes to enforce
    uint8_t        mrEnclave[32];       //!< Measurement Reg of encl. build process
    uint8_t        mrSigner[32];        //!< Measurement Reg extended with pub key that verified the enclave
    uint8_t        keyid[32];           //!< Value for key wear-out protection
    uint8_t        seal_key_fuses[16];
    uint8_t        cpusvn[16];          //!< The security version number of the processor used in the key derivation
    miscselect_t   miscselect;
    miscselect_t   miscmask;
    uint64_t       padding[44];         //!< Padding pattern from Signature
} keydep_t;

/* Store the ranges for each EID */
typedef struct addrRanges {
    uint64_t ssa[2];
    uint64_t thread[2];
} addrRange;

/* Tracking Enclave Entry */
typedef struct enclaveEntry {
    uint64_t  addr;
    struct enclaveEntry *next;
} entry;

typedef struct lastAddress_t {
    uint64_t addr;
    struct lastAddress_t *next;
} lastAddress;

typedef struct mark_eid_einit {
    uint64_t eid;
    struct mark_eid_einit *next;
} eid_einit_t;

typedef struct {
    unsigned int mode_switch;
    unsigned int tlbflush_n;

    unsigned int encls_n;
    unsigned int ecreate_n;
    unsigned int eadd_n;
    unsigned int eextend_n;
    unsigned int einit_n;
    unsigned int eaug_n;
 
    unsigned int enclu_n;
    unsigned int eenter_n;
    unsigned int eresume_n;
    unsigned int eexit_n;
    unsigned int egetkey_n;
    unsigned int ereport_n;
    unsigned int eaccept_n;
} stat_t;

typedef struct {
    stat_t stat;
} qeid_t;


/* Not defined in the SGX spec sec2.6 but used in ewb & eldb instruction */
typedef struct { //128 bytes...
    uint64_t eid;
    uint64_t linaddr;
    secinfo_t secinfo; //64 bytes
    uint8_t padding[48]; // padding bytes to make it 128 byte ...
}mac_header_t;


// XXX: global for launch enclave's sig & token
// XXX: you guys should study c programming in depth
//      all should go to c, so will be linked in an obj file
//      here you basically duplicate all symbols in all obj files
//      that includ sgx.h
/*
sigstruct_t qe_sig __attribute__((aligned(PAGE_SIZE)));
einittoken_t qe_token __attribute__((aligned(EINITTOKEN_ALIGN_SIZE)));
uint64_t qe_tcs;
uint64_t qe_aep;
uint64_t qe_input_addr;
uint64_t qe_output_addr;
uint64_t qe_ret_addr;
*/
#pragma pack(pop)
