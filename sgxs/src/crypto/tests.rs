/*
 * The Rust SGXS library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

use super::*;

const KEY: &'static [u8] = b"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

include!("../tests/hex_macro.rs");

const N: &'static [u8] = &hex!( _f3 _57 _fd _12 _f0 _28 _7b _d9 _24 _ae _74 _d6
_02 _13 _6d _1b _50 _56 _5b _c7 _64 _d5 _91 _d4 _2f _18 _66 _20 _0b _d6 _71 _03
_4d _f1 _e6 _b2 _53 _d6 _3e _12 _04 _6a _d0 _b5 _58 _d6 _9b _d4 _22 _b7 _f8 _24
_87 _23 _46 _5c _9b _b7 _71 _28 _56 _59 _b4 _c9 _dc _9f _70 _70 _07 _91 _34 _da
_b0 _1f _01 _3e _77 _23 _22 _33 _4c _d7 _2f _10 _15 _62 _43 _85 _9c _d6 _44 _4e
_f1 _60 _94 _96 _77 _2b _94 _92 _89 _70 _ff _b7 _e2 _95 _7a _e4 _83 _c7 _2a _36
_dd _22 _3e _bf _9c _f1 _eb _95 _ff _5b _03 _f9 _59 _67 _6b _aa _b1 _8c _2a _ef
_a0 _c5 _23 _f7 _11 _77 _5c _bb _a8 _72 _79 _3c _b3 _52 _49 _f5 _ab _69 _b2 _48
_f4 _e6 _d7 _38 _07 _af _b9 _20 _d2 _b4 _4d _61 _6b _de _4a _b4 _2e _0f _7a _a4
_12 _d3 _ab _71 _9c _55 _ee _37 _c4 _bd _01 _92 _cb _ca _c0 _55 _c8 _06 _65 _b6
_55 _d5 _77 _6b _01 _4e _f5 _3d _87 _26 _39 _df _db _4e _62 _10 _9a _a8 _39 _77
_19 _36 _bd _0c _b5 _b7 _9e _5b _fb _5f _6d _eb _71 _bb _f2 _8b _16 _5b _a5 _09
_1a _0a _4f _37 _03 _e0 _c9 _46 _be _37 _9e _2f _6d _c3 _9e _74 _27 _1d _43 _9c
_eb _53 _1b _c2 _06 _bb _e0 _b8 _5f _f3 _4e _22 _66 _7d _f2 _d5 _b7 _40 _1e _19
_2f _41 _e3 _27 _b1 _a7 _a8 _f6 _f2 _d3 _6c _c7 _57 _fc _64 _e7 _09 _49 _96 _46
_2b _13 _3e _ce _8c _4c _37 _66 _89 _f7 _22 _23 _f0 _25 _83 _65 _cf _98 _7c _98
_5d _27 _9a _df _3e _2b _20 _fc _c0 _97 _8f _17 _13 _30 _ab _0a _59 _6f _71 _30
_33 _c1 _ca _22 _23 _0a _72 _bf _00 _99 _7e _81 _c8 _6e _66 _02 _d9 _a2 _d6 _94
_ae _95 _41 _8d _1f _5e _6a _32 _d6 _f9 _46 _25 _2d _93 _66 _d2 _e9 _25 _d9 _15
_17 _8f _65 _43 _f6 _fd _23 _fb _82 _a8 _83 _ae);
const S: &'static [u8] = &hex!( _01 _6c _b2 _1f _d5 _68 _e8 _54 _a8 _c4 _72 _c1
_2b _64 _1b _1a _0f _0e _71 _65 _67 _f5 _67 _16 _fe _c6 _e8 _76 _e5 _cd _ea _53
_e5 _e1 _60 _64 _2c _a5 _86 _78 _a5 _da _50 _08 _d2 _7f _ca _af _9d _ed _4d _62
_f1 _17 _2d _e5 _81 _fe _01 _88 _6d _f9 _88 _a5 _10 _0e _30 _79 _df _a6 _57 _2c
_32 _3d _ac _54 _cb _01 _85 _88 _56 _0a _fa _14 _a4 _5b _c1 _57 _86 _f0 _31 _1b
_0d _52 _c6 _4d _5e _fa _5d _70 _fa _0d _42 _1a _81 _9a _e8 _06 _c0 _7b _64 _05
_95 _7f _bd _31 _d8 _36 _d8 _f6 _71 _f9 _31 _3c _c0 _ce _a0 _b0 _52 _5c _22 _55
_9b _4f _0e _ba _0e _51 _eb _d0 _2d _df _3c _65 _39 _86 _75 _ae _99 _28 _d3 _81
_e8 _5e _2d _cf _2e _f9 _bd _48 _e5 _0d _db _7b _91 _f4 _b1 _1d _20 _49 _10 _d3
_9d _0f _61 _b2 _cd _0d _31 _9f _4f _2b _e1 _79 _6a _39 _bc _73 _57 _0d _14 _c8
_9b _a6 _09 _d8 _45 _39 _0e _b4 _13 _aa _da _16 _ef _ac _31 _c1 _e7 _09 _95 _5a
_99 _1a _22 _3a _97 _92 _51 _ab _26 _56 _ac _cf _7f _01 _e5 _5f _29 _75 _59 _20
_49 _0e _f1 _25 _dd _c3 _b2 _2a _bd _b4 _5c _b7 _96 _8f _7b _9d _67 _33 _38 _5a
_f6 _fc _45 _60 _c7 _9c _8e _a4 _99 _d9 _b5 _56 _63 _b0 _dc _67 _15 _a3 _e8 _8b
_45 _38 _0c _fb _32 _bf _f8 _e7 _74 _56 _e7 _7f _26 _8e _e8 _07 _ef _71 _65 _8b
_eb _36 _9e _d2 _ac _cd _24 _17 _10 _13 _43 _9a _eb _ef _a8 _a4 _8a _b4 _7a _25
_80 _e6 _6b _19 _35 _db _53 _45 _66 _06 _e7 _69 _58 _f8 _74 _a3 _e1 _ef _95 _8b
_79 _87 _83 _f3 _bb _3b _17 _04 _e0 _5d _91 _19 _04 _27 _70 _94 _20 _ba _e1 _55
_ca _fe _12 _22 _f4 _42 _64 _fc _8d _03 _8d _1e _fa _51 _97 _8c _67 _21 _b1 _b7
_54 _32 _e8 _fe _fd _ae _ec _37 _02 _c8 _46 _41);
const Q1: &'static [u8] = &hex!(_56 _68 _1f _6e _28 _1d _0d _80 _4f _b8 _7d _ba
_d3 _7d _57 _6e _4b _c6 _44 _73 _97 _79 _43 _76 _5c _a9 _dd _db _fc _4b _13 _9d
_68 _a9 _ac _36 _6b _0a _3d _b9 _5c _a9 _2f _e5 _8c _6f _f0 _00 _39 _cb _64 _46
_71 _a7 _0c _8c _bf _9f _39 _11 _5e _e9 _f3 _e3 _f5 _a7 _0b _07 _00 _20 _97 _3c
_c8 _6a _2a _40 _ca _ed _a9 _21 _6c _ef _ef _40 _ae _a0 _49 _a8 _d8 _05 _36 _44
_2a _ce _53 _e8 _61 _6c _55 _87 _31 _10 _2e _f9 _2a _6a _49 _1f _1f _01 _57 _99
_2e _05 _cd _b0 _3d _31 _4c _d8 _82 _53 _ad _9f _27 _ce _96 _25 _cb _8c _2b _1e
_ea _ee _0b _4c _49 _fa _09 _57 _b6 _19 _cd _82 _80 _e4 _6b _4b _25 _a6 _60 _54
_2d _a7 _cc _1c _2d _5d _9e _a5 _a3 _e8 _a9 _6f _6e _ae _4b _2a _67 _7c _51 _58
_f8 _9d _e3 _db _c2 _13 _8b _89 _b0 _0c _59 _e1 _94 _a0 _ba _b4 _98 _86 _90 _69
_3e _7d _d5 _f2 _34 _46 _9c _7c _e3 _60 _ab _85 _88 _87 _81 _1f _3e _a5 _d0 _ad
_2d _de _5e _6f _e9 _3a _f8 _3c _15 _54 _8d _9a _ef _aa _e8 _19 _a3 _0f _b2 _32
_c8 _a9 _7c _ef _91 _94 _48 _ab _c2 _18 _cb _20 _7b _e4 _2b _54 _8d _e3 _3c _fa
_01 _67 _53 _df _5b _cb _6c _f5 _4a _9d _1b _46 _b2 _1b _21 _94 _3c _3e _50 _16
_0a _d6 _db _d5 _97 _4a _67 _1d _13 _61 _99 _9f _1b _ea _95 _b8 _e6 _12 _3e _4d
_fe _93 _77 _b7 _c2 _8a _eb _d8 _b4 _0a _5d _3e _ac _12 _d0 _9f _41 _b4 _62 _fb
_ba _1d _73 _c5 _f3 _de _4b _03 _39 _83 _c5 _dd _c6 _03 _2d _04 _c4 _a3 _a3 _ef
_e2 _a7 _73 _cd _36 _cd _93 _98 _b2 _ba _33 _c2 _23 _0e _aa _10 _b0 _e4 _18 _e0
_97 _37 _56 _c2 _84 _83 _0e _6a _bf _98 _c8 _46 _b7 _a6 _e0 _fd _9d _0d _cc _4b
_c4 _a4 _4c _f8 _50 _d9 _2b _30 _b4 _9c _6a _18);
const Q2: &'static [u8] = &hex!(_37 _47 _9e _e9 _dd _d1 _55 _7d _2c _78 _b6 _26
_89 _26 _fc _32 _df _96 _a8 _64 _c4 _f2 _be _38 _d7 _54 _61 _28 _d6 _e9 _1c _8c
_19 _e9 _f5 _dd _ca _47 _61 _76 _e4 _38 _7d _8f _72 _41 _59 _c0 _83 _01 _a1 _f9
_af _28 _57 _23 _68 _32 _ad _b5 _cd _ab _7b _85 _83 _6f _b0 _96 _76 _2a _bc _f2
_11 _24 _43 _fc _8e _e1 _f8 _26 _5f _83 _e0 _29 _11 _fa _ce _08 _48 _81 _39 _8e
_4c _d3 _f4 _5a _61 _bb _ea _d3 _49 _8a _6c _6b _f3 _54 _43 _8f _d3 _9b _dd _40
_7f _00 _ac _f8 _6b _cf _b6 _85 _9b _d1 _69 _d4 _be _55 _aa _de _32 _08 _bb _4d
_55 _80 _a3 _8f _12 _fd _9b _aa _7b _dc _64 _e2 _73 _ce _17 _f2 _7a _1b _55 _14
_91 _1a _c6 _d2 _02 _87 _db _d3 _6e _ca _7f _f8 _55 _e1 _ff _50 _56 _15 _1e _97
_98 _e8 _cb _d6 _96 _d6 _66 _7c _c8 _66 _5d _c7 _4e _c7 _cf _c1 _fa _b3 _70 _17
_b3 _c3 _fd _5c _46 _b7 _05 _25 _e5 _d9 _59 _ec _1b _2e _49 _cd _36 _1f _cc _2c
_e3 _db _76 _27 _72 _78 _25 _c7 _1d _a0 _00 _aa _e9 _2a _fa _6c _47 _36 _ca _8a
_c0 _c0 _a6 _6c _f0 _ee _0b _75 _fe _67 _a0 _0a _cd _c6 _bf _2d _94 _09 _e2 _1d
_27 _0a _ea _66 _d1 _50 _f5 _9f _20 _f9 _f2 _fa _e0 _01 _26 _8b _8e _18 _8c _89
_6e _8e _0b _e6 _f7 _09 _db _c4 _2c _4e _40 _c7 _62 _5c _c7 _f9 _2b _26 _15 _e9
_a6 _ac _1e _94 _78 _b5 _60 _e1 _de _c4 _6f _7b _ff _37 _ef _b3 _ec _41 _d8 _3a
_e1 _8e _de _e0 _12 _88 _b7 _37 _b0 _f6 _39 _ec _81 _bd _f2 _85 _f0 _a9 _ca _a4
_6c _39 _75 _a7 _c2 _44 _3f _b0 _9d _33 _5c _7a _21 _b4 _b2 _81 _22 _a2 _ea _22
_71 _60 _f9 _a7 _e9 _6f _59 _b5 _77 _5a _25 _0f _40 _e6 _21 _e8 _f9 _73 _13 _c6
_8f _6e _a8 _91 _76 _b4 _d1 _6c _83 _f4 _02 _3e);
const H: &'static [u8] = &hex!( _28 _69 _61 _92 _07 _2b _91 _b0 _9f _90 _8b _e5
_3e _f7 _b5 _a0 _ca _48 _f0 _26 _20 _08 _44 _3e _a2 _8f _8c _b2 _0a _8b _5e _2a);

#[test]
fn rsa() {
	// Braces necessary for now, see https://github.com/rust-lang/rust/issues/31234
	let key=RsaPrivateKey::new(&mut {KEY}).unwrap();
	assert_eq!(key.len(),3072);
	assert_eq!(&key.n().unwrap()[..],N);
	assert_eq!(&key.e().unwrap()[..],[3]);
	let (sig,q1,q2)=key.sign_sha256_pkcs1v1_5_with_q1_q2(H).unwrap();
	assert_eq!(&sig[..],S);
	assert_eq!(&q1[..],Q1);
	assert_eq!(&q2[..],Q2);
}
