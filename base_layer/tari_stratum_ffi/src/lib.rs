// Copyright 2021. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
#![cfg_attr(not(debug_assertions), deny(unused_variables))]
#![cfg_attr(not(debug_assertions), deny(unused_imports))]
#![cfg_attr(not(debug_assertions), deny(dead_code))]
#![cfg_attr(not(debug_assertions), deny(unused_extern_crates))]
#![deny(unused_must_use)]
#![deny(unreachable_patterns)]
#![deny(unknown_lints)]

mod error;

use core::ptr;
use std::ffi::CString;

use libc::{c_char, c_int, c_ulonglong};
use tari_core::{
    blocks::Block,
    proof_of_work::{sha3_difficulty, Difficulty},
};
use tari_crypto::tari_utilities::{hex::Hex, message_format::MessageFormat};
use tari_utilities::Hashable;

use crate::error::{InterfaceError, StratumTranscoderError};

pub type TariPublicKey = tari_comms::types::CommsPublicKey;

/// Validates a hex string is convertible into a TariPublicKey
///
/// ## Arguments
/// `hex` - The hex formatted cstring to be validated
///
/// ## Returns
/// `bool` - Returns true/false
/// `error_out` - Error code returned, 0 means no error
///
/// # Safety
/// None
#[no_mangle]
pub unsafe extern "C" fn public_key_hex_validate(hex: *const c_char, error_out: *mut c_int) -> bool {
    let mut error = 0;
    ptr::swap(error_out, &mut error as *mut c_int);
    let native;

    if hex.is_null() {
        error = StratumTranscoderError::from(InterfaceError::Null("hex".to_string())).code;
        ptr::swap(error_out, &mut error as *mut c_int);
        return false;
    } else {
        native = CString::from_raw(hex as *mut i8).to_str().unwrap().to_owned();
    }
    let pk = TariPublicKey::from_hex(&native);
    match pk {
        Ok(_pk) => true,
        Err(e) => {
            error = StratumTranscoderError::from(e).code;
            ptr::swap(error_out, &mut error as *mut c_int);
            false
        },
    }
}

/// Injects a nonce into a blocktemplate
///
/// ## Arguments
/// `hex` - The hex formatted cstring
/// `nonce` - The nonce to be injected
///
/// ## Returns
/// `c_char` - The updated hex formatted cstring or null on error
/// `error_out` - Error code returned, 0 means no error
///
/// # Safety
/// None
#[no_mangle]
pub unsafe extern "C" fn inject_nonce(hex: *const c_char, nonce: c_ulonglong, error_out: *mut c_int) -> *const c_char {
    let mut error = 0;
    ptr::swap(error_out, &mut error as *mut c_int);
    let native;

    if hex.is_null() {
        error = StratumTranscoderError::from(InterfaceError::Null("hex".to_string())).code;
        ptr::swap(error_out, &mut error as *mut c_int);
        ptr::null()
    } else {
        native = CString::from_raw(hex as *mut i8).to_str().unwrap().to_owned();
        let block_hex = hex::decode(native);
        match block_hex {
            Ok(block_hex) => {
                let block: Result<Block, serde_json::Error> =
                    serde_json::from_str(&String::from_utf8_lossy(&block_hex).to_string());
                match block {
                    Ok(mut block) => {
                        block.header.nonce = nonce;
                        let block_json = block.to_json().unwrap();
                        let block_hex = hex::encode(block_json);
                        let result = CString::new(block_hex).unwrap();
                        CString::into_raw(result)
                    },
                    Err(_) => {
                        error = StratumTranscoderError::from(InterfaceError::Conversion("block".to_string())).code;
                        ptr::swap(error_out, &mut error as *mut c_int);
                        ptr::null()
                    },
                }
            },
            Err(_) => {
                error = StratumTranscoderError::from(InterfaceError::Conversion("hex".to_string())).code;
                ptr::swap(error_out, &mut error as *mut c_int);
                ptr::null()
            },
        }
    }
}

/// Returns the difficulty of a share
///
/// ## Arguments
/// `hex` - The hex formatted cstring to be validated
///
/// ## Returns
/// `c_ulonglong` - Difficulty, 0 on error
/// `error_out` - Error code returned, 0 means no error
///
/// # Safety
/// None
#[no_mangle]
pub unsafe extern "C" fn share_difficulty(hex: *const c_char, error_out: *mut c_int) -> c_ulonglong {
    let mut error = 0;
    ptr::swap(error_out, &mut error as *mut c_int);
    let block_hex_string;

    if hex.is_null() {
        error = StratumTranscoderError::from(InterfaceError::Null("hex".to_string())).code;
        ptr::swap(error_out, &mut error as *mut c_int);
        return 0;
    } else {
        block_hex_string = CString::from_raw(hex as *mut i8).to_str().unwrap().to_owned();
    }

    let block_hex = hex::decode(block_hex_string);
    match block_hex {
        Ok(block_hex) => {
            let block: Result<Block, serde_json::Error> =
                serde_json::from_str(&String::from_utf8_lossy(&block_hex).to_string());
            match block {
                Ok(block) => {
                    let difficulty = sha3_difficulty(&block.header);
                    difficulty.as_u64()
                },
                Err(_) => {
                    error = StratumTranscoderError::from(InterfaceError::Conversion("block".to_string())).code;
                    ptr::swap(error_out, &mut error as *mut c_int);
                    0
                },
            }
        },
        Err(_) => {
            error = StratumTranscoderError::from(InterfaceError::Conversion("hex".to_string())).code;
            ptr::swap(error_out, &mut error as *mut c_int);
            0
        },
    }
}

/// Validates a share submission
///
/// ## Arguments
/// `hex` - The hex representation of the share to be validated
/// `hash` - The hash of the share to be validated
/// `nonce` - The nonce for the share to be validated
/// `stratum_difficulty` - The stratum difficulty to be checked against (meeting this means that the share is valid for
/// payout) `template_difficulty` - The difficulty to be checked against (meeting this means the share is also a block
/// to be submitted to the chain)
///
/// ## Returns
/// `c_uint` - Returns one of the following:
///             0: Valid Block
///             1: Valid Share
///             2: Invalid Share
/// `error_out` - Error code returned, 0 means no error
///
/// # Safety
/// None
#[no_mangle]
pub unsafe extern "C" fn share_validate(
    hex: *const c_char,
    hash: *const c_char,
    stratum_difficulty: c_ulonglong,
    template_difficulty: c_ulonglong,
    error_out: *mut c_int,
) -> c_int {
    let mut error = 0;
    ptr::swap(error_out, &mut error as *mut c_int);
    let block_hex_string;
    let block_hash_string;

    if hex.is_null() {
        error = StratumTranscoderError::from(InterfaceError::Null("hex".to_string())).code;
        ptr::swap(error_out, &mut error as *mut c_int);
        return 2;
    } else {
        block_hex_string = CString::from_raw(hex as *mut i8).to_str().unwrap().to_owned();
    }

    if hash.is_null() {
        error = StratumTranscoderError::from(InterfaceError::Null("hash".to_string())).code;
        ptr::swap(error_out, &mut error as *mut c_int);
        return 2;
    } else {
        block_hash_string = CString::from_raw(hash as *mut i8).to_str().unwrap().to_owned();
    }

    let block_hex = hex::decode(block_hex_string);
    match block_hex {
        Ok(block_hex) => {
            let block: Result<Block, serde_json::Error> =
                serde_json::from_str(&String::from_utf8_lossy(&block_hex).to_string());
            match block {
                Ok(block) => {
                    if block.header.hash().to_hex() == block_hash_string {
                        // Hash submitted by miner is the same hash produced for the nonce submitted by miner
                        let mut result = 2;
                        let difficulty = sha3_difficulty(&block.header);
                        if difficulty >= Difficulty::from(template_difficulty) {
                            // Valid block
                            result = 0;
                        } else if difficulty >= Difficulty::from(stratum_difficulty) {
                            // Valid share
                            result = 1;
                        } else {
                            // Difficulty not reached
                            error = StratumTranscoderError::from(InterfaceError::LowDifficulty(block_hash_string)).code;
                            ptr::swap(error_out, &mut error as *mut c_int);
                        }
                        result
                    } else {
                        error = StratumTranscoderError::from(InterfaceError::InvalidHash(block_hash_string)).code;
                        ptr::swap(error_out, &mut error as *mut c_int);
                        2
                    }
                },
                Err(_) => {
                    error = StratumTranscoderError::from(InterfaceError::Conversion("block".to_string())).code;
                    ptr::swap(error_out, &mut error as *mut c_int);
                    2
                },
            }
        },
        Err(_) => {
            error = StratumTranscoderError::from(InterfaceError::Conversion("hex".to_string())).code;
            ptr::swap(error_out, &mut error as *mut c_int);
            2
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, str};

    use libc::{c_char, c_int};
    // use tari_crypto::tari_utilities::Hashable;
    // use tari_crypto::tari_utilities::hex::Hex;
    // use tari_core::blocks::Block;
    use crate::{inject_nonce, public_key_hex_validate, share_difficulty, share_validate};

    const BLOCK_HEX: &str = "7b22686561646572223a7b2276657273696f6e223a312c22686569676874223a312c22707265765f68617368223a2265346435666439373464326362636638373336366138333937306338303161313134363962326239663731626134326634373536346664653465353133643130222c2274696d657374616d70223a313633393134353431372c226f75747075745f6d72223a2263326336353231303931303835376537333131313561623063623564633265363264343564373037346239313833346364356437353934373333303736313235222c227769746e6573735f6d72223a2237346432353931653833323661633465393862663935323230316532306365303437663337356164613032343566666438393335346664346630396166313766222c226f75747075745f6d6d725f73697a65223a343030322c226b65726e656c5f6d72223a2265623431626631663264356336353134346435623231336665353730316362343738323637303362353263353136653236663064633536383662636263333065222c226b65726e656c5f6d6d725f73697a65223a332c22696e7075745f6d72223a2232363134366135343335656631356538636637646333333534636237323638313337653862653231313739346539336430343535313537366336353631353635222c22746f74616c5f6b65726e656c5f6f6666736574223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c22746f74616c5f7363726970745f6f6666736574223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c226e6f6e6365223a302c22706f77223a7b22706f775f616c676f223a2253686133222c22706f775f64617461223a5b5d7d7d2c22626f6479223a7b22736f72746564223a66616c73652c22696e70757473223a5b5d2c226f757470757473223a5b7b226665617475726573223a7b22666c616773223a7b2262697473223a317d2c226d61747572697479223a372c2266696c7465725f62797465223a307d2c22636f6d6d69746d656e74223a2232633738313336643139666235636235613561343234323037316438363737323338643837363131383339666136393163363037656133656264376634323537222c2270726f6f66223a22353230633933376261373639326131363563646534326363626438343530626366356536656538353366353237663964373463633962646431376137333634663265353963343036663165666161356238663463626531663731326536393539653230623331633463303831303663316234303339636566613936353137303635326661633835383036316130336130343035386534356334623137316330666337386565313733373632336132626162343962663138326337656563303261383031316336656335363461626134336430396136643031333530663136376263333034653739383066663233356364336238323961656361333434386136376631373231383564386431656131646666333633383639643034653730653165346462343933643431376130366663656537626462656465653435313761306262336638306463643530396430623437386263346635373631316631353763306539636535353839663734393961666331343931613365383231646336343062323031643832613162303331313366643864346234393662393531633064373531393438336162376332393439323330653664346432636538366337363730313063316638373534653337646561333633393465633465323233353965616564643033376535386464346465653630326431343532613533366339386464336138346338663066646630633165343530383161333562653266373139363666656232663561613138393666343063316430323232353530383834396238343765316338386230643762366462626463626131383730373166663562333335336362313364656162626233386634613262383238666533656439623034326433333430626436636638373339343666333434383836653165393337656166353734633838653766613764303162336561356639643930366361323561353466353838633830613531393836396436623236383038616633393465313664616666613534336634336137666531303462633137306138363334373732613533313235343463356230373932303834323265376431633134373064356232326633393461303161333737616663323466363930613366636233336539646537363937643836326165396337323436626164646237666635393736336336623263346338653633653532306161326638656632643031306539313637306633353163373836656430616262306636343032393335346163393130373232333637666239363765346230386664633963646561303939643466613237343862643565623338386538383863653463616363333762303931326466353730643631326330326334316364616432313331623536386630346439356530393631346438616433336263613139643134336565663938303733663366373339633334626163393834356437343836636562313432386637393764343230663634653262636632316433363666623264333733633765353162643336623035386236363262333565643731643662343438633433663632376165623137656433656165373838623334373034643163656430323334666536383133386137326637643361346361323864636431653034396463363061623130656161323331633037366331666535636432616433383063346335633866313766666465326434346135313961363633386331373766343566363466316635386133363337383432643531653635306262303165326233613461343061363166363331346131303566336539393635363533373037306166343739336634663939333861633561333231363132623033222c22736372697074223a223733222c2273656e6465725f6f66667365745f7075626c69635f6b6579223a2263363331643432313033356331663163353133303239656665376464393932646233343131646430343738303731386563616230313037613635373366313130222c226d657461646174615f7369676e6174757265223a7b227075626c69635f6e6f6e6365223a2263343437643432653236633032373764353663616639306438303862373030386563366633306537353466386363323435343231396638626338333832623261222c2275223a2263383637393032366661653465633736356261343065623630316433393130366661393165323230663835643430306662316638323333326365306633373065222c2276223a2234393366616136383136323565386565363231366130626634663732323565623732396534623763343432353638363537653036666133306361616265373034227d7d5d2c226b65726e656c73223a5b7b226665617475726573223a7b2262697473223a317d2c22666565223a302c226c6f636b5f686569676874223a302c22657863657373223a2239613334316237376538316532313832653765396161343962373136393734656231326637616566383364636466353530393935373934636335303532663065222c226578636573735f736967223a7b227075626c69635f6e6f6e6365223a2237366466666539663963323065353237336161656439633531373564623937333838346631376564396236646434336632306538396132316263323563313731222c227369676e6174757265223a2231343631646138393033356135636436313564393034643637613364326465633938323734613937393662326563633732376232613131383966353863613037227d7d5d7d7d";
    // Hash of the header
    const HASH_HEX: &str = "e631dc4c0b98198c5f08090acded220ccc944b97d6079c00ce0c59b4994e51d7";
    const NONCE: u64 = 995572868245622544;

    #[test]
    #[ignore = "to be fixed"]
    fn check_difficulty() {
        // Difficulty 10
        unsafe {
            // let block_hex = hex::decode("7b22686561646572223a7b2276657273696f6e223a312c22686569676874223a312c22707265765f68617368223a2265346435666439373464326362636638373336366138333937306338303161313134363962326239663731626134326634373536346664653465353133643130222c2274696d657374616d70223a313633393134353431372c226f75747075745f6d72223a2263326336353231303931303835376537333131313561623063623564633265363264343564373037346239313833346364356437353934373333303736313235222c227769746e6573735f6d72223a2237346432353931653833323661633465393862663935323230316532306365303437663337356164613032343566666438393335346664346630396166313766222c226f75747075745f6d6d725f73697a65223a343030322c226b65726e656c5f6d72223a2265623431626631663264356336353134346435623231336665353730316362343738323637303362353263353136653236663064633536383662636263333065222c226b65726e656c5f6d6d725f73697a65223a332c22696e7075745f6d72223a2232363134366135343335656631356538636637646333333534636237323638313337653862653231313739346539336430343535313537366336353631353635222c22746f74616c5f6b65726e656c5f6f6666736574223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c22746f74616c5f7363726970745f6f6666736574223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c226e6f6e6365223a302c22706f77223a7b22706f775f616c676f223a2253686133222c22706f775f64617461223a5b5d7d7d2c22626f6479223a7b22736f72746564223a66616c73652c22696e70757473223a5b5d2c226f757470757473223a5b7b226665617475726573223a7b22666c616773223a7b2262697473223a317d2c226d61747572697479223a372c2266696c7465725f62797465223a307d2c22636f6d6d69746d656e74223a2232633738313336643139666235636235613561343234323037316438363737323338643837363131383339666136393163363037656133656264376634323537222c2270726f6f66223a22353230633933376261373639326131363563646534326363626438343530626366356536656538353366353237663964373463633962646431376137333634663265353963343036663165666161356238663463626531663731326536393539653230623331633463303831303663316234303339636566613936353137303635326661633835383036316130336130343035386534356334623137316330666337386565313733373632336132626162343962663138326337656563303261383031316336656335363461626134336430396136643031333530663136376263333034653739383066663233356364336238323961656361333434386136376631373231383564386431656131646666333633383639643034653730653165346462343933643431376130366663656537626462656465653435313761306262336638306463643530396430623437386263346635373631316631353763306539636535353839663734393961666331343931613365383231646336343062323031643832613162303331313366643864346234393662393531633064373531393438336162376332393439323330653664346432636538366337363730313063316638373534653337646561333633393465633465323233353965616564643033376535386464346465653630326431343532613533366339386464336138346338663066646630633165343530383161333562653266373139363666656232663561613138393666343063316430323232353530383834396238343765316338386230643762366462626463626131383730373166663562333335336362313364656162626233386634613262383238666533656439623034326433333430626436636638373339343666333434383836653165393337656166353734633838653766613764303162336561356639643930366361323561353466353838633830613531393836396436623236383038616633393465313664616666613534336634336137666531303462633137306138363334373732613533313235343463356230373932303834323265376431633134373064356232326633393461303161333737616663323466363930613366636233336539646537363937643836326165396337323436626164646237666635393736336336623263346338653633653532306161326638656632643031306539313637306633353163373836656430616262306636343032393335346163393130373232333637666239363765346230386664633963646561303939643466613237343862643565623338386538383863653463616363333762303931326466353730643631326330326334316364616432313331623536386630346439356530393631346438616433336263613139643134336565663938303733663366373339633334626163393834356437343836636562313432386637393764343230663634653262636632316433363666623264333733633765353162643336623035386236363262333565643731643662343438633433663632376165623137656433656165373838623334373034643163656430323334666536383133386137326637643361346361323864636431653034396463363061623130656161323331633037366331666535636432616433383063346335633866313766666465326434346135313961363633386331373766343566363466316635386133363337383432643531653635306262303165326233613461343061363166363331346131303566336539393635363533373037306166343739336634663939333861633561333231363132623033222c22736372697074223a223733222c2273656e6465725f6f66667365745f7075626c69635f6b6579223a2263363331643432313033356331663163353133303239656665376464393932646233343131646430343738303731386563616230313037613635373366313130222c226d657461646174615f7369676e6174757265223a7b227075626c69635f6e6f6e6365223a2263343437643432653236633032373764353663616639306438303862373030386563366633306537353466386363323435343231396638626338333832623261222c2275223a2263383637393032366661653465633736356261343065623630316433393130366661393165323230663835643430306662316638323333326365306633373065222c2276223a2234393366616136383136323565386565363231366130626634663732323565623732396534623763343432353638363537653036666133306361616265373034227d7d5d2c226b65726e656c73223a5b7b226665617475726573223a7b2262697473223a317d2c22666565223a302c226c6f636b5f686569676874223a302c22657863657373223a2239613334316237376538316532313832653765396161343962373136393734656231326637616566383364636466353530393935373934636335303532663065222c226578636573735f736967223a7b227075626c69635f6e6f6e6365223a2237366466666539663963323065353237336161656439633531373564623937333838346631376564396236646434336632306538396132316263323563313731222c227369676e6174757265223a2231343631646138393033356135636436313564393034643637613364326465633938323734613937393662326563633732376232613131383966353863613037227d7d5d7d7d").unwrap();
            // let block: Result<Block, serde_json::Error> =
            //     serde_json::from_str(&String::from_utf8_lossy(&block_hex).to_string());
            // let hash_hex = block.unwrap().header.hash().to_hex();

            let mut error = -1;
            let error_ptr = &mut error as *mut c_int;
            let block_hex = CString::new(BLOCK_HEX).unwrap();
            let block_hex_ptr: *const c_char = CString::into_raw(block_hex) as *const c_char;
            let block_hex_ptr2 = inject_nonce(block_hex_ptr, NONCE, error_ptr);
            let result = share_difficulty(block_hex_ptr2, error_ptr);
            assert_eq!(result, 10);
        }
    }

    #[test]
    #[ignore = "to be fixed"]
    fn check_invalid_share() {
        // Difficulty 20025
        unsafe {
            let mut error = -1;
            let error_ptr = &mut error as *mut c_int;
            let block_hex = CString::new(BLOCK_HEX).unwrap();
            let hash_hex = CString::new(HASH_HEX).unwrap();
            let block_hex_ptr: *const c_char = CString::into_raw(block_hex) as *const c_char;
            let hash_hex_ptr: *const c_char = CString::into_raw(hash_hex) as *const c_char;
            let template_difficulty = 30000;
            let stratum_difficulty = 22200;
            let block_hex_ptr2 = inject_nonce(block_hex_ptr, NONCE, error_ptr);
            let result = share_validate(
                block_hex_ptr2,
                hash_hex_ptr,
                stratum_difficulty,
                template_difficulty,
                error_ptr,
            );
            assert_eq!(result, 2);
            assert_eq!(error, 4);
        }
    }

    #[test]
    #[ignore = "to be fixed"]
    fn check_valid_share() {
        // Difficulty 20025
        unsafe {
            let mut error = -1;
            let error_ptr = &mut error as *mut c_int;
            let block_hex = CString::new(BLOCK_HEX).unwrap();
            let hash_hex = CString::new(HASH_HEX).unwrap();
            let block_hex_ptr: *const c_char = CString::into_raw(block_hex) as *const c_char;
            let hash_hex_ptr: *const c_char = CString::into_raw(hash_hex) as *const c_char;
            let template_difficulty = 30000;
            let stratum_difficulty = 20000;
            let block_hex_ptr2 = inject_nonce(block_hex_ptr, NONCE, error_ptr);
            let result = share_validate(
                block_hex_ptr2,
                hash_hex_ptr,
                stratum_difficulty,
                template_difficulty,
                error_ptr,
            );
            assert_eq!(result, 1);
            assert_eq!(error, 0);
        }
    }

    #[test]
    #[ignore = "to be fixed"]
    fn check_valid_block() {
        // Difficulty 20025
        unsafe {
            let mut error = -1;
            let error_ptr = &mut error as *mut c_int;
            let block_hex = CString::new(BLOCK_HEX).unwrap();
            let hash_hex = CString::new(HASH_HEX).unwrap();
            let block_hex_ptr: *const c_char = CString::into_raw(block_hex) as *const c_char;
            let hash_hex_ptr: *const c_char = CString::into_raw(hash_hex) as *const c_char;
            let template_difficulty = 20000;
            let stratum_difficulty = 15000;
            let block_hex_ptr2 = inject_nonce(block_hex_ptr, NONCE, error_ptr);
            let result = share_validate(
                block_hex_ptr2,
                hash_hex_ptr,
                stratum_difficulty,
                template_difficulty,
                error_ptr,
            );
            assert_eq!(result, 0);
            assert_eq!(error, 0);
        }
    }

    #[test]
    fn check_valid_address() {
        unsafe {
            let mut error = -1;
            let error_ptr = &mut error as *mut c_int;
            let test_pk = CString::new("5ce83bf62521629ca185098ac24c7b02b184c2e0a2b01455f3a5957d5df94126").unwrap();
            let test_pk_ptr: *const c_char = CString::into_raw(test_pk) as *const c_char;
            let success = public_key_hex_validate(test_pk_ptr, error_ptr);
            assert_eq!(error, 0);
            assert!(success);
        }
    }

    #[test]
    fn check_invalid_address() {
        unsafe {
            let mut error = -1;
            let error_ptr = &mut error as *mut c_int;
            let test_pk = CString::new("5fe83bf62521629ca185098ac24c7b02b184c2e0a2b01455f3a5957d5df94126").unwrap();
            let test_pk_ptr: *const c_char = CString::into_raw(test_pk) as *const c_char;
            let success = public_key_hex_validate(test_pk_ptr, error_ptr);
            assert!(!success);
            assert_ne!(error, 0);
        }
        unsafe {
            let mut error = -1;
            let error_ptr = &mut error as *mut c_int;
            let test_pk = CString::new("5fe83bf62521629ca185098ac24c7b02b184c2e0a2b01455f3a5957d5d").unwrap();
            let test_pk_ptr: *const c_char = CString::into_raw(test_pk) as *const c_char;
            let success = public_key_hex_validate(test_pk_ptr, error_ptr);
            assert!(!success);
            assert_ne!(error, 0);
        }
    }
}
