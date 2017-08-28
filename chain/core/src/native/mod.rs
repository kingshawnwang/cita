// CITA
// Copyright 2016-2017 Cryptape Technologies LLC.

// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any
// later version.

// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////

use action_params::ActionParams;
use evm::{self, Ext, GasLeft};
use std::collections::HashMap;
use util::{H256, U256};

////////////////////////////////////////////////////////////////////////////////
pub type Signature = u32;
pub type Function = Fn(&ActionParams, &mut Ext) -> evm::Result<GasLeft<'static>> + Sync + Send;

////////////////////////////////////////////////////////////////////////////////
// Contract
pub trait Contract: Sync + Send {
    fn get_function(&self, hash: &Signature) -> Option<&Box<Function>>;
    fn exec(&self, params: &ActionParams, mut ext: &mut Ext) {
        if let Some(data) = params.clone().data.unwrap().get(0..4) {
            let signature = data.iter().fold(0u32, |acc, &x| (acc << 8) + (x as u32));
            if let Some(exec_call) = self.get_function(&signature) {
                //let cost = self.engine.cost_of_builtin(&params.code_address, data);
                let cost = U256::from(100);
                if cost <= params.gas {
                    let _ = exec_call(params, ext);
                    //self.state.discard_checkpoint();
                    return;
                }
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// NowPay
pub struct NowPay {
    functions: HashMap<Signature, Box<Function>>,
}

impl Contract for NowPay {
    fn get_function(&self, hash: &Signature) -> Option<&Box<Function>> {
        self.functions.get(hash)
    }
}

impl NowPay {
    pub fn new() -> Self {
        let mut contract = NowPay { functions: HashMap::<Signature, Box<Function>>::new() };
        contract.functions.insert(0, Box::new(NowPay::set_value));
        contract
    }
    pub fn set_value(params: &ActionParams, ext: &mut Ext) -> evm::Result<GasLeft<'static>> {
        if let Some(ref data) = params.data {
            if let Some(data) = data.get(4..32) {
                let _ = ext.set_storage(H256::from(0), H256::from(data));
            }
        }
        Ok(GasLeft::Known(U256::from(0)))
    }
}
pub mod types {
    use evm::Ext;
    use std::ops::Add;
    use std::ops::Deref;
    use util::{U256, H256, Hashable};

    pub fn set_string(ext: &mut Ext, key: &H256, s: &String) {
        let bytes = s.as_bytes();
        let key = H256::from(*key);
        if s.len() < 32 {
            let mut value = [0u8; 32];
            let mut index = 0;
            for c in bytes.iter() {
                value[index] = *c;
                index += 1;
            }
            while index < 31 {
                value[index] = 0;
                index += 1;
            }
            value[index] = (s.len() * 2) as u8;
            debug!(target: "native", "key: {:?}, value: {:?}", key, H256::from_slice(&value));
            let _ = ext.set_storage(key, H256::from_slice(&value));
        } else {
            let value = H256::from(U256::from(s.len() * 2 + 1));
            debug!(target: "native", "key: {:?}, value: {:?}", key, value);
            let _ = ext.set_storage(key, value);
            let mut key = key.crypt_hash();
            for chunk in bytes.chunks(32) {
                let value = H256::from(chunk);
                debug!(target: "native", "key: {:?}, value: {:?}", key, value);
                let _ = ext.set_storage(key, value);
                key = H256::from(U256::from(key).add(U256::one()));
            }
        }
    }

    pub fn string_at(ext: &Ext, key: &H256, value: &mut String) {
        let key = H256::from(*key);
        if let Ok(v) = ext.storage_at(&key) {
            if v[31] % 2 == 0 {
                let len = (v[31] / 2) as usize;
                value.push_str(&String::from_utf8_lossy(v.split_at(len).0).deref());
            } else {
                let mut len = ((v.low_u64() as usize) - 1) / 2;
                let mut key = key.crypt_hash();
                while len > 0 {
                    if let Ok(v) = ext.storage_at(&key) {

                        if len > 32 {
                            value.push_str(&String::from_utf8_lossy(&v).deref());
                            key = H256::from(U256::from(key) + U256::one());
                            len -= 32;
                        } else {
                            value.push_str(&String::from_utf8_lossy(v.split_at(len).0).deref());
                            len = 0;
                        }
                    }
                }
            }
        }
    }

    pub fn set_array(ext: &mut Ext, key: &H256, vector: &Vec<U256>) {
        let key = H256::from(*key);
        let value = H256::from(U256::from(vector.len()));
        debug!(target: "native", "key: {:?}, value: {:?}", key, value);
        let _ = ext.set_storage(key, value);

        let mut key = key.crypt_hash();
        for item in vector.iter() {
            let value = H256::from(item);
            debug!(target: "native", "key: {:?}, value: {:?}", key, value);
            let _ = ext.set_storage(key, value);
            key = H256::from(U256::from(key).add(U256::one()));
        }
    }

    pub fn array_at(ext: &Ext, key: &H256, vec: &mut Vec<U256>) {
        let key = H256::from(*key);
        if let Ok(value) = ext.storage_at(&key) {
            let mut len = value.low_u64() as usize;
            let mut key = key.crypt_hash();
            while len > 0 {
                if let Ok(value) = ext.storage_at(&key) {
                    vec.push(U256::from(value));
                    key = H256::from(U256::from(key) + U256::one());
                    len -= 1;
                }
            }
        }
    }

    pub fn set_map(ext: &mut Ext, pos: &H256, key: &H256, value: &U256) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(pos);
        let key = bytes.crypt_hash();
        debug!(target: "native", "key: {:?}, value: {:?}", key, value);
        let _ = ext.set_storage(key, H256::from(value));
    }
    pub fn set_map_string(ext: &mut Ext, pos: &H256, key: &H256, value: &String) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(pos);
        let key = bytes.crypt_hash();
        set_string(ext, &key, value);
    }
    pub fn map_at(ext: &Ext, pos: &H256, key: &H256, value: &mut U256) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(pos);
        let key = bytes.crypt_hash();
        if let Ok(value2) = ext.storage_at(&key) {
            *value = U256::from(value2);
            debug!(target: "native", "key: {:?}, value: {:?}", key, value);
        }
    }
    pub fn map_at_string(ext: &Ext, pos: &H256, key: &H256, value: &mut String) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(pos);
        let key = bytes.crypt_hash();
        string_at(ext, &key, &mut value);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use env_logger;
        use evm::tests::FakeExt;
        use std::sync::{Once, ONCE_INIT};

        static INIT: Once = ONCE_INIT;

        /// Setup function that is only run once, even if called multiple times.
        fn setup() {
            INIT.call_once(|| { env_logger::init().unwrap(); });
        }
        #[test]
        fn test_string() {
            setup();
            let mut ext = FakeExt::new();
            let original = String::from("abcdefghijabcdefghijabcdefghij");
            set_string(&mut ext, &H256::from(0), &original);
            let mut expected = String::new();
            string_at(&mut ext, &H256::from(0), &mut expected);
            assert_eq!(original, expected);

            let original = String::from("abcdefghijabcdefghijabcdefghija");
            set_string(&mut ext, &H256::from(1), &original);
            let mut expected = String::new();
            string_at(&mut ext, &H256::from(1), &mut expected);
            assert_eq!(original, expected);

            let original = String::from("abcdefghijabcdefghijabcdefghijab");
            set_string(&mut ext, &H256::from(2), &original);
            let mut expected = String::new();
            string_at(&mut ext, &H256::from(2), &mut expected);
            assert_eq!(original, expected);

            let original = String::from("abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij");
            set_string(&mut ext, &H256::from(3), &original);
            let mut expected = String::new();
            string_at(&mut ext, &H256::from(3), &mut expected);
            assert_eq!(original, expected);
        }
        #[test]
        fn test_array() {
            setup();
            let mut ext = FakeExt::new();
            let mut from = Vec::new();
            for i in 0..4 {
                from.push(U256::from(0x1234560 + i));
            }
            set_array(&mut ext, &H256::from(1), &from);
            let mut to = Vec::new();
            array_at(&mut ext, &H256::from(1), &mut to);
            assert_eq!(from, to);
        }

        #[test]
        fn test_map() {
            setup();
            let mut ext = FakeExt::new();

            let original = U256::from(3);
            let mut expected = U256::zero();
            set_map(&mut ext, &H256::from(2), &H256::from(3), &original);
            map_at(&mut ext, &H256::from(2), &H256::from(3), &mut expected);
            assert_eq!(original, expected);


            let original = String::from("abcdefghijabcdefghijabcdefghijabcdefghij");
            let mut expected = String::new();
            set_map_string(&mut ext, &H256::from(2), &H256::from(3), &original);
            map_at_string(&mut ext, &H256::from(2), &H256::from(3), &mut expected);
            assert_eq!(original, expected);
        }
    }
}
