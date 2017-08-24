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
    use util::{U256, H256, Hashable};
    use std::ops::Deref;
    #[allow(dead_code)]
    fn set_storage(ext: &mut Ext, key: H256, s: &str) {
        let bytes = s.as_bytes();
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
            debug!("key: {:?}, value: {:?}", key, H256::from_slice(&value));
            let _ = ext.set_storage(key, H256::from_slice(&value));
        } else {
            let value = H256::from(U256::from(s.len() * 2 + 1));
            debug!("key: {:?}, value: {:?}", key, value);
            let _ = ext.set_storage(key, value);
            let mut key = key.crypt_hash();
            for chunk in bytes.chunks(32) {
                let value = H256::from(chunk);
                debug!("key: {:?}, value: {:?}", key, value);
                let _ = ext.set_storage(key, value);
                key = H256::from(U256::from(key).add(U256::one()));
            }
        }
    }

    #[allow(dead_code)]
    fn storage_at(ext: &mut Ext, key: &H256, str: &mut String) {
        if let Ok(value) = ext.storage_at(key) {
            if value[31] % 2 == 0 {
                let len = (value[31] / 2) as usize;
                str.push_str(&String::from_utf8_lossy(value.split_at(len).0).deref());
            } else {
                let mut len = ((value.low_u64() as usize) - 1) / 2;
                let mut key = key.crypt_hash();
                while len > 0 {
                    if let Ok(value) = ext.storage_at(&key) {

                        if len > 32 {
                            str.push_str(&String::from_utf8_lossy(&value).deref());
                            key = H256::from(U256::from(key) + U256::one());
                            len -= 32;
                        } else {
                            str.push_str(&String::from_utf8_lossy(value.split_at(len).0).deref());
                            len = 0;
                        }
                    }
                }
            }

        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use action_params::ActionParams;
        use engines::NullEngine;
        use env_info::EnvInfo;
        use evm::{Factory, VMType};
        use externalities::{OriginInfo, OutputPolicy, Externalities};
        use state::Substate;
        use tests::helpers::get_temp_state;
        use trace::{ExecutiveTracer, ExecutiveVMTracer};
        use util::Bytes;
        #[test]
        fn test_set_storage_string() {
            let mut state = get_temp_state();
            let vm_factory = Factory::new(VMType::Interpreter, 1000);
            let origin_info = OriginInfo::from(&ActionParams::default());
            let mut output = Bytes::new();
            let mut tracer = ExecutiveTracer::default();
            let mut vm_tracer = ExecutiveVMTracer::toplevel();
            let engine = NullEngine::default();
            let mut substate = Substate::new();
            let output_policy = OutputPolicy::InitContract(Some(&mut output));
            let env_info = EnvInfo::default();
            let mut ext = Externalities::new(
                &mut state,
                &env_info,
                &engine,
                &vm_factory,
                1000,
                origin_info,
                &mut substate,
                output_policy,
                &mut tracer,
                &mut vm_tracer,
            );
            let from = "abcdefghijabcdefghijabcdefghij";
            set_storage(&mut ext, H256::from(0), from);
            let mut to = String::new();
            storage_at(&mut ext, &H256::from(0), &mut to);
            assert_eq!(from, to);

            let from = "abcdefghijabcdefghijabcdefghija";
            set_storage(&mut ext, H256::from(1), from);
            let mut to = String::new();
            storage_at(&mut ext, &H256::from(1), &mut to);
            assert_eq!(from, to);


            let from = "abcdefghijabcdefghijabcdefghijab";
            set_storage(&mut ext, H256::from(2), from);
            let mut to = String::new();
            storage_at(&mut ext, &H256::from(2), &mut to);
            assert_eq!(from, to);


            let from = "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij";
            set_storage(&mut ext, H256::from(3), from);
            let mut to = String::new();
            storage_at(&mut ext, &H256::from(3), &mut to);
            assert_eq!(from, to);
        }
    }


}
