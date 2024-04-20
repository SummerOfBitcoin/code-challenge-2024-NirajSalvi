extern crate serde_derive;

use serde_json::{json, Result};
use serde_derive::Deserialize;

#[derive(Deserialize, Debug)]
pub struct btctx {
    pub txid : Option<String>,
    pub version: u32,
    pub locktime: u32,
    pub vin : Vec<txin>,
    pub vout: Vec<txout>,
}

#[derive(Debug, Deserialize)]
pub struct txin {
    pub txid: String,
    pub vout: u32,
    pub prevout: txout,
    pub scriptsig: String,
    pub scriptsig_asm: String,
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
}

#[derive(Debug, Deserialize)]
pub struct txout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    
    if value < 0xFD {
        result.push(value as u8);
    }
    else if value <= 0xFFFF {
        result.push(0xFD);
        result.extend_from_slice(&(value as u16).to_le_bytes());
    }
    else if value <= 0xFFFFFFFF {
        result.push(0xFE);
        result.extend_from_slice(&(value as u32).to_le_bytes());
    }
    else {
        result.push(0xFF);
        result.extend_from_slice(&value.to_le_bytes());
    }
    
    result
}

impl btctx {

    pub fn serialize_tx(&self) -> Vec<u8> {

        let mut v: Vec<u8> = Vec::new();
        
        let mut version_bytes = self.version.to_le_bytes().to_vec();
        println!("{} = {:?}",self.version ,version_bytes );
        v.append(&mut version_bytes);

        let input_count = encode_varint(self.vin.len() as u64);
        println!("{} = {:?}",self.vin.len() ,input_count );
        v.append(&mut input_count.to_vec());
        // let le_bytes = value.to_le_bytes().to_vec();

        for i in &self.vin {
            let mut txid = i.txid.as_bytes().to_vec();
            println!("{} = {:?}",i.txid ,txid );
            v.append(&mut txid);

            let mut vout_bytes = i.vout.to_le_bytes().to_vec();
            println!("{} = {:?}",i.vout , vout_bytes);
            v.append(&mut vout_bytes);

            let mut scriptsig_size = encode_varint(i.scriptsig.len() as u64);
            println!("{} = {:?}", i.scriptsig.len(), scriptsig_size);
            v.append(&mut scriptsig_size);

            let mut scriptsig_bytes = i.scriptsig.as_bytes().to_vec();
            println!("{} = {:?}", i.scriptsig, scriptsig_bytes);
            v.append(&mut scriptsig_bytes);

            let mut sequence_bytes = i.sequence.to_le_bytes().to_vec();
            println!("{} = {:?}", i.sequence, sequence_bytes );
            v.append(&mut sequence_bytes);
        }

        let output_count = encode_varint(self.vout.len() as u64);
        println!("{} = {:?}", self.vout.len() , output_count );
        v.append(&mut output_count.to_vec());

        for i in &self.vout {
            let mut amount = i.value.to_le_bytes().to_vec();
            println!("{} = {:?}",i.value ,amount );
            v.append(&mut amount);

            let mut scriptpubkey_size = encode_varint(i.scriptpubkey.len() as u64);
            println!("{} = {:?}",i.scriptpubkey.len() ,scriptpubkey_size );
            v.append(&mut scriptpubkey_size);

            let mut scriptpubkey_bytes = i.scriptpubkey.as_bytes().to_vec();
            println!("{} = {:?}",i.scriptpubkey ,scriptpubkey_bytes );
            v.append(&mut scriptpubkey_bytes);
        }

        let mut locktime_bytes = self.locktime.to_le_bytes().to_vec();
        println!("{} = {:?}",self.locktime ,locktime_bytes );
        v.append(&mut locktime_bytes);

        v
    }
    
}
