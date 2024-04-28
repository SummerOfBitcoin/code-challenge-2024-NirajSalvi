extern crate serde_derive;
use std::{alloc::System, clone, time::{SystemTime, UNIX_EPOCH}};

use num_bigint::BigUint;
use ripemd::Ripemd160;
use serde_derive::Deserialize;
use sha2::{Sha256,Digest};


#[derive(Deserialize, Debug, Clone)]
pub struct btctx {
    pub txid : Option<String>,
    pub wtxid : Option<String>,
    pub filename: Option<String>,
    pub serializedtx : Option<String>,
    pub is_verified: Option<bool>,
    pub version: u32,
    pub locktime: u32,
    pub vin : Vec<txin>,
    pub vout: Vec<txout>,
    pub weight: Option<u64>,
    pub fee: Option<u64>,
    pub feerate: Option<f64>
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
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

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct txout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

fn encode_varint(value: u64) -> Vec<u8> {
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


pub fn dsha256(data: Vec<u8>) -> Vec<u8>{
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();
    hash.to_vec()
}

pub fn h160(data: Vec<u8>) -> Vec<u8>{
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let mut hasher = Ripemd160::new();
    hasher.update(hash);
    let hash = hasher.finalize();
    hash.to_vec()
}

impl btctx {

    pub fn serialize_tx(&mut self) -> Vec<u8> {

        let mut inputsats: u64 = 0;
        let mut outputsats: u64 = 0;

        let mut v: Vec<u8> = Vec::new();
        
        let mut version_bytes = self.version.to_le_bytes().to_vec();
        // println!("{} = {:?}",self.version ,version_bytes );
        v.append(&mut version_bytes);

        let input_count = encode_varint(self.vin.len() as u64);
        // println!("{} = {:?}",self.vin.len() ,input_count );
        v.append(&mut input_count.to_vec());
        // let le_bytes = value.to_le_bytes().to_vec();

        for i in &self.vin {
            let mut txid = hex::decode(&i.txid).unwrap();
            // println!("{} = {:?}",i.txid ,txid );
            txid.reverse();
            v.append(&mut txid);

            let mut vout_bytes = i.vout.to_le_bytes().to_vec();
            // println!("{} = {:?}",i.vout , vout_bytes);
            v.append(&mut vout_bytes);

            let mut scriptsig_size = encode_varint((i.scriptsig.len()/2) as u64); // Send 0 if cleaned
            // println!("scriptsig len {} = {:?}", i.scriptsig.len(), scriptsig_size);
            v.append(&mut scriptsig_size);

            let mut scriptsig_bytes =hex::decode(&i.scriptsig).unwrap();
            // println!("{} = {:?}", i.scriptsig, scriptsig_bytes);
            // println!("{}", i.scriptsig);
            v.append(&mut scriptsig_bytes);

            let mut sequence_bytes = i.sequence.to_le_bytes().to_vec();
            // println!("{} = {:?}", i.sequence, sequence_bytes );
            v.append(&mut sequence_bytes);

            inputsats += i.prevout.value;
        }

        
        let output_count = encode_varint(self.vout.len() as u64);
        // println!("{} = {:?}", self.vout.len() , output_count );
        v.append(&mut output_count.to_vec());

        for i in &self.vout {
            let mut amount = i.value.to_le_bytes().to_vec();
            // println!("{} = {:?}",i.value ,amount );
            v.append(&mut amount);

            let mut scriptpubkey_size = encode_varint((i.scriptpubkey.len()/2) as u64);
            // println!("{} = {:?}",i.scriptpubkey.len() ,scriptpubkey_size );
            v.append(&mut scriptpubkey_size);

            let mut scriptpubkey_bytes = hex::decode(&i.scriptpubkey).unwrap();
            // println!("{} = {:?}",i.scriptpubkey ,scriptpubkey_bytes );
            v.append(&mut scriptpubkey_bytes);

            outputsats += i.value;
        }

        let mut locktime_bytes = self.locktime.to_le_bytes().to_vec();
        // println!("{} = {:?}",self.locktime ,locktime_bytes );
        v.append(&mut locktime_bytes);

        
        self.weight = Some(v.len() as u64);

        // println!("{}",inputsats);
        // println!("{}",outputsats);

        self.fee = Some(inputsats-outputsats);
        self.feerate = Some(self.fee.unwrap() as f64/self.weight.unwrap() as f64);

        v
    }


    pub fn wserialize_tx(&mut self) -> Vec<u8> {

        let tx_types: Vec<String> = self.vin.iter().map(|vin| vin.prevout.scriptpubkey_type.clone()).collect(); 
        let is_segwit =tx_types.contains(&String::from("v0_p2wpkh"));
        let mut v: Vec<u8> = Vec::new();

        let mut weight = 0;
        
        let mut version_bytes = self.version.to_le_bytes().to_vec();
        // println!("{} = {:?}",self.version ,version_bytes );
        weight += version_bytes.len()*4 ;
        v.append(&mut version_bytes);
        

        if is_segwit {
            let mut marker = encode_varint(00);
            // println!("{} = {:?}",00 ,marker );
            weight += marker.len();
            v.append(&mut marker);

            let mut flag = encode_varint(01);
            weight += flag.len();
            v.append(&mut flag);
        }

        let input_count = encode_varint(self.vin.len() as u64);
        // println!("{} = {:?}",self.vin.len() ,input_count );
        weight += input_count.len()*4;
        v.append(&mut input_count.to_vec());

        // let le_bytes = value.to_le_bytes().to_vec();

        for i in &self.vin {
            let mut txid = hex::decode(&i.txid).unwrap();
            // println!("{} = {:?}",i.txid ,txid );
            txid.reverse();
            weight += txid.len()*4;
            v.append(&mut txid);

            let mut vout_bytes = i.vout.to_le_bytes().to_vec();
            // println!("{} = {:?}",i.vout , vout_bytes);
            weight += vout_bytes.len()*4;
            v.append(&mut vout_bytes);

            let mut scriptsig_size = encode_varint((i.scriptsig.len()/2) as u64); // Send 0 if cleaned
            // println!("scriptsig len {} = {:?}", i.scriptsig.len(), scriptsig_size);
            weight += scriptsig_size.len()*4;
            v.append(&mut scriptsig_size);

            let mut scriptsig_bytes =hex::decode(&i.scriptsig).unwrap();
            // println!("{} = {:?}", i.scriptsig, scriptsig_bytes);
            // println!("{}", i.scriptsig);
            weight += scriptsig_bytes.len()*4;
            v.append(&mut scriptsig_bytes);

            let mut sequence_bytes = i.sequence.to_le_bytes().to_vec();
            // println!("{} = {:?}", i.sequence, sequence_bytes );
            weight += sequence_bytes.len()*4;
            v.append(&mut sequence_bytes);

        }


        
        let output_count = encode_varint(self.vout.len() as u64);
        // println!("{} = {:?}", self.vout.len() , output_count );
        weight += output_count.len()*4;
        v.append(&mut output_count.to_vec());

        for i in &self.vout {
            let mut amount = i.value.to_le_bytes().to_vec();
            // println!("{} = {:?}",i.value ,amount );
            weight += amount.len()*4;
            v.append(&mut amount);

            let mut scriptpubkey_size = encode_varint((i.scriptpubkey.len()/2) as u64);
            // println!("{} = {:?}",i.scriptpubkey.len() ,scriptpubkey_size );
            weight += scriptpubkey_size.len()*4;
            v.append(&mut scriptpubkey_size);

            let mut scriptpubkey_bytes = hex::decode(&i.scriptpubkey).unwrap();
            // println!("{} = {:?}",i.scriptpubkey ,scriptpubkey_bytes );
            weight += scriptpubkey_bytes.len()*4;
            v.append(&mut scriptpubkey_bytes);

        }

        if is_segwit { 
            for i in &self.vin 
            {

                if i.witness != None {
                    // let mut stacksize = encode_varint(02);  
                    let mut stacksize = encode_varint(i.witness.clone().unwrap().len() as u64);
                    weight += stacksize.len();  
                    v.append(&mut stacksize);


                    let vec = i.witness.clone().unwrap();
                    for j in vec {

                        let mut itemsize = encode_varint((j.len()/2) as u64);
                        weight += itemsize.len();
                        v.append(&mut itemsize);


                        let mut item_bytes =hex::decode(&j).unwrap();
                        weight += item_bytes.len();
                        v.append(&mut item_bytes);

                    }
                }
                else {
                    let mut stacksize = encode_varint(00);
                    weight += stacksize.len();
                    v.append(&mut stacksize);
                }
            }
        }

        let mut locktime_bytes = self.locktime.to_le_bytes().to_vec();
        // println!("{} = {:?}",self.locktime ,locktime_bytes );
        weight += locktime_bytes.len()*4;
        v.append(&mut locktime_bytes);

        // println!("weight = {}",weight);

        self.weight = Some(weight as u64);
        // self.weight = Some(v.len() as u32);

        self.feerate = Some(self.fee.unwrap() as f64/self.weight.unwrap() as f64);


        v
    }


    pub fn coinbaseserialize_tx(&mut self) -> Vec<u8> {

        let mut v: Vec<u8> = Vec::new();

        let mut weight = 0;
        
        let mut version_bytes = self.version.to_le_bytes().to_vec();
        // println!("{} = {:?}",self.version ,version_bytes );
        weight += version_bytes.len()*4 ;
        v.append(&mut version_bytes);
        

        if self.vin[0].witness != None {
            let mut marker = encode_varint(00);
            // println!("{} = {:?}",00 ,marker );
            weight += marker.len();
            v.append(&mut marker);

            let mut flag = encode_varint(01);
            weight += flag.len();
            v.append(&mut flag);
        }

        let input_count = encode_varint(self.vin.len() as u64);
        // println!("{} = {:?}",self.vin.len() ,input_count );
        weight += input_count.len()*4;
        v.append(&mut input_count.to_vec());

        // let le_bytes = value.to_le_bytes().to_vec();

        for i in &self.vin {
            let mut txid = hex::decode(&i.txid).unwrap();
            // println!("{} = {:?}",i.txid ,txid );
            txid.reverse();
            weight += txid.len()*4;
            v.append(&mut txid);

            let mut vout_bytes = i.vout.to_le_bytes().to_vec();
            // println!("{} = {:?}",i.vout , vout_bytes);
            weight += vout_bytes.len()*4;
            v.append(&mut vout_bytes);

            let mut scriptsig_size = encode_varint((i.scriptsig.len()/2) as u64); // Send 0 if cleaned
            // println!("scriptsig len {} = {:?}", i.scriptsig.len(), scriptsig_size);
            weight += scriptsig_size.len()*4;
            v.append(&mut scriptsig_size);

            let mut scriptsig_bytes =hex::decode(&i.scriptsig).unwrap();
            // println!("{} = {:?}", i.scriptsig, scriptsig_bytes);
            // println!("{}", i.scriptsig);
            weight += scriptsig_bytes.len()*4;
            v.append(&mut scriptsig_bytes);

            let mut sequence_bytes = i.sequence.to_le_bytes().to_vec();
            // println!("{} = {:?}", i.sequence, sequence_bytes );
            weight += sequence_bytes.len()*4;
            v.append(&mut sequence_bytes);

        }


        
        let output_count = encode_varint(self.vout.len() as u64);
        // println!("{} = {:?}", self.vout.len() , output_count );
        weight += output_count.len()*4;
        v.append(&mut output_count.to_vec());

        for i in &self.vout {
            let mut amount = i.value.to_le_bytes().to_vec();
            // println!("{} = {:?}",i.value ,amount );
            weight += amount.len()*4;
            v.append(&mut amount);

            let mut scriptpubkey_size = encode_varint((i.scriptpubkey.len()/2) as u64);
            // println!("{} = {:?}",i.scriptpubkey.len() ,scriptpubkey_size );
            weight += scriptpubkey_size.len()*4;
            v.append(&mut scriptpubkey_size);

            let mut scriptpubkey_bytes = hex::decode(&i.scriptpubkey).unwrap();
            // println!("{} = {:?}",i.scriptpubkey ,scriptpubkey_bytes );
            weight += scriptpubkey_bytes.len()*4;
            v.append(&mut scriptpubkey_bytes);

        }

        for i in &self.vin {

            if i.witness != None {
                let mut stacksize = encode_varint(01);                
                weight += stacksize.len();  
                v.append(&mut stacksize);


                let vec = i.witness.clone().unwrap();
                for j in vec {

                    let mut itemsize = encode_varint((j.len()/2) as u64);
                    weight += itemsize.len();
                    v.append(&mut itemsize);


                    let mut item_bytes =hex::decode(&j).unwrap();
                    weight += item_bytes.len();
                    v.append(&mut item_bytes);

                }
            }
            else {
                let mut stacksize = encode_varint(00);
                weight += stacksize.len();
                v.append(&mut stacksize);
            }
        }
        

        let mut locktime_bytes = self.locktime.to_le_bytes().to_vec();
        // println!("{} = {:?}",self.locktime ,locktime_bytes );
        weight += locktime_bytes.len()*4;
        v.append(&mut locktime_bytes);

        // println!("weight = {}",weight);

        self.weight = Some(weight as u64);
        // self.weight = Some(v.len() as u32);

        self.feerate = Some(self.fee.unwrap() as f64/self.weight.unwrap() as f64);


        v
    }
}


pub fn coinbase(totalfee: u64 , wtxid_commitment: String) -> btctx {

    let txid =  String::from("0000000000000000000000000000000000000000000000000000000000000000") ;

    
    
    let outputtx = txout {
        scriptpubkey: String::from(""),
        scriptpubkey_asm: String::from(""),
        scriptpubkey_type: String::from(""),
        scriptpubkey_address: None,
        value: 0,
    };
    let mut vout: Vec<txout> = Vec::new();
    vout.push(outputtx.clone());
    vout.push(outputtx.clone());

    vout[0].value = totalfee;
    vout[0].scriptpubkey=String::from("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac");

    vout[1].value = 0;
    vout[1].scriptpubkey="6a24aa21a9ed".to_owned()+&wtxid_commitment;
    
    // let scriptpubkey = "1976a914".to_owned()+pubkey+"88ac";
    // "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"


    let s = String::from("0000000000000000000000000000000000000000000000000000000000000000");
    let mut witness: Vec<String> = Vec::new();
    witness.push(s);
    // let wit


    let inputtx = txin {
        txid,
        vout: 0xffffffff,
        prevout: outputtx.clone(),
        scriptsig: String::from("03233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100"),
        scriptsig_asm: String::from(""),
        witness: Some(witness),
        is_coinbase: false,
        sequence: 0xffffffff,
    };
    let mut vin: Vec<txin> = Vec::new();
    vin.push(inputtx);

    let wtxid =  String::from("0000000000000000000000000000000000000000000000000000000000000000") ;


    let coinbase = btctx{
        txid: None,
        wtxid: Some(wtxid),
        filename: None,
        serializedtx: None,
        is_verified: Some(true),
        version: 0,
        locktime: 0,
        vin,
        vout,
        weight: None,
        fee: None,
        feerate: None,
    };

    coinbase
}


pub fn merkle_root(mut root : Vec<Vec<u8>>) -> Vec<u8> {
    let mut result: Vec<Vec<u8>> = Vec::new();
    result.extend_from_slice(&root);

    while result.len()>1 {
        if(result.len()%2==1) {
            result.push(result.last().unwrap().clone());
        }
        let mut v = Vec::new();
        for i in (0..result.len()).step_by(2) {
            let mut first = result[i].clone();
            let mut second = result[i+1].clone();

            let mut sum = Vec::new();
            sum.append(&mut first);
            sum.append(&mut second);
            let hash = dsha256(sum);
            v.push(hash);
        }
        result = v;
    }

    result[0].clone()
}

pub fn block_header(merkle_root: Vec<u8>) -> Vec<u8> {
    
    let version_bytes: Vec<u8> = vec![0,0,0,4];
    
    let previous_block = hex::decode(String::from("0000000000000000000000000000000000000000000000000000000000000000")).unwrap();

    let timestamp = (SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs() as u32).to_le_bytes().to_vec();

    let bits = hex::decode(String::from("0000ffff00000000000000000000000000000000000000000000000000000000")).unwrap();


    for nonce in (0..u32::MAX) {

        let nonce = nonce.to_le_bytes();

        let mut result: Vec<u8> = Vec::new();

        result.extend_from_slice(&version_bytes);
        result.extend_from_slice(&previous_block);
        result.extend_from_slice(&merkle_root);
        result.extend_from_slice(&timestamp);
        result.extend_from_slice(&vec![0xff,0xff,0x00,0x1f]);
        result.extend_from_slice(&nonce);

        let mut hash = dsha256(result.clone());
        hash.reverse();

        let block_hash_num = BigUint::from_bytes_be(hash.as_slice());
        let target = BigUint::from_bytes_be(bits.as_slice());
        
        if block_hash_num.le(&target) {
            return result;
        }
    }

    vec![]
}
