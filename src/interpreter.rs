// - Operators to be implemented
// 		- OP_0
// 		- OP_PUSHNUM_1
// 		- OP_PUSHBYTES_20
// 		- OP_PUSHBYTES_32
// 		- OP_HASH160
// 		- OP_EQUAL
// 		- OP_CHECKSIG
// 		- OP_DUP
// 		- OP_EQUALVERIFY
// 		- OP_PUSHBYTES_72
// 		- OP_PUSHBYTES_70
// 		- OP_PUSHBYTES_33
// 		- OP_PUSHBYTES_71


use crate::tx::dsha256;
use crate::tx::h160;
use crate::tx::txin;

use crate::tx::btctx;
use libsecp256k1::{PublicKey,Signature,Message,verify as txverify,PublicKeyFormat};


#[derive(Debug)]
pub struct Stack<T> {
    stack: Vec<T>,
}
  
impl<T> Stack<T> {
    pub fn new() -> Self {
        Stack { stack: Vec::new() }
    }

    pub fn length(&self) -> usize {
        self.stack.len()
    }

    pub fn pop(&mut self) -> Option<T> {
        self.stack.pop()
    }

    pub fn push(&mut self, item: T) {
        self.stack.push(item)
    }

    // pub fn is_empty(&self) -> bool {
    //     self.stack.is_empty()
    // }

    pub fn peek(&self) -> Option<&T> {
        self.stack.last()
    }

    
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

pub fn verify(mut btc_tx:btctx) -> btctx{

    for i in &btc_tx.vin {
        if &i.prevout.scriptpubkey_type == "p2sh" 
            || &i.prevout.scriptpubkey_type=="v1_p2tr"
            || &i.prevout.scriptpubkey_type=="v0_p2wsh" {
            btc_tx.is_verified = Some(false);
            // println!("ivsverified = {}", btc_tx.is_verified.unwrap());
            break;
        }
        btc_tx.is_verified = Some(true);

        if &i.prevout.scriptpubkey_type == "p2pkh" {

            let scriptsig = &i.scriptsig_asm;
            let scriptsig: Vec<&str> = scriptsig.as_str().split_whitespace().collect();

            let scriptpubkey = &i.prevout.scriptpubkey_asm;
            let scriptpubkey: Vec<&str> = scriptpubkey.as_str().split_whitespace().collect();


            let mut st: Stack<Vec<u8>> = Stack::new();
            for j in scriptsig {
                if j.len() > 15 {
                    let j = hex::decode(j).unwrap();
                    st.push(j);
                    // println!("{} => {:?}", st.length(),hex::encode(st.peek().unwrap()));
                }
            }

            for j in scriptpubkey {
                if j.len() > 15 {
                    let i = hex::decode(j).unwrap();
                    st.push(i);
                }
                else {
                    match j {
                        "OP_0" =>  {
                            let v: Vec<u8> = Vec::new();
                            st.push(v);
                        },
                        "OP_PUSHNUM_1" =>  {
                            let mut v: Vec<u8> = Vec::new();
                            v.push(1);
                            st.push(v);
                        },
                        "OP_PUSHBYTES_20" =>  {
                            {};
                        },
                        "OP_PUSHBYTES_32" =>  {
                            {};
                        },
                        "OP_DUP" =>  {
                            if st.length() > 0 {
                                let v = st.peek().unwrap();
                                st.push(v.to_vec());
                            } else {
                                btc_tx.is_verified = Some(false);
                                println!("OP_DUP");                                
                                break;
                            }
                        },
                        "OP_HASH160" =>  {
                            if st.length() > 0 {
                                let v = st.pop().unwrap();
                                let hash: Vec<u8> = h160(v);                            
                                st.push(hash);
                            } else {
                                btc_tx.is_verified = Some(false);
                                println!("OP_HASH160");                                
                                break;
                            }
                        },
                        "OP_EQUAL" =>  {
                            if st.length() >=2 {
                                let v1=st.pop().unwrap();
                                let v2=st.pop().unwrap();
                                if v1==v2 {
                                    let mut v: Vec<u8> = Vec::new();
                                    v.push(1);
                                    st.push(v);
                                } else {
                                    println!("OP_EQUAL1");  
                                    println!("{:?}",v1);                              
                                    println!("{:?}",v2);                              
                                    btc_tx.is_verified = Some(false);
                                    break;
                                }
                            } else {
                                println!("OP_EQUAL2");                                
                                btc_tx.is_verified = Some(false);
                                break;
                            }
                            
                        },
                        "OP_EQUALVERIFY" =>  {
                            if st.length() >=2 {
                                let v1=st.pop().unwrap();
                                let v2=st.pop().unwrap();
                                if v1!=v2 {                                    
                                    println!("OP_EQUALVERIFY1");  
                                    // println!("filename : {:?}",btc_tx.filename);
                                    println!("{:?}",v1);                              
                                    println!("{:?}",v2);                            
                                    btc_tx.is_verified = Some(false);
                                    break;
                                }
                            } else {
                                println!("OP_EQUALVERIFY2");                                
                                btc_tx.is_verified = Some(false);
                                break;
                            }
                        },
                        "OP_CHECKSIG" =>  {
                            if st.length() >=2 {
                                
                                let publickey = st.pop().unwrap();
                                let signature = st.pop().unwrap();
                                let hashtype = *signature.last().unwrap() as u32;


                                let mut btc_tx2 = checksig(btc_tx.clone(), i.clone());
                                btc_tx2.append(&mut hashtype.to_le_bytes().to_vec());

                                // println!("serialized cleaned tx {}",encode(btc_tx2.clone()));

                                let hash = dsha256(btc_tx2);

                                // println!("message hash is {}",encode(hash.to_vec()));
                                // println!("public key is {}",encode(publickey.to_vec()));
                                // println!("filename : {:?}",btc_tx.filename);



                                let message = Message::parse_slice(&hash.as_slice()).unwrap();
                                let signature = Signature::parse_der_lax(&signature.as_slice()).unwrap();
                                let publickey = PublicKey::parse_slice(&publickey.as_slice() , Some(PublicKeyFormat::Compressed));

                                match publickey {
                                    Ok(publickey) => {
                                        let result = txverify(&message, &signature, &publickey);
                                        btc_tx.is_verified = Some(result);
                                    },
                                    Err(e) => {
                                        btc_tx.is_verified=Some(false);
                                        // println!("filename : {:?}",btc_tx.filename);
                                        // println!("{}",e);
                                    }
                                }

                                

                                // println!("Verification status = {}", result);
                            } else {
                                println!("OP_CHECKSIG");                                
                                btc_tx.is_verified = Some(false);
                                break;
                            }
                        },
                        _ => {
                            println!("Invalid opcode found");
                        },
                    }
                }
                // println!("{} => {:?}", st.length(),st.peek());
                // println!("{} => {:?}", st.length(),hex::encode(st.peek().unwrap()));
            }
            // println!("{:#?}",st.peek());
            // println!("ivsverified = {}", btc_tx.is_verified.unwrap());
        }
        else if i.prevout.scriptpubkey_type == "v0_p2wpkh"{


            let scriptpubkey = &i.prevout.scriptpubkey_asm;
            let scriptpubkey: Vec<&str> = scriptpubkey.as_str().split_whitespace().collect();
            let mut pubkey = "";
            for j in scriptpubkey {
                if j.len() > 15 {
                    pubkey = j;
                }
            }

            let scriptpubkey = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 ".to_owned()+pubkey+" OP_EQUALVERIFY OP_CHECKSIG";
            let scriptpubkey: Vec<&str> = scriptpubkey.as_str().split_whitespace().collect();

            let scriptsig =  i.witness.as_ref().unwrap();
            
            let mut st: Stack<Vec<u8>> = Stack::new();
            for j in scriptsig {
                if j.len() > 15 {
                    let j = hex::decode(j.as_str()).unwrap();
                    st.push(j);
                }
                // println!("{} => {:?}", st.length(),hex::encode(st.peek().unwrap()));
            }

            for j in scriptpubkey {
                if j.len() > 15 {
                    let i = hex::decode(j).unwrap();
                    st.push(i);
                }
                else {
                    match j {
                        "OP_0" =>  {
                            let v: Vec<u8> = Vec::new();
                            st.push(v);
                        },
                        "OP_PUSHNUM_1" =>  {
                            let mut v: Vec<u8> = Vec::new();
                            v.push(1);
                            st.push(v);
                        },
                        "OP_PUSHBYTES_20" =>  {
                            {};
                        },
                        "OP_PUSHBYTES_32" =>  {
                            {};
                        },
                        "OP_DUP" =>  {
                            if st.length() > 0 {
                                let v = st.peek().unwrap();
                                st.push(v.to_vec());
                            } else {
                                btc_tx.is_verified = Some(false);
                                println!("OP_DUP");                                
                                break;
                            }
                        },
                        "OP_HASH160" =>  {
                            if st.length() > 0 {
                                let v = st.pop().unwrap();                           
                                let hash: Vec<u8> = h160(v);                             
                                st.push(hash);
                            } else {
                                btc_tx.is_verified = Some(false);
                                println!("OP_HASH160");                                
                                break;
                            }
                        },
                        "OP_EQUAL" =>  {
                            if st.length() >=2 {
                                let v1=st.pop().unwrap();
                                let v2=st.pop().unwrap();
                                if v1==v2 {
                                    let mut v: Vec<u8> = Vec::new();
                                    v.push(1);
                                    st.push(v);
                                } else {
                                    println!("OP_EQUAL1");  
                                    println!("{:?}",v1);                              
                                    println!("{:?}",v2);                              
                                    btc_tx.is_verified = Some(false);
                                    break;
                                }
                            } else {
                                println!("OP_EQUAL2");                                
                                btc_tx.is_verified = Some(false);
                                break;
                            }
                            
                        },
                        "OP_EQUALVERIFY" =>  {
                            if st.length() >=2 {
                                let v1=st.pop().unwrap();
                                let v2=st.pop().unwrap();
                                if v1!=v2 {
                                    println!("OP_EQUALVERIFY1");  
                                    // println!("filename : {:?}",btc_tx.filename);
                                    println!("{:?}",v1);                              
                                    println!("{:?}",v2);                            
                                    btc_tx.is_verified = Some(false);
                                    break;
                                }
                            } else {
                                println!("OP_EQUALVERIFY2");                                
                                btc_tx.is_verified = Some(false);
                                break;
                            }
                        },
                        "OP_CHECKSIG" =>  {
                            if st.length() >=2 {
                                
                                let publickey = st.pop().unwrap();
                                let signature = st.pop().unwrap();

                                let hashtype = *signature.last().unwrap() as u32;


                                let mut btc_tx2 = wchecksig(btc_tx.clone(), i.clone());
                                btc_tx2.append(&mut hashtype.to_le_bytes().to_vec());

                                // println!("serialized cleaned tx {}",encode(btc_tx2.clone()));

                                let hash = dsha256(btc_tx2);

                                // println!("message hash is {}",encode(hash.to_vec()));

                                let message = Message::parse_slice(&hash.as_slice()).unwrap();
                                let signature = Signature::parse_der_lax(&signature.as_slice()).unwrap();
                                let publickey = PublicKey::parse_slice(&publickey.as_slice() , Some(PublicKeyFormat::Compressed));


                                match publickey {
                                    Ok(publickey) => {
                                        let result = txverify(&message, &signature, &publickey);
                                        btc_tx.is_verified = Some(result);
                                    },
                                    Err(e) => {
                                        btc_tx.is_verified=Some(false);
                                        // println!("filename : {:?}",btc_tx.filename);
                                        // println!("{}",e);
                                        // println!("{}",&btc_tx.is_verified);
                                    }
                                }


                                // println!("Verification status = {}", result);
                            } else {
                                println!("OP_CHECKSIG");                                
                                btc_tx.is_verified = Some(false);
                                break;
                            }
                        },
                        _ => {
                            println!("Invalid opcode found");
                        },
                    }
                }
                // println!("{} => {:?}", st.length(),st.peek());
                // println!("{} => {:?}", st.length(),hex::encode(st.peek().unwrap()));
            }
            // println!("{:#?}",st.peek());
            // println!("ivsverified = {}", btc_tx.is_verified.unwrap());
        }
    };
    btc_tx
}



pub fn checksig<'a> (mut btc_tx:  btctx , txin : txin) ->  Vec<u8> {
    for i in &mut btc_tx.vin {
        if *i.txid != txin.txid {
            i.scriptsig = String::new();
        } else {
            i.scriptsig = i.prevout.scriptpubkey.clone();
        }          
    }
    let v: Vec<u8> = btc_tx.serialize_tx();
    v
}


pub fn wchecksig<'a> (btc_tx:  btctx , txin : txin) ->  Vec<u8> {


    let mut preimage: Vec<u8> = Vec::new();

    let mut version = btc_tx.version.to_le_bytes().to_vec();

    let mut inputs: Vec<u8> = Vec::new();
    for i in &btc_tx.vin {
        let mut txid = hex::decode(&i.txid).unwrap();
        txid.reverse();
        inputs.append(&mut txid);

        let mut vout_bytes = i.vout.to_le_bytes().to_vec();
        inputs.append(&mut vout_bytes);
    }
    let mut inputshash = dsha256(inputs);

    let mut sequences: Vec<u8> = Vec::new();
    for i in &btc_tx.vin {
        let mut sequence_bytes = i.sequence.to_le_bytes().to_vec();
        sequences.append(&mut sequence_bytes);
    }
    let mut sequenceshash = dsha256(sequences);

    let mut input: Vec<u8> = Vec::new();
    {
        let mut txid = hex::decode(&txin.txid).unwrap();
        txid.reverse();
        input.append(&mut txid);

        let mut vout_bytes = txin.vout.to_le_bytes().to_vec();
        input.append(&mut vout_bytes);
    }

    let mut scriptcode: Vec<u8> = Vec::new();
    {
        let scriptpubkey = txin.prevout.scriptpubkey_asm;
        let scriptpubkey: Vec<&str> = scriptpubkey.as_str().split_whitespace().collect();
        let mut pubkey = "";
        for j in scriptpubkey {
            if j.len() > 15 {
                pubkey = j;
            }
        }

        let scriptpubkey = "1976a914".to_owned()+pubkey+"88ac";
        let scriptpubkey = "1976a914".to_owned()+pubkey+"88ac";
        scriptcode.append(&mut hex::decode(scriptpubkey).unwrap());
    }


    let mut amount: Vec<u8> = Vec::new();
    {
        let mut txinamount = txin.prevout.value.to_le_bytes().to_vec();
        amount.append(&mut txinamount);

    }

    let mut sequence: Vec<u8> = Vec::new();
    {
        let mut sequence_bytes = txin.sequence.to_le_bytes().to_vec();
        sequence.append(&mut sequence_bytes);
    }

    let mut outputs: Vec<u8> = Vec::new();
    for i in &btc_tx.vout{
        let mut amount = i.value.to_le_bytes().to_vec();
        outputs.append(&mut amount);

        let mut scriptpubkey_size = encode_varint((i.scriptpubkey.len()/2) as u64);
        outputs.append(&mut scriptpubkey_size);

        let mut scriptpubkey_bytes = hex::decode(&i.scriptpubkey).unwrap();
        outputs.append(&mut scriptpubkey_bytes);
    }
    let mut outputshash = dsha256(outputs);

    let mut locktime: Vec<u8> = Vec::new();
    {
        let mut locktime_bytes = btc_tx.locktime.to_le_bytes().to_vec();        
        locktime.append(&mut locktime_bytes);
    }

    preimage.append(&mut version);
    preimage.append(&mut inputshash);
    preimage.append(&mut sequenceshash);
    preimage.append(&mut input);
    preimage.append(&mut scriptcode);
    preimage.append(&mut amount);
    preimage.append(&mut sequence);
    preimage.append(&mut outputshash);
    preimage.append(&mut locktime);




    preimage
    
}