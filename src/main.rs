mod tx;
mod interpreter;

use std::{collections::HashSet, fs, io, vec};

use crate::tx::dsha256;

// use crate::tx;



fn main() {
    let mut tx_vec: Vec<tx::btctx> = Vec::new();

    let paths = fs::read_dir("mempool/").unwrap();
    // let paths = fs::read_dir("serialize/").unwrap();
    // let paths = fs::read_dir("p2pkh/").unwrap();
    // let paths = fs::read_dir("multi_input_p2pkh/").unwrap();
    // let paths = fs::read_dir("multi_input_p2wpkh/").unwrap();

    for path in paths {
        // println!("Name: {}", path.unwrap().path().display());
        let path1 = path.unwrap().path();
        let file  = fs::File::open(&path1).unwrap();
        let filename = path1.file_name().unwrap().to_str().unwrap();
        let reader = io::BufReader::new(file);
        let mut btc_tx: tx::btctx = serde_json::from_reader(reader).unwrap();

        btc_tx.filename = Some (filename.to_string());
        btc_tx.is_verified = Some(false);

        
        let dummy = btc_tx.serialize_tx();        
        let txid = dsha256(dummy);
        let temp: String = txid.to_vec().iter().rev().map(|val| format!("{:02x}",*val)).collect();
        btc_tx.txid = Some(temp);
        
        

        // let hex_dummy = hex::encode(dummy.clone());
        // println!("serialied tx {:?}",hex_dummy);
        // btc_tx.serializedtx = Some(hex_dummy);

        // let txidhash = {
        //     let mut hasher = Sha256::new();
        //     txid.reverse();
        //     hasher.update(&txid);
        //     let hash = hasher.finalize();
        //     format!("{:x}",hash)
        // };
        // println!("filename =  {}",txidhash);
        // assert!(txidhash == filename);   // Change and implement this by removing .json from filename

        
        btc_tx = interpreter::verify(btc_tx);

        tx_vec.push(btc_tx);
    }

    // {
    //     let mut set: HashSet<String> = HashSet::new();
    //     for i in &tx_vec {
    //         for j in &i.vin {
    //             // let operator_string = &j.prevout.scriptpubkey_asm;
    //             // let operator_string = &j.prevout.scriptpubkey_type;
    //             let operator_string = &j.scriptsig_asm;
    //             let words: Vec<&str> = operator_string.as_str().split_whitespace().collect();
    //             for word in words {
    //                 if word.len()<30 {
    //                     set.insert(word.to_string());
    //                 }
    //             }
    //         }
    //     }
    //     for word in set {
    //         println!("{}",word);
    //     }
    // }

    let mut count = 0;
    let mut p2pkh = 0;
    let mut p2wpkh = 0;

    // let mut verified_tx_with_ds: Vec<tx::btctx> = Vec::new();
    let mut verified_tx: Vec<tx::btctx> = Vec::new();
    

    let mut outputset: HashSet<String> = HashSet::new();

    for i in &tx_vec {
        if i.is_verified==Some(true) {
            // count+=1;
            // if i.vin[0].prevout.scriptpubkey_type=="p2pkh" {
            //     p2pkh+= 1;
            // };
            // if i.vin[0].prevout.scriptpubkey_type=="v0_p2wpkh" {
            //     p2wpkh+=1;
            // };

            verified_tx.push(i.clone());
            outputset.insert(i.txid.as_ref().unwrap().clone());
        };
    }

    // {
        // let mut inputset: HashSet<String> = HashSet::new();
        // for i in verified_tx {
        //     outputset.insert(i.txid.unwrap());
        //     for j in i.vin {
        //         inputset.insert(j.txid);
        //     }
        // }
        // println!("inputset size = {}",inputset.len());
        // println!("outputset size = {}",outputset.len());
        // let mut common = 0;
        // for x in inputset.intersection(&outputset) {
        //     common += 1;
        // }
        // println!("num of common elements = {}",common);
    // }

    let mut verified_tx_2: Vec<tx::btctx> = Vec::new();
    for mut i in verified_tx {
        for j in &i.vin {
            if outputset.contains(&j.txid) {
                i.is_verified = Some(false);
            }
        }        
        if i.is_verified == Some(true) {
            verified_tx_2.push(i);
        }
    }


    for i in &mut verified_tx_2 {
        if i.is_verified==Some(true) {
            count+=1;
            if i.vin[0].prevout.scriptpubkey_type=="p2pkh" {
                p2pkh+= 1;
            };
            if i.vin[0].prevout.scriptpubkey_type=="v0_p2wpkh" {
                p2wpkh+=1;
            };
        };
        let dummy = i.wserialize_tx();
        let wtxid =  dsha256(dummy.clone());
        let temp: String = wtxid.to_vec().iter().rev().map(|val| format!("{:02x}",*val)).collect();
        i.wtxid = Some(temp);

        // println!("{:#?}",i);

    }
    
    // println!("{}",count);
    // println!("{}",p2pkh);
    // println!("{}",p2wpkh);

    verified_tx_2.sort_by(|a, b| {

        let ratio_a = (a.fee.unwrap() as f64) / a.weight.unwrap() as f64;
        let ratio_b = (b.fee.unwrap() as f64) / b.weight.unwrap() as f64;

        a.feerate.unwrap().total_cmp(&b.feerate.unwrap())
    });
    
    verified_tx_2.reverse();

    for i in &verified_tx_2 {
        // println!("{:#?}",i.feerate);
    }

//    {  // Double spending code
//         let mut inputtxs = 0 ;
//         {
//             let mut set: HashSet<String> = HashSet::new();
//             for i in &mut verified_tx_with_ds {
//                 for j in &i.vin {                    
//                     let mut s = String::from("");
//                     s = s + &j.txid;
//                     s = s + &j.vout.to_string();
//                     inputtxs = inputtxs + 1;
//                     if set.contains(&s)==false {
//                         set.insert(s);
//                     }
//                     else {
//                         println!("{:?}",i.filename);
//                         i.is_verified=Some(false);
//                     }
//                 }
//             }
//             println!("{}",inputtxs);
//             println!("{}",set.len());
//         }
//     }

    let mut maxweight = 4000000-712;
    let mut totalfee = 0;

    let mut verified_tx_3: Vec<tx::btctx> = Vec::new();

    for i in verified_tx_2 {
        if i.weight.unwrap() <= maxweight {
            maxweight -= i.weight.unwrap();
            totalfee += i.fee.unwrap();
            verified_tx_3.push(i);
        }
    }

    

    // println!("totalfee = {}",totalfee);
    // println!("total transactions = {}",verified_tx_3.len());
    // println!("weight = {}",4000000 - 712 - maxweight);

    let mut wtxids: Vec<Vec<u8>> = Vec::new();


    let coinbase_wtxid = String::from("0000000000000000000000000000000000000000000000000000000000000000"); 
    let witness_reserved_value = hex::decode(&coinbase_wtxid).unwrap();
    wtxids.push(hex::decode(&coinbase_wtxid).unwrap());

    for i in verified_tx_3.clone() {
        wtxids.push(hex::decode(i.wtxid.unwrap()).unwrap());
    }



    let witness_root_hash: Vec<u8> = tx::merkle_root(wtxids.clone());
    // let witness_root_hash: Vec<u8> = tx::merkle_root(wtxids.clone());
    let mut sum= Vec::new();
    sum.extend_from_slice(&witness_root_hash);
    sum.extend_from_slice(&witness_reserved_value);
    let wtxid_commitment = dsha256(sum);

    let mut coinbase = tx::coinbase(totalfee,hex::encode(wtxid_commitment));

    let dummy = coinbase.serialize_tx();        
    let txid = dsha256(dummy);
    let temp: String = txid.to_vec().iter().rev().map(|val| format!("{:02x}",*val)).collect();
    coinbase.txid = Some(temp);

    let dummy = coinbase.wserialize_tx();        

    // println!("{:#?}",coinbase);


    let mut txids: Vec<Vec<u8>> = Vec::new();

    txids.push(hex::decode(coinbase.txid.unwrap()).unwrap());

    for i in verified_tx_3.clone() {
        txids.push(hex::decode(i.txid.unwrap()).unwrap());
    }

    let mut reverse_txids: Vec<Vec<u8>> = Vec::new();
    for mut i in txids.clone() {
        i.reverse();
        reverse_txids.push(i);
    }
    // println!("txids  = {:#?}",reverse_txids);
    
    // let merkle_root: Vec<u8> = tx::merkleroot(reverse_txids.clone()).first().unwrap().to_vec();
    let merkle_root: Vec<u8> = tx::merkle_root(reverse_txids.clone());
    // println!("merkle root = {:?}",hex::encode(merkle_root));


    let block_header = tx::block_header(merkle_root.clone());

    println!("{}",hex::encode(block_header));
    
    println!("{}",hex::encode(dummy));

    // for i in verified_tx_3 {
    //     let mut v = hex::decode(i.txid.unwrap()).unwrap();
    //     // v.reverse();

    //     println!("{}",hex::encode(v));
    // }

    for i in txids {
        println!("{}",hex::encode(i));
    }
    println!("merke root = {}",hex::encode(merkle_root));

}