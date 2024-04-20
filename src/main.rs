mod tx;
use std::{fs, io};

// use crate::tx::btctx;


fn main() {
    let mut tx_vec: Vec<tx::btctx> = Vec::new();
    let paths = fs::read_dir("serialize/").unwrap();
    for path in paths {
        // println!("Name: {}", path.unwrap().path().display());
        let path1 = path.unwrap().path();
        let file  = fs::File::open(&path1);

        let file = match file {
            Ok(file) => file,
            Err(error) => panic!("Problem opening the file: {:#?}", &path1),
        };
        let reader = io::BufReader::new(file);

        let btc_tx: Result<tx::btctx, serde_json::Error> = serde_json::from_reader(reader);

        let empty_btctx = tx::btctx {
            txid : Some(String::from("")),
            version : 1002322352,
            locktime: 3,
            vin : vec![],
            vout: vec![],
        };

        match btc_tx {
            Ok(tx) => 
            {
                tx_vec.push(tx);
            }, 
            Err(err) => {println!("{:#?} {:#?}",err,&path1)}
        }

        let btc_tx = tx_vec.last().unwrap();
        // println!("The version is {} ", btc_tx.version);
        // println!("The length of inputs is {}", btc_tx.vin.len());

        let dummy = tx_vec.last().unwrap().serialize_tx();        
        println!("{:?}",dummy);
        println!("");
        println!("");
        println!("");
        println!("{:#?}",btc_tx);

        // println!("The version is {} ", empty_btctx.version);
        // println!("The length of inputs is {}", empty_btctx.vin.len());
        // let dummy = empty_btctx.serialize_tx();        
        // println!("{:#?}",dummy);
        // println!("");
        
    }

    
    // for i in tx_vec {
    //     println!("{:#?}",i);
    // }

}