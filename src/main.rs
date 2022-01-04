
mod storage;

use std::env;
use std::io::{Read};
use std::fs::{OpenOptions};

#[derive(PartialEq)]
enum IterArgs {
    Unknown,
    PrivateKey,
    StorageFile,
}

fn parse_app_args(args: &Vec<String>) -> (String, String) {

    let mut storage_file = String::new(); 
    let mut pk_file = String::new();

    if args.len() != 0 {

        let mut iter: IterArgs = IterArgs::Unknown; 
        for line in args {

            if iter == IterArgs::StorageFile {
                storage_file = String::from(line);
                iter = IterArgs::Unknown;
            }
            else if iter == IterArgs::PrivateKey {
                pk_file = String::from(line);
                iter = IterArgs::Unknown;
            }

            if line == "-s" { // storage file location
                iter = IterArgs::StorageFile;
            } else if line == "-pk" { // private key file location                
                iter = IterArgs::PrivateKey;
            }
        }
    }

    (storage_file, pk_file)
}

const APP_VERSION: &str = "0.0.1"; // v.0.0.1 from 04.01.2022 

fn main() -> std::io::Result<()> {

    println!("Application version is {}", APP_VERSION);
    
    let (storage_file, pk_file) = parse_app_args(&env::args().collect());

    let mut key_file = OpenOptions::new()
        .read(true)
        .open(pk_file)
        .unwrap();

    let mut spk = String::new();
    key_file.read_to_string(&mut spk)?;

    let store = storage::Storage::new(&storage_file, spk);
    
    // test data inputs and output
    store.read_record();
    store.write_record("root admin1234");
    store.write_record("test123 testpass123");   

    Ok(())
}