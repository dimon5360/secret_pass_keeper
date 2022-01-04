
extern crate chrono;
extern crate crypto;
extern crate rand;
extern crate base64;

use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use rand::RngCore;

use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use std::io::BufReader;
use std::fs::{OpenOptions, File};

use std::io::prelude::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;

use ecies::{SecretKey, PublicKey};
use ecies::{decrypt, encrypt};

/**
 * Record presents the record whick contains a few fields:
 *  - id as identificator of record;
 *  - user login;
 *  - corresponding login user password;
 *  - timestamp as saving the record time
 *  - hash(login+password+timestamp).
 * 
 * Each block keeps in encrypted view.
 * Aes algorithm uses to encrypt records.
 * Aes secret key presents the hash SHA function result from common password.
*/

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    record: std::vec::Vec<u8>,
    timestamp: std::vec::Vec<u8>,
    hash: [u8; 32],
    key: [u8;32],
    iv: [u8;16]
}

impl Record {

    fn new(record: &str, key: [u8; 32], iv: [u8; 16]) -> Record {

        // gen salt and timestamp
        let salt: String = " h72DGs#*uf74U ".to_string();

        let datetime = DateTime::<Utc>::from(SystemTime::now());
        let timestamp = datetime.format("%Y-%m-%d %H:%M:%S").to_string();

        // encrypt timestamp
        let crypto_timestamp = rec_encrypt(timestamp.as_bytes(), &key, &iv).ok().unwrap();
        
        // encrypt login
        let mut record_: String = record.to_string();
        record_.push_str(&salt);
        record_.push_str(&timestamp);
        let crypto_rec = rec_encrypt(record_.as_bytes(), &key, &iv).ok().unwrap();

        let mut hash = [0u8; 32];
        Self::get_hash::<Sha256>(&record_, &mut hash);

        Record { record: crypto_rec, timestamp: crypto_timestamp, hash : hash, key : key, iv : iv }
    }

    fn get_hash<D: Digest>(record: &String, result: &mut [u8]) {
        let mut hasher = D::new();
        hasher.update(record.as_bytes());
        result.copy_from_slice(&hasher.finalize());
    }

    fn print_decrypted(self: &Record) {
        let record_decrypt = rec_decrypt(&self.record, &self.key, &self.iv);
        match record_decrypt {
            Ok(record) => println!("Record: {:?}", String::from_utf8(record).unwrap()),
            Err(e) => println!("error decryption login: {:?}", e),
        }

        let timestamp_decrypt = rec_decrypt(&self.timestamp, &self.key, &self.iv);
        match timestamp_decrypt {
            Ok(timestamp) => println!("Timestamp: {:?}", String::from_utf8(timestamp).unwrap()),
            Err(e) => println!("error decryption timestamp: {:?}", e),
        }
    }
}

fn rec_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn rec_decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

/*
 1. When user signs up in applicatoin, he gets his own ID.
    ID is SHA512 from login + date and time of registartion.

    Further, the ID uses to encrypt / decrypt all data of the user 
    (should thing out what crypto algorithm need to use).
    Each block (contains logins, passwords, etc.) encrypts separately (by AES256).

 2. Think about I2P network participance, else need to think out security pf data storage 
    to prevent data leaks.
*/

fn generate_key_pair() -> ([u8;32], [u8;16]) {

    let mut key: [u8; 32] = [0; 32];
    let mut iv: [u8; 16] = [0; 16];

    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);

    (key, iv)
}


pub(crate) struct Storage {
    file: File,
    keys: Keys, 
}

struct Keys {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Storage {

    fn key_from_private_key(private_key: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {

        let (sk, pk) = (private_key, PublicKey::from_secret_key(&SecretKey::parse_slice(private_key.as_slice()).unwrap()));
        let (sk, pk) = (&sk, &pk.serialize());
        (sk.to_vec(), pk.to_vec())
    }

    pub(crate) fn new(filename: &str, sk: String) -> Storage {

        let upk = &base64::decode(&sk).unwrap();    
        let (sk, pk) = Storage::key_from_private_key(upk);
    
        let file = OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .open(filename)
        .unwrap();

        let keys = Keys { private_key : sk, public_key : pk };
        Storage { file, keys }
    }

    pub(crate) fn write_record(self: &Storage, record: &str) {

        let (key, iv) = generate_key_pair();
        let record = Record::new(record, key, iv);
        record.print_decrypted();    
    
        let r = bincode::serialize(&record).unwrap();


        let crypto_rec = &encrypt(&self.keys.public_key, &r).unwrap();
        // let crypto_rec = rec_encrypt(&r, &KEY, &IV).unwrap();

        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(base64::encode(crypto_rec).as_bytes()).unwrap();
        let compressed_bytes = e.finish().unwrap();
    
        if let Err(e) = writeln!(&self.file, "{}",  base64::encode(&compressed_bytes)) {
            eprintln!("Couldn't write to file: {}", e);
        }
    }

    pub(crate) fn read_record(self: &Storage) {  
        
        let buf_reader = BufReader::new(&self.file);
    
        for line in buf_reader.lines() {
            if let Ok(line) = line {
    
                let gz_base64_rec = base64::decode(line).unwrap();
    
                let mut d = GzDecoder::new(gz_base64_rec.as_slice());
                let mut s = Vec::new();
                d.read_to_end(&mut s).unwrap();
    
                let base64_rec = base64::decode(s).unwrap();

                let decrypted_rec = decrypt(&self.keys.private_key, &base64_rec).unwrap();
                // let decrypted_rec = rec_decrypt(&base64_rec, &KEY, &IV).unwrap();

                let record = bincode::deserialize::<Record>(&decrypted_rec).unwrap();
                record.print_decrypted(); 
            }
        }
    }    
}

