
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
    login: std::vec::Vec<u8>,
    password: std::vec::Vec<u8>,
    timestamp: std::vec::Vec<u8>,
    hash: [u8; 32],
    key: [u8;32],
    iv: [u8;16]
}

impl Record {

    fn new(login: &str, password: &str, key: [u8; 32], iv: [u8; 16]) -> Record {

        // gen salt and timestamp
        let login_salt: String = " h72DGs#*uf74U ".to_string();
        let pass_salt: String = " h&G7dr$^6dK# ".to_string();

        let datetime = DateTime::<Utc>::from(SystemTime::now());
        let timestamp = datetime.format("%Y-%m-%d %H:%M:%S").to_string();

        // encrypt timestamp
        let crypto_timestamp = encrypt(timestamp.as_bytes(), &key, &iv).ok().unwrap();
        
        // encrypt login
        let mut record_login: String = login.to_string();
        record_login.push_str(&login_salt);
        let crypto_login = encrypt(record_login.as_bytes(), &key, &iv).ok().unwrap();

        // get sha512 hash from record password
        let mut record_pass: String = password.to_string();
        record_pass.push_str(&pass_salt);
        record_pass.push_str(&timestamp);
        
        // encrypt password
        let crypto_pass = encrypt(record_pass.as_bytes(), &key, &iv).ok().unwrap();

        let mut hash = [0u8; 32];
        Self::get_hash::<Sha256>(&record_pass, &mut hash);

        Record { login: crypto_login, password: crypto_pass, 
            timestamp: crypto_timestamp, hash : hash, key : key, iv : iv }
    }

    fn get_hash<D: Digest>(record: &String, result: &mut [u8]) {
        let mut hasher = D::new();
        hasher.update(record.as_bytes());
        result.copy_from_slice(&hasher.finalize());
    }

    fn print_decrypted(self: &Record) {
        let login_decrypt = decrypt(&self.login, &self.key, &self.iv);
        match login_decrypt {
            Ok(login) => println!("Login: {:?}", String::from_utf8(login).unwrap()),
            Err(e) => println!("error decryption login: {:?}", e),
        }

        let pass_decrypt = decrypt(&self.password, &self.key, &self.iv);
        match pass_decrypt {
            Ok(password) => println!("Password: {:?}", String::from_utf8(password).unwrap()),
            Err(e) => println!("error decryption password: {:?}", e),
        }

        let timestamp_decrypt = decrypt(&self.timestamp, &self.key, &self.iv);
        match timestamp_decrypt {
            Ok(timestamp) => println!("Timestamp: {:?}", String::from_utf8(timestamp).unwrap()),
            Err(e) => println!("error decryption timestamp: {:?}", e),
        }
    }
}

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

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

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
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

const KEY: [u8;32] = [0x00,0x01,0x02,0x03,0x00,0x01,0x02,0x03,0x00,0x01,0x02,0x03,0x00,0x01,0x02,0x03,
                      0x00,0x01,0x02,0x03,0x00,0x01,0x02,0x03,0x00,0x01,0x02,0x03,0x00,0x01,0x02,0x03];
const IV: [u8;16] =  [0xFF,0xF1,0xF2,0xF3,0xEE,0xE1,0xE2,0xE3,0xDD,0xD1,0xD2,0xD3,0xCC,0xC1,0xC2,0xC3];

fn test_read_records(file : &mut File) -> std::io::Result<()> {  
    
    // TODO: decompress file
    let buf_reader = BufReader::new(file);

    for line in buf_reader.lines() {
        if let Ok(line) = line {

            let gz_base64_rec = base64::decode(line).unwrap();

            let mut d = GzDecoder::new(gz_base64_rec.as_slice());
            let mut s = Vec::new();
            d.read_to_end(&mut s).unwrap();
   
            let base64_rec = base64::decode(s).unwrap();
            let decrypted_rec = decrypt(&base64_rec, &KEY, &IV).unwrap();
            let record = bincode::deserialize::<Record>(&decrypted_rec).unwrap();
            record.print_decrypted(); 
        }
    }
    Ok(())
}

fn write_record(file: &mut File, record: Vec<u8>) {

    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(base64::encode(record).as_bytes()).unwrap();
    let compressed_bytes = e.finish().unwrap();

    if let Err(e) = writeln!(file, "{}",  base64::encode(&compressed_bytes)) {
        eprintln!("Couldn't write to file: {}", e);
    }
}

fn test_write_records(file: &mut File) -> std::io::Result<()> {

    let (key1, iv1) = generate_key_pair();
    let record1 = Record::new("root", "admin1234", key1, iv1);
    record1.print_decrypted();    

    let (key2, iv2) = generate_key_pair();
    let record2 = Record::new("testlogin", "testpass", key2, iv2);
    record2.print_decrypted();    

    let r1 = bincode::serialize(&record1).unwrap();
    let crypto_rec1 = encrypt(&r1, &KEY, &IV).unwrap();
    
    let r2 = bincode::serialize(&record2).unwrap();
    let crypto_rec2 = encrypt(&r2, &KEY, &IV).unwrap();

    write_record(file, crypto_rec1);
    write_record(file, crypto_rec2);
    
    Ok(())
}

fn main() -> std::io::Result<()> {

    let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .append(true)
                    .open("output.bin")
                    .unwrap();
                    
    match test_read_records(&mut file) {
        Ok(file) => file,
        Err(error) => panic!("Problem reading the file: {:?}", error),
    }
    
    match test_write_records(&mut file) {
        Ok(file) => file,
        Err(error) => panic!("Problem writing the file: {:?}", error),
    }
    
    Ok(())
}