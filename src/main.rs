extern crate reqwest;
extern crate hex;
#[macro_use]
extern crate nom;
use nom::*;

use std::fs::{OpenOptions, File};
use std::io::{ErrorKind, Read};
use std::collections::HashMap;
use reqwest::{Client, Identity};
use std::process::Command;

fn main() {
    download().unwrap()
}

#[derive(Debug)]
struct NcaMetadata {
    title_id: u64,
    title_version: u32,
    title_type: u8,
    table_offset: u16,
    content_entries: u16,
    meta_entries: u16
}

#[derive(Debug)]
struct ContentRecord {
    hash: [u8; 32],
    nca_id: [u8; 16],
    size: u64,
    ty: u8
}

#[derive(Debug)]
struct MetaRecord {
    title_id: u64,
    title_version: u32,
    ty: u8,
    weird: u8,
}

named! {nca_metadata<&[u8], NcaMetadata>,
    do_parse!(
        title_id: le_u64 >>
        title_version: le_u32 >>
        title_type: le_u8 >>
        take!(1) >>
        table_offset: le_u16 >>
        content_entries: le_u16 >>
        meta_entries: le_u16 >>
        take!(12) >>
        (NcaMetadata {
            title_id, title_version, title_type, table_offset, content_entries, meta_entries
        }))
}

named! {content_entry<&[u8], ContentRecord>,
    do_parse!(
        hash: take!(32) >>
        nca_id: take!(16) >>
        size: le_u64 >>
        ty: le_u8 >>
        take!(1) >>
        (ContentRecord { hash: { let mut a = [0; 32]; a.clone_from_slice(hash); a }, nca_id: { let mut a = [0; 16]; a.clone_from_slice(nca_id); a }, size, ty }))
}

named! {meta_entry<&[u8], MetaRecord>,
    do_parse!(
        title_id: le_u64 >>
        title_version: le_u32 >>
        ty: le_u8 >>
        weird: le_u8 >>
        take!(2) >>
        (MetaRecord { title_id, title_version, ty, weird }))
}

fn download() -> Result<(), Box<std::error::Error>> {
    let mut versions = HashMap::new();
    //versions.insert(450,        "1.0.0");
    versions.insert(65796,      "2.0.0");
    versions.insert(131162,     "2.1.0");
    versions.insert(196628,     "2.2.0");
    versions.insert(262164,     "2.3.0");
    versions.insert(201327002,  "3.0.0");
    versions.insert(201392178,  "3.0.1");
    versions.insert(201457684,  "3.0.2");
    versions.insert(268435656,  "4.0.0");
    versions.insert(268501002,  "4.0.1");
    versions.insert(269484082,  "4.1.0");
    versions.insert(335544750,  "5.0.0");
    versions.insert(335609886,  "5.0.1");
    versions.insert(335675432,  "5.0.2");
    versions.insert(336592976,  "5.1.0");

    let client_cert = {
        let mut cert_file = File::open("nx_tls_client_cert.pfx")?;
        let mut cert_raw = Vec::new();
        cert_file.read_to_end(&mut cert_raw)?;
        Identity::from_pkcs12_der(&cert_raw, "switch")?
    };

    let client = Client::builder()
        .identity(client_cert)
        .danger_disable_certificate_validation_entirely()
        .build()?;

    for (version_num, version_str) in versions {
        println!("Handling version {}", version_str);
        std::fs::create_dir(version_str).or_else(|e| if e.kind() == ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })?;

        download_version_meta(version_num, &client, version_str)?;

        // Parse the damn fella.
        let output = Command::new("hactool").args(&[format!("{}/0100000000000816.nca", version_str), format!("--section0dir={}/0100000000000816.nca.extracted", version_str)]).output()?;
        if !output.status.success() {
            println!("Failed to run command");
            println!("{}", String::from_utf8_lossy(&output.stdout[..]));
            println!("{}", String::from_utf8_lossy(&output.stderr[..]));
            panic!("Fail");
        }

        // Read it back
        let mut cnmt_file = Vec::new();
        File::open(format!("{}/0100000000000816.nca.extracted/SystemUpdate_0100000000000816.cnmt", version_str))?.read_to_end(&mut cnmt_file)?;
        let records = get_meta(cnmt_file.as_slice());

        for record in records {
            get_title(record, &client, version_str)?;
        }
    }

    Ok(())
}

fn download_version_meta(version_num: u64, client: &Client, version_str: &str) -> Result<(), Box<std::error::Error>> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(format!("{}/0100000000000816.nca", version_str)) {
        Ok(f) => f,
        Err(e) => if e.kind() == ErrorKind::AlreadyExists { return Ok(()) }
                  else                                    { return Err(Box::new(e)) }
    };

    let mut req = client.get(&format!("https://atumn.hac.lp1.d4c.nintendo.net/t/s/0100000000000816/{}", version_num));
    let mut response = req.send()?;
    std::io::copy(&mut response, &mut file)?;

    Ok(())
}

fn get_meta_type(ty: u8) -> &'static str {
    match ty {
        0x01 => "SystemProgram",
        0x02 => "SystemData",
        0x03 => "SystemUpdate",
        0x04 => "BootImagePackage",
        0x05 => "BootImagePackageSafe",
        _ => panic!("Unknown meta_type {}", ty)
    }
}

fn download_title_meta(title_id: u64, title_version: u32, client: &Client, version_str: &str) -> Result<(), Box<std::error::Error>> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(format!("{}/{:016x}.cnmt.nca", version_str, title_id)) {
        Ok(f) => f,
        Err(e) => if e.kind() == ErrorKind::AlreadyExists { return Ok(()) }
                  else                                    { return Err(Box::new(e)) }
    };

    let mut req = client.get(&format!("https://atumn.hac.lp1.d4c.nintendo.net/t/a/{:016x}/{}?device_id={}", title_id, title_version, std::env::args().nth(1).unwrap_or("0000000000000000".to_string())));
    let mut response = req.send()?;
    std::io::copy(&mut response, &mut file)?;
    Ok(())
}

fn get_title(record: MetaRecord, client: &Client, version_str: &str) -> Result<(), Box<std::error::Error>> {
    println!("\tHandling title {:016x}", record.title_id);

    download_title_meta(record.title_id, record.title_version, client, version_str)?;

    // Parse it again.
    let output = Command::new("hactool").args(&[format!("{}/{:016x}.cnmt.nca", version_str, record.title_id), format!("--section0dir={}/{:016x}.cnmt.nca.extracted", version_str, record.title_id)]).output()?;
    if !output.status.success() {
        println!("Failed to run command");
        println!("{}", String::from_utf8_lossy(&output.stdout[..]));
        println!("{}", String::from_utf8_lossy(&output.stderr[..]));
        panic!("Fail");
    }

    // Read it back
    let mut cnmt_file = Vec::new();
    File::open(format!("{}/{:016x}.cnmt.nca.extracted/{}_{1:016x}.cnmt", version_str, record.title_id, get_meta_type(record.ty)))?.read_to_end(&mut cnmt_file)?;
    let contents = get_contents(cnmt_file.as_slice());
    for content in contents {
        get_nca_by_id(content, client, version_str)?;
    }
    Ok(())
}

fn get_nca_by_id(content: ContentRecord, client: &Client, version_str: &str) -> Result<(), Box<std::error::Error>> {
    println!("\t\tHandling NCA ID {}", hex::encode(content.nca_id));
    // Download the actual NCA
    let mut file = match OpenOptions::new().write(true).create_new(true).open(format!("{}/{}.nca", version_str, hex::encode(content.nca_id))) {
        Ok(f) => f,
        Err(e) => if e.kind() == ErrorKind::AlreadyExists { return Ok(()) }
                  else                                    { return Err(Box::new(e)) }
    };
    let mut req = client.get(&format!("https://atumn.hac.lp1.d4c.nintendo.net/c/c/{}", hex::encode(content.nca_id)));
    let mut response = req.send()?;
    std::io::copy(&mut response, &mut file)?;
    Ok(())
}

fn get_meta(cnmt_file: &[u8]) -> Vec<MetaRecord> {
    let (mut input, nca) = nca_metadata(cnmt_file).unwrap();
    input = &input[nca.table_offset as usize..];

    for _ in 0..nca.content_entries {
        let (newinput, _content) = content_entry(input).unwrap();
        input = newinput;
    }

    let mut metas = Vec::new();
    for _ in 0..nca.meta_entries {
        let (newinput, content) = meta_entry(input).unwrap();
        input = newinput;
        metas.push(content);
    }
    metas
}

fn get_contents(cnmt_file: &[u8]) -> Vec<ContentRecord> {
    let (mut input, nca) = nca_metadata(cnmt_file).unwrap();
    input = &input[nca.table_offset as usize..];

    let mut contents = Vec::new();
    for _ in 0..nca.content_entries {
        let (newinput, content) = content_entry(input).unwrap();
        input = newinput;
        contents.push(content);
    }

    for _ in 0..nca.meta_entries {
        let (newinput, _content) = meta_entry(input).unwrap();
        input = newinput;
    }
    contents
}
