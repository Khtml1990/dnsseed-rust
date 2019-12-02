use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::io::BufReader;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use tokio::prelude::*;
use tokio::io::{stdin, lines};

use crate::printer::Printer;
use crate::datastore::{Store, AddressState, U64Setting, RegexSetting};
use crate::bgp_client::BGPClient;

use crate::{START_SHUTDOWN, scan_node};

use regex::Regex;

// base32 decoder and tests stolen (transliterated) from Bitcoin Core
// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see
// http://www.opensource.org/licenses/mit-license.php.
fn decode_base32(inp: &[u8]) -> Option<Vec<u8>> {
	let decode32_table: [i8; 256] = [
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
		-1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,  0,  1,  2,
		 3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
		23, 24, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
	];

	let mut ret = Vec::with_capacity((inp.len() * 5) / 8);

	let mut acc: u16 = 0;
	let mut bits: u8 = 0;
	for i in inp {
		if *i == '=' as u8 { break; }
		let codepoint = decode32_table[*i as usize];
		if codepoint < 0 { return None; }
		acc = ((acc << 5) | codepoint as u16) & ((1 << (8 + 5 - 1)) - 1);
		bits += 5;
		while bits >= 8 {
			bits -= 8;
			ret.push((acc >> bits) as u8);
		}
	}
	Some(ret)
}

#[test]
fn test_decode_base32() {
	let tests_in = ["","f","fo","foo","foob","fooba","foobar"];
	let tests_out = ["","my======","mzxq====","mzxw6===","mzxw6yq=","mzxw6ytb","mzxw6ytboi======"];
	for (inp, out) in tests_in.iter().zip(tests_out.iter()) {
		assert_eq!(&decode_base32(out.as_bytes()).unwrap()[..], inp.as_bytes());
	}
	// My seednode's onion addr:
	assert_eq!(decode_base32("nkf5e6b7pl4jfd4a".as_bytes()).unwrap()[..],[0x6a, 0x8b, 0xd2, 0x78, 0x3f, 0x7a, 0xf8, 0x92, 0x8f, 0x80]);
}

pub fn read(store: &'static Store, printer: &'static Printer, bgp_client: Arc<BGPClient>) {
	tokio::spawn(lines(BufReader::new(stdin())).for_each(move |line| {
		macro_rules! err {
			() => { {
				printer.add_line(format!("Unparsable input: \"{}\"", line), true);
				return future::ok(());
			} }
		}
		let mut line_iter = line.split(' ');
		macro_rules! get_next_chunk {
			() => { {
				match line_iter.next() {
					Some(c) => c,
					None => err!(),
				}
			} }
		}
		macro_rules! try_parse_next_chunk {
			($type: ty) => { {
				match get_next_chunk!().parse::<$type>() {
					Ok(res) => res,
					Err(_) => err!(),
				}
			} }
		}
		match get_next_chunk!() {
			"t" => store.set_u64(U64Setting::RunTimeout, try_parse_next_chunk!(u64)),
			"v" => store.set_u64(U64Setting::MinProtocolVersion, try_parse_next_chunk!(u64)),
			"w" => store.set_u64(U64Setting::WasGoodTimeout, try_parse_next_chunk!(u64)),
			"s" => {
				if line.len() < 3 || !line.starts_with("s ") {
					err!();
				}
				store.set_regex(RegexSetting::SubverRegex, match line[2..].parse::<Regex>() {
					Ok(res) => res,
					Err(_) => err!(),
				});
			},
			"a" => {
				let host_port = get_next_chunk!();
				let parsed = if host_port.len() > 23 && &host_port[16..23] == ".onion:" {
					let port = match host_port[23..].parse::<u16>() { Ok(res) => res, Err(_) => err!(), };

					let ipv6 = match decode_base32(host_port[0..16].as_bytes()) { Some(res) => res, None => err!(), };
					if ipv6.len() != 10 { err!(); }
					let mut octets = [0xFD,0x87,0xD8,0x7E,0xEB,0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
					octets[6..].copy_from_slice(&ipv6[0..10]);

					SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
				} else {
					match host_port.parse::<SocketAddr>() {
						Ok(res) => res, Err(_) => err!(), }
				};
				scan_node(Instant::now(), parsed, true)
			},
			"b" => {
				let ip = try_parse_next_chunk!(IpAddr);
				printer.add_line(format!("ASN for {} is {} (prefixlen, path: {:?})", ip, bgp_client.get_asn(ip), bgp_client.get_path(ip)), false);
			},
			"r" => {
				match AddressState::from_num(try_parse_next_chunk!(u8)) {
					Some(state) => store.set_u64(U64Setting::RescanInterval(state), try_parse_next_chunk!(u64)),
					None => err!(),
				}
			},
			"q" => {
				START_SHUTDOWN.store(true, Ordering::SeqCst);
				return future::err(std::io::Error::new(std::io::ErrorKind::Other, ""));
			},
			_ => err!(),
		}
		future::ok(())
	}).then(move |_| {
		printer.add_line("Shutting down...".to_string(), true);
		future::ok(())
	}));
}
