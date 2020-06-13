use std::cmp;
use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode;
use bitcoin::consensus::encode::{Decodable, Encodable};
use bitcoin::network::address::Address;
use bitcoin::network::constants::{Network, ServiceFlags};
use bitcoin::network::message::{RawNetworkMessage, NetworkMessage};
use bitcoin::network::message_network::VersionMessage;

use tokio::prelude::*;
use tokio::codec;
use tokio::codec::Framed;
use tokio::net::TcpStream;
use tokio::io::read_exact;
use tokio::timer::Delay;

use futures::sync::mpsc;

use crate::printer::Printer;

struct BytesCoder<'a>(&'a mut bytes::BytesMut);
impl<'a> std::io::Write for BytesCoder<'a> {
	fn write(&mut self, b: &[u8]) -> Result<usize, std::io::Error> {
		self.0.extend_from_slice(&b);
		Ok(b.len())
	}
	fn flush(&mut self) -> Result<(), std::io::Error> {
		Ok(())
	}
}
struct BytesDecoder<'a> {
	buf: &'a mut bytes::BytesMut,
	pos: usize,
}
impl<'a> std::io::Read for BytesDecoder<'a> {
	fn read(&mut self, b: &mut [u8]) -> Result<usize, std::io::Error> {
		let copy_len = cmp::min(b.len(), self.buf.len() - self.pos);
		b[..copy_len].copy_from_slice(&self.buf[self.pos..self.pos + copy_len]);
		self.pos += copy_len;
		Ok(copy_len)
	}
}

struct MsgCoder<'a>(&'a Printer);
impl<'a> codec::Decoder for MsgCoder<'a> {
	type Item = Option<NetworkMessage>;
	type Error = encode::Error;

	fn decode(&mut self, bytes: &mut bytes::BytesMut) -> Result<Option<Option<NetworkMessage>>, encode::Error> {
		let mut decoder = BytesDecoder {
			buf: bytes,
			pos: 0
		};
		match RawNetworkMessage::consensus_decode(&mut decoder) {
			Ok(res) => {
				decoder.buf.advance(decoder.pos);
				if res.magic == Network::Bitcoin.magic() {
					Ok(Some(Some(res.payload)))
				} else {
					Err(encode::Error::UnexpectedNetworkMagic {
						expected: Network::Bitcoin.magic(),
						actual: res.magic
					})
				}
			},
			Err(e) => match e {
				encode::Error::Io(_) => Ok(None),
				encode::Error::UnrecognizedNetworkCommand(ref msg) => {
					decoder.buf.advance(decoder.pos);
					//XXX(fixthese): self.0.add_line(format!("rust-bitcoin doesn't support {}!", msg), true);
					if msg == "gnop" {
						Err(e)
					} else { Ok(Some(None)) }
				},
				_ => {
					self.0.add_line(format!("Error decoding message: {:?}", e), true);
					Err(e)
				},
			}
		}
	}
}
impl<'a> codec::Encoder for MsgCoder<'a> {
	type Item = NetworkMessage;
	type Error = std::io::Error;

	fn encode(&mut self, msg: NetworkMessage, res: &mut bytes::BytesMut) -> Result<(), std::io::Error> {
		if let Err(_) = (RawNetworkMessage {
			magic: Network::Bitcoin.magic(),
			payload: msg,
		}.consensus_encode(&mut BytesCoder(res))) {
			//XXX
		}
		Ok(())
	}
}

// base32 encoder and tests stolen (transliterated) from Bitcoin Core
// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see
// http://www.opensource.org/licenses/mit-license.php.
fn encode_base32(inp: &[u8]) -> String {
	let mut ret = String::with_capacity(((inp.len() + 4) / 5) * 8);

	let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
	let mut acc: u16 = 0;
	let mut bits: u8 = 0;
	for i in inp {
		acc = ((acc << 8) | *i as u16) & ((1 << (8 + 5 - 1)) - 1);
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			let idx = ((acc >> bits) & ((1 << 5) - 1)) as usize;
			ret += &alphabet[idx..idx + 1];
		}
	}
	if bits != 0 {
		let idx = ((acc << (5 - bits)) & ((1 << 5) - 1)) as usize;
		ret += &alphabet[idx..idx + 1];
	}
	while ret.len() % 8 != 0 { ret += "=" };
	return ret;
}

#[test]
fn test_encode_base32() {
	let tests_in = ["","f","fo","foo","foob","fooba","foobar"];
	let tests_out = ["","my======","mzxq====","mzxw6===","mzxw6yq=","mzxw6ytb","mzxw6ytboi======"];
	for (inp, out) in tests_in.iter().zip(tests_out.iter()) {
		assert_eq!(&encode_base32(inp.as_bytes()), out);
	}
	// My seednode's onion addr:
	assert_eq!(&encode_base32(&[0x6a, 0x8b, 0xd2, 0x78, 0x3f, 0x7a, 0xf8, 0x92, 0x8f, 0x80]), "nkf5e6b7pl4jfd4a");
}

/// Note that this should only be used for really small chunks, ie small enough to *definitely* fit
/// in the outbound TCP buffer, and shouldn't (practically) block.
macro_rules! try_write_small {
	($sock: expr, $obj: expr) => { {
		match $sock.write_all($obj) {
			Ok(()) => {},
			Err(e) => return future::Either::A(future::err(e)),
		}
	} }
}

pub struct Peer {}
impl Peer {
	pub fn new(addr: SocketAddr, tor_proxy: &SocketAddr, timeout: Duration, printer: &'static Printer) -> impl Future<Error=(), Item=(mpsc::Sender<NetworkMessage>, impl Stream<Item=Option<NetworkMessage>, Error=encode::Error>)> {
		let connect_timeout = Delay::new(Instant::now() + timeout.clone()).then(|_| {
			future::err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout reached"))
		});
		match addr.ip() {
			IpAddr::V6(v6addr) if v6addr.octets()[..6] == [0xFD,0x87,0xD8,0x7E,0xEB,0x43][..] => {
				future::Either::A(connect_timeout.select(TcpStream::connect(&tor_proxy)
					.and_then(move |mut stream: TcpStream| {
						try_write_small!(stream, &[5u8, 1u8, 0u8]); // SOCKS5 with 1 method and no auth
						future::Either::B(read_exact(stream, [0u8; 2]).and_then(move |(mut stream, response)| {
							if response != [5, 0] { // SOCKS5 with no auth successful
								future::Either::B(future::Either::A(future::err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to authenticate"))))
							} else {
								let hostname = encode_base32(&v6addr.octets()[6..]) + ".onion";
								let mut connect_msg = Vec::with_capacity(7 + hostname.len());
								// SOCKS5 command CONNECT (+ reserved byte) to hostname with given len
								connect_msg.extend_from_slice(&[5u8, 1u8, 0u8, 3u8, hostname.len() as u8]);
								connect_msg.extend_from_slice(hostname.as_bytes());
								connect_msg.push((addr.port() >> 8) as u8);
								connect_msg.push((addr.port() >> 0) as u8);
								try_write_small!(stream, &connect_msg);
								future::Either::B(future::Either::B(read_exact(stream, [0u8; 4]).and_then(move |(stream, response)| {
									if response[..3] != [5, 0, 0] {
										future::Either::B(future::err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to authenticate")))
									} else {
										if response[3] == 1 {
											future::Either::A(future::Either::A(read_exact(stream, [0; 6]).and_then(|(stream, _)| future::ok(stream))))
										} else if response[3] == 4 {
											future::Either::A(future::Either::B(read_exact(stream, [0; 18]).and_then(|(stream, _)| future::ok(stream))))
										} else {
											future::Either::B(future::err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Bogus proxy address value")))
										}
									}
								})))
							}
						}))
					})
				).and_then(|(stream, _)| future::ok(stream)).or_else(|(e, _)| future::err(e)))
			},
			_ => future::Either::B(connect_timeout.select(TcpStream::connect(&addr))
				.and_then(|(stream, _)| future::ok(stream)).or_else(|(e, _)| future::err(e))),
		}.and_then(move |stream| {
				let (write, read) = Framed::new(stream, MsgCoder(printer)).split();
				let (mut sender, receiver) = mpsc::channel(10); // We never really should send more than 10 messages unless they're dumb
				tokio::spawn(write.sink_map_err(|_| { () }).send_all(receiver)
					.then(|_| {
						future::err(())
					}));
				let _ = sender.try_send(NetworkMessage::Version(VersionMessage {
					version: 70015,
					services: ServiceFlags::WITNESS,
					timestamp: SystemTime::now().duration_since(UNIX_EPOCH).expect("time > 1970").as_secs() as i64,
					receiver: Address::new(&addr, ServiceFlags::NONE),
					sender: Address::new(&"0.0.0.0:0".parse().unwrap(), ServiceFlags::WITNESS),
					nonce: 0xdeadbeef,
					user_agent: "/rust-bitcoin:0.18/bluematt-tokio-client:0.1/".to_string(),
					start_height: 0,
					relay: false,
				}));
				future::ok((sender, read))
			})
		.or_else(move |_| {
			Delay::new(Instant::now() + timeout / 10).then(|_| future::err(()))
		})
	}
}
