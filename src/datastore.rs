use std::cmp;
use std::collections::{HashSet, HashMap, hash_map};
use std::sync::{Arc, RwLock};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};
use std::io::{BufRead, BufReader};

use bitcoin::network::address::{Address, AddrV2Message};

use rand::thread_rng;
use rand::seq::{SliceRandom, IteratorRandom};

use tokio::prelude::*;
use tokio::fs::File;
use tokio::io::write_all;

use regex::Regex;

use crate::bgp_client::BGPClient;

pub const SECS_PER_SCAN_RESULTS: u64 = 15;
const MAX_CONNS_PER_SEC_PER_STATUS: u64 = 30;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum AddressState {
	Untested,
	LowBlockCount,
	HighBlockCount,
	LowVersion,
	BadVersion,
	NotFullNode,
	ProtocolViolation,
	Timeout,
	TimeoutDuringRequest,
	TimeoutAwaitingPong,
	TimeoutAwaitingAddr,
	TimeoutAwaitingBlock,
	Good,
	WasGood,
	EvilNode,
}

impl AddressState {
	pub fn from_num(num: u8) -> Option<AddressState> {
		match num {
			0x0 => Some(AddressState::Untested),
			0x1 => Some(AddressState::LowBlockCount),
			0x2 => Some(AddressState::HighBlockCount),
			0x3 => Some(AddressState::LowVersion),
			0x4 => Some(AddressState::BadVersion),
			0x5 => Some(AddressState::NotFullNode),
			0x6 => Some(AddressState::ProtocolViolation),
			0x7 => Some(AddressState::Timeout),
			0x8 => Some(AddressState::TimeoutDuringRequest),
			0x9 => Some(AddressState::TimeoutAwaitingPong),
			0xa => Some(AddressState::TimeoutAwaitingAddr),
			0xb => Some(AddressState::TimeoutAwaitingBlock),
			0xc => Some(AddressState::Good),
			0xd => Some(AddressState::WasGood),
			0xe => Some(AddressState::EvilNode),
			_   => None,
		}
	}

	pub fn to_num(&self) -> u8 {
		match *self {
			AddressState::Untested => 0,
			AddressState::LowBlockCount => 1,
			AddressState::HighBlockCount => 2,
			AddressState::LowVersion => 3,
			AddressState::BadVersion => 4,
			AddressState::NotFullNode => 5,
			AddressState::ProtocolViolation => 6,
			AddressState::Timeout => 7,
			AddressState::TimeoutDuringRequest => 8,
			AddressState::TimeoutAwaitingPong => 9,
			AddressState::TimeoutAwaitingAddr => 10,
			AddressState::TimeoutAwaitingBlock => 11,
			AddressState::Good => 12,
			AddressState::WasGood => 13,
			AddressState::EvilNode => 14,
		}
	}

	pub fn to_str(&self) -> &'static str {
		match *self {
			AddressState::Untested => "Untested",
			AddressState::LowBlockCount => "Low Block Count",
			AddressState::HighBlockCount => "High Block Count",
			AddressState::LowVersion => "Low Version",
			AddressState::BadVersion => "Bad Version",
			AddressState::NotFullNode => "Not Full Node",
			AddressState::ProtocolViolation => "Protocol Violation",
			AddressState::Timeout => "Timeout",
			AddressState::TimeoutDuringRequest => "Timeout During Request",
			AddressState::TimeoutAwaitingPong => "Timeout Awaiting Pong",
			AddressState::TimeoutAwaitingAddr => "Timeout Awaiting Addr",
			AddressState::TimeoutAwaitingBlock => "Timeout Awaiting Block",
			AddressState::Good => "Good",
			AddressState::WasGood => "Was Good",
			AddressState::EvilNode => "Evil Node",
		}
	}

	pub const fn get_count() -> u8 {
		15
	}
}

#[derive(Hash, PartialEq, Eq)]
pub enum U64Setting {
	RunTimeout,
	WasGoodTimeout,
	RescanInterval(AddressState),
	MinProtocolVersion,
}

#[derive(Hash, PartialEq, Eq)]
pub enum RegexSetting {
	SubverRegex,
}

struct Node {
	last_update: Instant,
	last_good: Instant, // Ignored unless state is Good or WasGood
	last_services: u64,
	state: AddressState,
	queued: bool,
}

/// Essentially SocketAddr but without a traffic class or scope
#[derive(Clone, PartialEq, Eq, Hash)]
enum SockAddr {
	V4(SocketAddrV4),
	V6((Ipv6Addr, u16)),
}
impl From<SocketAddr> for SockAddr {
	fn from(addr: SocketAddr) -> SockAddr {
		match addr {
			SocketAddr::V4(sa) => SockAddr::V4(sa),
			SocketAddr::V6(sa) => SockAddr::V6((sa.ip().clone(), sa.port())),
		}
	}
}
impl Into<SocketAddr> for &SockAddr {
	fn into(self) -> SocketAddr {
		match self {
			&SockAddr::V4(sa) => SocketAddr::V4(sa),
			&SockAddr::V6(sa) => SocketAddr::V6(SocketAddrV6::new(sa.0, sa.1, 0, 0))
		}
	}
}
impl ToString for SockAddr {
	fn to_string(&self) -> String {
		let sa: SocketAddr = self.into();
		sa.to_string()
	}
}
impl SockAddr {
	pub fn port(&self) -> u16 {
		match *self {
			SockAddr::V4(sa) => sa.port(),
			SockAddr::V6((_, port)) => port,
		}
	}
	pub fn ip(&self) -> IpAddr {
		match *self {
			SockAddr::V4(sa) => IpAddr::V4(sa.ip().clone()),
			SockAddr::V6((ip, _)) => IpAddr::V6(ip),
		}
	}
}

struct Nodes {
	good_node_services: [HashSet<SockAddr>; 64],
	nodes_to_state: HashMap<SockAddr, Node>,
	state_next_scan: [Vec<SockAddr>; AddressState::get_count() as usize],
}
struct NodesMutRef<'a> {
	good_node_services: &'a mut [HashSet<SockAddr>; 64],
	nodes_to_state: &'a mut HashMap<SockAddr, Node>,
	state_next_scan: &'a mut [Vec<SockAddr>; AddressState::get_count() as usize],
}

impl Nodes {
	fn borrow_mut<'a>(&'a mut self) -> NodesMutRef<'a> {
		NodesMutRef {
			good_node_services: &mut self.good_node_services,
			nodes_to_state: &mut self.nodes_to_state,
			state_next_scan: &mut self.state_next_scan,
		}
	}
}

pub struct Store {
	u64_settings: RwLock<HashMap<U64Setting, u64>>,
	subver_regex: RwLock<Arc<Regex>>,
	nodes: RwLock<Nodes>,
	store: String,
}

impl Store {
	pub fn new(store: String) -> impl Future<Item=Store, Error=()> {
		let settings_future = File::open(store.clone() + "/settings").and_then(|f| {
			let mut l = BufReader::new(f).lines();
			macro_rules! try_read {
				($lines: expr, $ty: ty) => { {
					match $lines.next() {
						Some(line) => match line {
							Ok(line) => match line.parse::<$ty>() {
								Ok(res) => res,
								Err(e) => return future::err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
							},
							Err(e) => return future::err(e),
						},
						None => return future::err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "")),
					}
				} }
			}
			let mut u64s = HashMap::with_capacity(AddressState::get_count() as usize + 4);
			u64s.insert(U64Setting::RunTimeout, try_read!(l, u64));
			u64s.insert(U64Setting::WasGoodTimeout, try_read!(l, u64));
			u64s.insert(U64Setting::MinProtocolVersion, try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::Untested), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::LowBlockCount), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::HighBlockCount), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::LowVersion), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::BadVersion), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::NotFullNode), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::ProtocolViolation), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::Timeout), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutDuringRequest), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutAwaitingPong), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutAwaitingAddr), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutAwaitingBlock), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::Good), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::WasGood), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::EvilNode), try_read!(l, u64));
			future::ok((u64s, try_read!(l, Regex)))
		}).or_else(|_| -> future::FutureResult<(HashMap<U64Setting, u64>, Regex), ()> {
			let mut u64s = HashMap::with_capacity(15);
			u64s.insert(U64Setting::RunTimeout, 120);
			u64s.insert(U64Setting::WasGoodTimeout, 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::Untested), 1);
			u64s.insert(U64Setting::RescanInterval(AddressState::LowBlockCount), 3600);
			u64s.insert(U64Setting::RescanInterval(AddressState::HighBlockCount), 7200);
			u64s.insert(U64Setting::RescanInterval(AddressState::LowVersion), 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::BadVersion), 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::NotFullNode), 86400);
			u64s.insert(U64Setting::RescanInterval(AddressState::ProtocolViolation), 86400);
			u64s.insert(U64Setting::RescanInterval(AddressState::Timeout), 86400);
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutDuringRequest), 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutAwaitingPong), 3600);
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutAwaitingAddr), 1800);
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutAwaitingBlock), 3600);
			u64s.insert(U64Setting::RescanInterval(AddressState::Good), 1800);
			u64s.insert(U64Setting::RescanInterval(AddressState::WasGood), 1800);
			u64s.insert(U64Setting::RescanInterval(AddressState::EvilNode), 315360000);
			u64s.insert(U64Setting::MinProtocolVersion, 70002);
			future::ok((u64s, Regex::new(".*").unwrap()))
		});

		macro_rules! nodes_uninitd {
			() => { {
				let state_vecs = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
				let good_node_services = [HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new()];
				Nodes {
					good_node_services,
					nodes_to_state: HashMap::new(),
					state_next_scan: state_vecs,
				}
			} }
		}

		let nodes_future = File::open(store.clone() + "/nodes").and_then(|f| {
			let mut res = nodes_uninitd!();
			let l = BufReader::new(f).lines();
			for line_res in l {
				let line = match line_res {
					Ok(l) => l,
					Err(_) => return future::ok(res),
				};
				let mut line_iter = line.split(',');
				macro_rules! try_read {
					($lines: expr, $ty: ty) => { {
						match $lines.next() {
							Some(line) => match line.parse::<$ty>() {
								Ok(res) => res,
								Err(_) => return future::ok(res),
							},
							None => return future::ok(res),
						}
					} }
				}
				let sockaddr = try_read!(line_iter, SocketAddr);
				let state = try_read!(line_iter, u8);
				let last_services = try_read!(line_iter, u64);
				let node = Node {
					state: match AddressState::from_num(state) {
						Some(v) => v,
						None => return future::ok(res),
					},
					last_services,
					last_update: Instant::now(),
					last_good: Instant::now(),
					queued: true,
				};
				if node.state == AddressState::Good {
					for i in 0..64 {
						if node.last_services & (1 << i) != 0 {
							res.good_node_services[i].insert(sockaddr.into());
						}
					}
				}
				res.state_next_scan[node.state.to_num() as usize].push(sockaddr.into());
				res.nodes_to_state.insert(sockaddr.into(), node);
			}
			future::ok(res)
		}).or_else(|_| -> future::FutureResult<Nodes, ()> {
			future::ok(nodes_uninitd!())
		});
		settings_future.join(nodes_future).and_then(move |((u64_settings, regex), nodes)| {
			future::ok(Store {
				u64_settings: RwLock::new(u64_settings),
				subver_regex: RwLock::new(Arc::new(regex)),
				nodes: RwLock::new(nodes),
				store,
			})
		})
	}

	pub fn get_u64(&self, setting: U64Setting) -> u64 {
		*self.u64_settings.read().unwrap().get(&setting).unwrap()
	}

	pub fn set_u64(&self, setting: U64Setting, value: u64) {
		*self.u64_settings.write().unwrap().get_mut(&setting).unwrap() = value;
	}

	pub fn get_node_count(&self, state: AddressState) -> usize {
		self.nodes.read().unwrap().state_next_scan[state.to_num() as usize].len()
	}

	pub fn get_regex(&self, _setting: RegexSetting) -> Arc<Regex> {
		Arc::clone(&*self.subver_regex.read().unwrap())
	}

	pub fn set_regex(&self, _setting: RegexSetting, value: Regex) {
		*self.subver_regex.write().unwrap() = Arc::new(value);
	}

	pub fn add_fresh_addrs<I: Iterator<Item=SocketAddr>>(&self, addresses: I) -> u64 {
		let mut res = 0;
		let mut nodes = self.nodes.write().unwrap();
		let cur_time = Instant::now();
		for addr in addresses {
			match nodes.nodes_to_state.entry(addr.into()) {
				hash_map::Entry::Vacant(e) => {
					e.insert(Node {
						state: AddressState::Untested,
						last_services: 0,
						last_update: cur_time,
						last_good: cur_time,
						queued: true,
					});
					nodes.state_next_scan[AddressState::Untested.to_num() as usize].push(addr.into());
					res += 1;
				},
				hash_map::Entry::Occupied(_) => {},
			}
		}
		res
	}

	pub fn add_fresh_nodes(&self, addresses: &Vec<(u32, Address)>) {
		self.add_fresh_addrs(addresses.iter().filter_map(|(_, addr)| {
			match addr.socket_addr() {
				Ok(socketaddr) => Some(socketaddr),
				Err(_) => None, // TODO: Handle onions
			}
		}));
	}
	pub fn add_fresh_nodes_v2(&self, addresses: &Vec<AddrV2Message>) {
		self.add_fresh_addrs(addresses.iter().filter_map(|addr| {
			match addr.socket_addr() {
				Ok(socketaddr) => Some(socketaddr),
				Err(_) => None, // TODO: Handle onions
			}
		}));
	}

	pub fn set_node_state(&self, sockaddr: SocketAddr, state: AddressState, services: u64) -> AddressState {
		let addr: SockAddr = sockaddr.into();
		let now = Instant::now();

		let mut nodes_lock = self.nodes.write().unwrap();
		let nodes = nodes_lock.borrow_mut();

		let state_ref = nodes.nodes_to_state.entry(addr.clone()).or_insert(Node {
			state: AddressState::Untested,
			last_services: 0,
			last_update: now,
			last_good: now,
			queued: false,
		});
		let ret = state_ref.state;
		if (state_ref.state == AddressState::Good || state_ref.state == AddressState::WasGood)
				&& state != AddressState::Good
				&& state_ref.last_good >= now - Duration::from_secs(self.get_u64(U64Setting::WasGoodTimeout)) {
			state_ref.state = AddressState::WasGood;
			for i in 0..64 {
				if state_ref.last_services & (1 << i) != 0 {
					nodes.good_node_services[i].remove(&addr);
				}
			}
			state_ref.last_services = 0;
			if !state_ref.queued {
				nodes.state_next_scan[AddressState::WasGood.to_num() as usize].push(addr);
				state_ref.queued = true;
			}
		} else {
			state_ref.state = state;
			if state == AddressState::Good {
				for i in 0..64 {
					if services & (1 << i) != 0 && state_ref.last_services & (1 << i) == 0 {
						nodes.good_node_services[i].insert(addr.clone());
					} else if services & (1 << i) == 0 && state_ref.last_services & (1 << i) != 0 {
						nodes.good_node_services[i].remove(&addr);
					}
				}
				state_ref.last_services = services;
				state_ref.last_good = now;
			}
			if !state_ref.queued {
				nodes.state_next_scan[state.to_num() as usize].push(addr);
				state_ref.queued = true;
			}
		}
		state_ref.last_update = now;
		ret
	}

	pub fn save_data(&'static self) -> impl Future<Item=(), Error=()> {
		let settings_file = self.store.clone() + "/settings";
		let settings_future = File::create(settings_file.clone() + ".tmp").and_then(move |f| {
			let settings_string = format!("{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
				self.get_u64(U64Setting::RunTimeout),
				self.get_u64(U64Setting::WasGoodTimeout),
				self.get_u64(U64Setting::MinProtocolVersion),
				self.get_u64(U64Setting::RescanInterval(AddressState::Untested)),
				self.get_u64(U64Setting::RescanInterval(AddressState::LowBlockCount)),
				self.get_u64(U64Setting::RescanInterval(AddressState::HighBlockCount)),
				self.get_u64(U64Setting::RescanInterval(AddressState::LowVersion)),
				self.get_u64(U64Setting::RescanInterval(AddressState::BadVersion)),
				self.get_u64(U64Setting::RescanInterval(AddressState::NotFullNode)),
				self.get_u64(U64Setting::RescanInterval(AddressState::ProtocolViolation)),
				self.get_u64(U64Setting::RescanInterval(AddressState::Timeout)),
				self.get_u64(U64Setting::RescanInterval(AddressState::TimeoutDuringRequest)),
				self.get_u64(U64Setting::RescanInterval(AddressState::TimeoutAwaitingPong)),
				self.get_u64(U64Setting::RescanInterval(AddressState::TimeoutAwaitingAddr)),
				self.get_u64(U64Setting::RescanInterval(AddressState::TimeoutAwaitingBlock)),
				self.get_u64(U64Setting::RescanInterval(AddressState::Good)),
				self.get_u64(U64Setting::RescanInterval(AddressState::WasGood)),
				self.get_u64(U64Setting::RescanInterval(AddressState::EvilNode)),
				self.get_regex(RegexSetting::SubverRegex).as_str());
			write_all(f, settings_string).and_then(|(mut f, _)| {
				f.poll_sync_all()
			}).and_then(|_| {
				tokio::fs::rename(settings_file.clone() + ".tmp", settings_file)
			})
		});

		let nodes_file = self.store.clone() + "/nodes";
		let nodes_future = File::create(nodes_file.clone() + ".tmp").and_then(move |f| {
			let mut nodes_buff = String::new();
			{
				let nodes = self.nodes.read().unwrap();
				nodes_buff.reserve(nodes.nodes_to_state.len() * 32);
				for (ref sockaddr, ref node) in nodes.nodes_to_state.iter() {
					nodes_buff += &sockaddr.to_string();
					nodes_buff += ",";
					nodes_buff += &node.state.to_num().to_string();
					nodes_buff += ",";
					nodes_buff += &node.last_services.to_string();
					nodes_buff += "\n";
				}
			}
			write_all(f, nodes_buff)
		}).and_then(|(mut f, _)| {
			f.poll_sync_all()
		}).and_then(|_| {
			tokio::fs::rename(nodes_file.clone() + ".tmp", nodes_file)
		});

		settings_future.join(nodes_future).then(|_| { future::ok(()) })
	}

	pub fn write_dns(&'static self, bgp_client: Arc<BGPClient>) -> impl Future<Item=(), Error=()> {
		let dns_file = self.store.clone() + "/nodes.dump";
		File::create(dns_file.clone() + ".tmp").and_then(move |f| {
			let mut dns_buff = String::new();
			{
				let mut rng = thread_rng();
				for i in &[ 0b00000000001u64,
				            0b00000000100,
				            0b00000000101,
				            0b00000001000,
				            0b00000001001,
				            0b00000001100,
				            0b00000001101,
				            0b00001001001,
				            0b10000000000,
				            0b10000000001,
				            0b10000000100,
				            0b10000000101,
				            0b10000001000,
				            0b10000001001,
				            0b10000001100,
				            0b10000001101,
				            0b10001001000] {
				//            ^ NODE_NETWORK_LIIMTED
				//COMPACT_FILTERS ^   ^ NODE_BLOOM
				//      NODE_WITNESS ^  ^ NODE_NETWORK
				// We support all combos of NETWORK, NETWORK_LIMITED, BLOOM, and WITNESS
				// We support COMPACT_FILTERS with WITNESS and NETWORK or NETWORK_LIIMTED.
					let mut tor_set: Vec<Ipv6Addr> = Vec::new();
					let mut v6_set: Vec<Ipv6Addr> = Vec::new();
					let mut v4_set: Vec<Ipv4Addr> = Vec::new();
					macro_rules! add_addr { ($addr: expr) => {
						match $addr.ip() {
							IpAddr::V4(v4addr) => v4_set.push(v4addr),
							IpAddr::V6(v6addr) if v6addr.octets()[..6] == [0xFD,0x87,0xD8,0x7E,0xEB,0x43][..] => tor_set.push(v6addr),
							IpAddr::V6(v6addr) => v6_set.push(v6addr),
						}
					} }
					{
						let nodes = self.nodes.read().unwrap();
						if i.count_ones() == 1 {
							for j in 0..64 {
								if i & (1 << j) != 0 {
									let set_ref = &nodes.good_node_services[j];
									for a in set_ref.iter().filter(|e| e.port() == 8333) {
										add_addr!(a);
									}
									break;
								}
							}
						} else if i.count_ones() == 2 {
							let mut first_set = None;
							let mut second_set = None;
							for j in 0..64 {
								if i & (1 << j) != 0 {
									if first_set == None {
										first_set = Some(&nodes.good_node_services[j]);
									} else {
										second_set = Some(&nodes.good_node_services[j]);
										break;
									}
								}
							}
							for a in first_set.unwrap().intersection(&second_set.unwrap()).filter(|e| e.port() == 8333) {
								add_addr!(a);
							}
						} else {
							//TODO: Could optimize this one a bit
							let mut intersection;
							let mut intersection_set_ref = None;
							for j in 0..64 {
								if i & (1 << j) != 0 {
									if intersection_set_ref == None {
										intersection_set_ref = Some(&nodes.good_node_services[j]);
									} else {
										let new_intersection = intersection_set_ref.unwrap()
											.intersection(&nodes.good_node_services[j]).map(|e| (*e).clone()).collect();
										intersection = Some(new_intersection);
										intersection_set_ref = Some(intersection.as_ref().unwrap());
									}
								}
							}
							for a in intersection_set_ref.unwrap().iter().filter(|e| e.port() == 8333) {
								add_addr!(a);
							}
						}
					}
					let mut asn_set = HashSet::with_capacity(cmp::max(v4_set.len(), v6_set.len()));
					asn_set.insert(0);
					for (a, asn) in v4_set.iter().map(|a| (a, bgp_client.get_asn(IpAddr::V4(*a)))).filter(|a| asn_set.insert(a.1)).choose_multiple(&mut rng, 21) {
						dns_buff += &format!("x{:x}.dnsseed\tIN\tA\t{} ; AS{}\n", i, a, asn);
					}
					asn_set.clear();
					asn_set.insert(0);
					for (a, asn) in v6_set.iter().map(|a| (a, bgp_client.get_asn(IpAddr::V6(*a)))).filter(|a| asn_set.insert(a.1)).choose_multiple(&mut rng, 10) {
						dns_buff += &format!("x{:x}.dnsseed\tIN\tAAAA\t{} ; AS{}\n", i, a, asn);
					}
					for a in tor_set.iter().choose_multiple(&mut rng, 2) {
						dns_buff += &format!("x{:x}.dnsseed\tIN\tAAAA\t{} ; Tor Onionv2\n", i, a);
					}
				}
			}
			write_all(f, dns_buff)
		}).and_then(|(mut f, _)| {
			f.poll_sync_all()
		}).and_then(|_| {
			tokio::fs::rename(dns_file.clone() + ".tmp", dns_file)
		}).then(|_| { future::ok(()) })
	}

	pub fn get_next_scan_nodes(&self) -> Vec<SocketAddr> {
		let mut res = Vec::with_capacity(128);

		{
			let mut nodes_lock = self.nodes.write().unwrap();
			let nodes = nodes_lock.borrow_mut();
			for (idx, state_nodes) in nodes.state_next_scan.iter_mut().enumerate() {
				let rescan_interval = cmp::max(self.get_u64(U64Setting::RescanInterval(AddressState::from_num(idx as u8).unwrap())), 1);
				let split_point = cmp::min(cmp::min(SECS_PER_SCAN_RESULTS * state_nodes.len() as u64 / rescan_interval,
							SECS_PER_SCAN_RESULTS * MAX_CONNS_PER_SEC_PER_STATUS),
						state_nodes.len() as u64);
				for node in state_nodes.drain(..split_point as usize) {
					nodes.nodes_to_state.get_mut(&node).unwrap().queued = false;
					res.push((&node).into());
				}
			}
		}
		res.shuffle(&mut thread_rng());
		res
	}
}
