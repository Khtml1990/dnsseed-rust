use std::sync::atomic::Ordering;
use std::collections::LinkedList;
use std::sync::{Arc, Mutex};
use std::io::Write;

use crate::datastore::{Store, AddressState, U64Setting, RegexSetting};

use crate::START_SHUTDOWN;

pub enum Stat {
	HeaderCount(u64),
	NewConnection,
	ConnectionClosed,
	V4RoutingTableSize(usize),
	V6RoutingTableSize(usize),
	RoutingTablePaths(usize),
}

struct Stats {
	lines: LinkedList<String>,
	header_count: u64,
	connection_count: u64,
	v4_table_size: usize,
	v6_table_size: usize,
	paths: usize,
}

pub struct Printer {
	stats: Arc<Mutex<Stats>>,
}

impl Printer {
	pub fn new(store: &'static Store) -> Printer {
		let stats: Arc<Mutex<Stats>> = Arc::new(Mutex::new(Stats {
			lines: LinkedList::new(),
			header_count: 0,
			connection_count: 0,
			v4_table_size: 0,
			v6_table_size: 0,
			paths: 0,
		}));
		let thread_arc = Arc::clone(&stats);
		std::thread::spawn(move || {
			loop {
				std::thread::sleep(std::time::Duration::from_secs(1));

				let mut out = Vec::new();

				{
					let stats = thread_arc.lock().unwrap();
					if START_SHUTDOWN.load(Ordering::Relaxed) && stats.connection_count == 0 {
						break;
					}

					out.write_all(b"\x1b[2J\x1b[;H\n").unwrap();
					for line in stats.lines.iter() {
						out.write_all(line.as_bytes()).unwrap();
						out.write_all(b"\n").unwrap();
					}

					out.write_all(b"\nNode counts by status:\n").unwrap();
					for i in 0..AddressState::get_count() {
						out.write_all(format!("{:22}: {}\n", AddressState::from_num(i).unwrap().to_str(),
								store.get_node_count(AddressState::from_num(i).unwrap())
								).as_bytes()).unwrap();
					}
					let generations = store.get_bloom_node_count();
					out.write_all(b"Bloom filter generations contain:").unwrap();
					for generation in &generations {
						out.write_all(format!(" {}", generation).as_bytes()).unwrap();
					}

					out.write_all(format!(
							"\n\nCurrent connections open/in progress: {}\n", stats.connection_count).as_bytes()).unwrap();
					out.write_all(format!(
							"Current block count: {}\n", stats.header_count).as_bytes()).unwrap();

					out.write_all(format!(
							"Timeout for full run (in seconds): {} (\"t x\" to change to x seconds)\n", store.get_u64(U64Setting::RunTimeout)
							).as_bytes()).unwrap();
					out.write_all(format!(
							"Minimum protocol version: {} (\"v x\" to change value to x)\n", store.get_u64(U64Setting::MinProtocolVersion)
							).as_bytes()).unwrap();
					out.write_all(format!(
							"Subversion match regex: {} (\"s x\" to change value to x)\n", store.get_regex(RegexSetting::SubverRegex).as_str()
							).as_bytes()).unwrap();

					out.write_all(b"\nRetry times (in seconds):\n").unwrap();
					for i in 0..AddressState::get_count() {
						let scan_secs = store.get_u64(U64Setting::RescanInterval(AddressState::from_num(i).unwrap()));
						out.write_all(format!(
								"{:22} ({:2}): {:5} (ie {} hrs, {} min)\n", AddressState::from_num(i).unwrap().to_str(), i,
								scan_secs, scan_secs / 60 / 60, (scan_secs / 60) % 60,
								).as_bytes()).unwrap();
					}

					out.write_all(format!(
							"\nBGP Routing Table: {} v4 nets, {} v6 nets, {} max paths\n",
							stats.v4_table_size, stats.v6_table_size, stats.paths).as_bytes()).unwrap();

					out.write_all(b"\nCommands:\n").unwrap();
					out.write_all(b"q: quit\n").unwrap();
					out.write_all(format!(
							"r x y: Change retry time for status x (int value, see retry times section for name mappings) to y (in seconds)\n"
							).as_bytes()).unwrap();
					out.write_all(format!(
							"w x: Change the amount of time a node is considered WAS_GOOD after it fails to x from {} (in seconds)\n",
							store.get_u64(U64Setting::WasGoodTimeout)
							).as_bytes()).unwrap();
					out.write_all(b"a x: Scan node x\n").unwrap();
					out.write_all(b"b x: BGP Lookup IP x\n").unwrap();
					out.write_all(b"\x1b[s").unwrap(); // Save cursor position and provide a blank line before cursor
					out.write_all(b"\x1b[;H\x1b[2K").unwrap();
					out.write_all(b"Most recent log:\n").unwrap();
					out.write_all(b"\x1b[u").unwrap(); // Restore cursor position and go up one line
				}

				let stdout = std::io::stdout();
				let mut stdout_lock = stdout.lock();
				stdout_lock.write_all(&out).expect("stdout broken?");
				stdout_lock.flush().expect("stdout broken?");
			}
		});
		Printer {
			stats,
		}
	}

	pub fn add_line(&self, line: String, err: bool) {
		let mut stats = self.stats.lock().unwrap();
		if err {
			stats.lines.push_back("\x1b[31m".to_string() + &line + "\x1b[0m");
		} else {
			stats.lines.push_back(line);
		}
		if stats.lines.len() > 150 {
			stats.lines.pop_front();
		}
	}

	pub fn set_stat(&self, s: Stat) {
		match s {
			Stat::HeaderCount(c) => self.stats.lock().unwrap().header_count = c,
			Stat::NewConnection => self.stats.lock().unwrap().connection_count += 1,
			Stat::ConnectionClosed => self.stats.lock().unwrap().connection_count -= 1,
			Stat::V4RoutingTableSize(c) => self.stats.lock().unwrap().v4_table_size = c,
			Stat::V6RoutingTableSize(c) => self.stats.lock().unwrap().v6_table_size = c,
			Stat::RoutingTablePaths(c) => self.stats.lock().unwrap().paths = c,
		}
	}
}
