This will do things that you need if you run a dns seed. You need a local Bitcoin full node, a Tor
node, and a BGP speaker that can give you an ADD_PATH session that gives you a diverse route view.

Outputs a partial zone file that you should shove into your DNS infrastructure as appropriate.

USAGE: dnsseed-rust datastore (ie storage folder) localPeerAddress:8333 tor_proxy_addr:9050 bgp_peer:179
