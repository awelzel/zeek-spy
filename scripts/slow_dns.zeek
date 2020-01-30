# Just some random event handlers that should be slow.
module SlowDNS;

global hashes: table[string, string] of count;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {

	local i = 0;
	local q = c$dns$query;
	local hash = md5_hash(q);
	while (i < 200) {
		hash = md5_hash(cat(q, hash));
		hash = sha1_hash(cat(q, hash));
		hash = sha256_hash(cat(q, hash));
		i += 1;
	}
	print fmt("DNS request for %s from %s:%d: %s",
		c$dns$query, c$id$orig_h, c$id$orig_p, hash);

	if ([hash, q] !in hashes) {
		hashes[hash, q] = 1;
	} else {
		hashes[hash, q] += 1;
	}
}

event schedule_me() {
	local max = 0;
	local max_q = "";
	local max_hash = "";

	for ([hash, q] in hashes) {
		local c = hashes[hash, q];
		if (c > max) {
			max = c;
			max_q = q;
			max_hash = hash;
		}
	}
	if (max > 0) {
		print(fmt("max %s:%s:%d", max_hash, max_q, max));
	}
	schedule 333msec { schedule_me() };
}
event zeek_init() {
	schedule 10msec { schedule_me() };
}

