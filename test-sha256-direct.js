// 简单的SHA-256实现测试
function SHA256(message) {
	// 初始哈希值
	const H = [
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	];

	// 轮常数
	const K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];

	function rotr(x, n) {
		return ((x >>> n) | (x << (32 - n))) >>> 0;
	}

	function pad(message) {
		const ml = message.length * 8;
		const paddingLen = (448 - (ml + 1) % 512 + 512) % 512;
		const result = new Uint8Array(message.length + 1 + paddingLen / 8 + 8);

		result.set(message);
		result[message.length] = 0x80;

		for (let i = 0; i < 8; i++) {
			result[result.length - 8 + i] = (ml >>> (56 - i * 8)) & 0xff;
		}

		return result;
	}

	const msgBytes = new TextEncoder().encode(message);
	const padded = pad(msgBytes);
	const blocks = [];

	for (let i = 0; i < padded.length; i += 64) {
		const block = [];
		for (let j = 0; j < 64; j += 4) {
			const word = ((padded[i + j] << 24) | (padded[i + j + 1] << 16) | (padded[i + j + 2] << 8) | padded[i + j + 3]) >>> 0;
			block.push(word);
		}
		blocks.push(block);
	}

	let hash = [...H];

	for (const block of blocks) {
		const w = new Array(64);
		for (let i = 0; i < 16; i++) w[i] = block[i];
		for (let i = 16; i < 64; i++) {
			const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
			const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
			w[i] = ((w[i - 16] + s0 + w[i - 7] + s1) >>> 0);
		}

		let [a, b, c, d, e, f, g, h] = hash;

		for (let i = 0; i < 64; i++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ ((~e) & g);
			const temp1 = ((h + S1 + ch + K[i] + w[i]) >>> 0);
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const temp2 = ((S0 + maj) >>> 0);

			h = g;
			g = f;
			f = e;
			e = ((d + temp1) >>> 0);
			d = c;
			c = b;
			b = a;
			a = ((temp1 + temp2) >>> 0);
		}

		hash[0] = ((hash[0] + a) >>> 0);
		hash[1] = ((hash[1] + b) >>> 0);
		hash[2] = ((hash[2] + c) >>> 0);
		hash[3] = ((hash[3] + d) >>> 0);
		hash[4] = ((hash[4] + e) >>> 0);
		hash[5] = ((hash[5] + f) >>> 0);
		hash[6] = ((hash[6] + g) >>> 0);
		hash[7] = ((hash[7] + h) >>> 0);
	}

	return hash.map(h => h.toString(16).padStart(8, "0")).join("");
}

console.log('Test SHA-256("hello world"):', SHA256('hello world'));
console.log('Expected:                   b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
