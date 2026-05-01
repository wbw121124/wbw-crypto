// 测试新的填充逻辑
function pad(message) {
	const ml = message.length * 8;
	const paddingLenBits = (448 - (ml + 1) % 512 + 512) % 512;
	const paddingLenBytes = Math.floor(paddingLenBits / 8);
	const result = new Uint8Array(message.length + 1 + paddingLenBytes + 8);

	result.set(message);
	result[message.length] = 0x80;

	for (let i = 0; i < 8; i++) {
		result[result.length - 8 + i] = (ml >>> (56 - i * 8)) & 0xff;
	}

	return result;
}

const msgBytes = new TextEncoder().encode("abc");
const padded = pad(msgBytes);

console.log('Padded message length:', padded.length);
console.log('Is multiple of 64:', padded.length % 64 === 0);

console.log('\nLast 16 bytes:');
for (let i = padded.length - 16; i < padded.length; i++) {
	console.log(`padded[${i}] = 0x${padded[i].toString(16).padStart(2, '0')}`);
}

console.log('\nAs 32-bit words:');
const w14 = ((padded[56] << 24) | (padded[57] << 16) | (padded[58] << 8) | padded[59]) >>> 0;
const w15 = ((padded[60] << 24) | (padded[61] << 16) | (padded[62] << 8) | padded[63]) >>> 0;
console.log('w[14] =', '0x' + w14.toString(16).padStart(8, '0'));
console.log('w[15] =', '0x' + w15.toString(16).padStart(8, '0'));
