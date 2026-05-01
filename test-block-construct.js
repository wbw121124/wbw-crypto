// 调试消息块构造
const message = "abc";
const msgBytes = new TextEncoder().encode(message);

const ml = msgBytes.length * 8;
const paddingLenBits = (448 - (ml + 1) % 512 + 512) % 512;
const paddingLenBytes = Math.floor(paddingLenBits / 8);
const padded = new Uint8Array(msgBytes.length + 1 + paddingLenBytes + 8);

padded.set(msgBytes);
padded[msgBytes.length] = 0x80;

for (let i = 0; i < 8; i++) {
	padded[padded.length - 8 + i] = (ml >>> (56 - i * 8)) & 0xff;
}

console.log('Message:', message);
console.log('Message bytes:', Array.from(msgBytes).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
console.log('Total padded length:', padded.length);

console.log('\nFirst block (64 bytes):');
const block = [];
for (let j = 0; j < 64; j += 4) {
	const word = ((padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3]) >>> 0;
	block.push(word);
	console.log(`w[${j / 4}] = 0x${word.toString(16).padStart(8, '0')}`);
}

console.log('\nExpected w[0-3]:');
console.log('w[0] = 0x61626380 (abc + 0x80)');
console.log('w[14] = 0x00000018 (length = 24 bits)');
console.log('w[15] = 0x00000018 (length = 24 bits)');
