// 调试SHA-256padding
const message = "hello world";
const msgBytes = new TextEncoder().encode(message);

console.log('Message:', message);
console.log('Message bytes:', msgBytes);
console.log('Message length:', msgBytes.length);
console.log('Message length in bits:', msgBytes.length * 8);

const ml = msgBytes.length * 8;
const paddingLen = (448 - (ml + 1) % 512 + 512) % 512;
console.log('Padding length:', paddingLen);

const result = new Uint8Array(msgBytes.length + 1 + paddingLen / 8 + 8);
result.set(msgBytes);
result[msgBytes.length] = 0x80;

for (let i = 0; i < 8; i++) {
	result[result.length - 8 + i] = (ml >>> (56 - i * 8)) & 0xff;
}

console.log('Total padded length:', result.length);
console.log('Padded bytes (hex):');
for (let i = 0; i < result.length; i++) {
	if (i % 16 === 0) console.log('\n' + i.toString().padStart(3, ' ') + ': ');
	process.stdout.write(result[i].toString(16).padStart(2, '0') + ' ');
}
console.log('\n');

console.log('Last 8 bytes (length):');
const lengthBytes = result.slice(result.length - 8);
for (let i = 0; i < 8; i++) {
	console.log(`Byte ${i}: 0x${lengthBytes[i].toString(16).padStart(2, '0')} = ${lengthBytes[i]}`);
}

// 验证长度字段
let decodedLength = 0n;
for (let i = 0; i < 8; i++) {
	decodedLength = (decodedLength << 8n) | BigInt(lengthBytes[i]);
}
console.log('Decoded length:', decodedLength.toString(), 'bits');
