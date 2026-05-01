// 正确的SHA-256 padding
const message = "hello world";
const msgBytes = new TextEncoder().encode(message);

const ml = msgBytes.length * 8;  // 88 bits
console.log('Message length in bits:', ml);

// SHA-256 padding规则：
// 1. 添加bit 1 (0x80字节)
// 2. 添加0 bits直到消息长度 ≡ 448 (mod 512)
// 3. 添加原始消息长度作为64-bit big-endian整数

const paddingLen = (448 - (ml + 1) % 512 + 512) % 512;  // 这是bit数
console.log('Padding bits needed:', paddingLen);
console.log('Padding bytes needed:', paddingLen / 8);

// 总字节数应该是: original + 1 (for 0x80) + padding + 8 (for length)
const totalBytes = msgBytes.length + 1 + (paddingLen / 8) + 8;
console.log('Expected total bytes:', totalBytes);
console.log('Should be multiple of 64:', totalBytes % 64 === 0);

const padded = new Uint8Array(totalBytes);
padded.set(msgBytes);
padded[msgBytes.length] = 0x80;

// 将长度写入最后8个字节
for (let i = 0; i < 8; i++) {
	padded[padded.length - 8 + i] = (ml >>> (56 - i * 8)) & 0xff;
}

console.log('\nPadded message (last 16 bytes):');
for (let i = padded.length - 16; i < padded.length; i++) {
	console.log(`Byte ${i}: 0x${padded[i].toString(16).padStart(2, '0')}`);
}
