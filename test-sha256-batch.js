import * as modules from './dist/index.js';
const { SHA256 } = modules;

// 测试多个消息
const testCases = [
	['hello world', 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'],
	['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
	['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
];

for (const [msg, expected] of testCases) {
	const result = SHA256.hash(msg);
	const match = result === expected ? '✓' : '✗';
	console.log(`${match} SHA256("${msg}"):`);
	console.log(`  Expected: ${expected}`);
	console.log(`  Got:      ${result}`);
	console.log();
}
