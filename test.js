import crypto from 'crypto';
import * as modules from './dist/index.js';

// 提取模块
const { AES128, AES256, MD5, Base64, RSA } = modules;

// 颜色输出
const colors = {
	reset: '\x1b[0m',
	green: '\x1b[32m',
	red: '\x1b[31m',
	yellow: '\x1b[33m',
	blue: '\x1b[34m',
	cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
	console.log(`${colors[color]}${message}${colors.reset}`);
}

function testPassed(name) {
	log(`✓ ${name} 通过`, 'green');
}

function testFailed(name, expected, actual) {
	log(`✗ ${name} 失败`, 'red');
	log(`  期望: ${expected}`, 'yellow');
	log(`  实际: ${actual}`, 'yellow');
}

function assertEquals(name, expected, actual) {
	if (expected === actual) {
		testPassed(name);
		return true;
	} else {
		testFailed(name, expected, actual);
		return false;
	}
}

// 测试数据
const testStrings = {
	simple: 'hello world',
	chinese: '你好世界',
	special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
	longText: 'The quick brown fox jumps over the lazy dog. ' + 'This is a longer test string to ensure the algorithm works with varied lengths.'
};


// ======================== MD5 测试 ========================
log('\n=== MD5 测试 ===', 'cyan');
for (const [key, testString] of Object.entries(testStrings)) {
	const nodeResult = crypto.createHash('md5').update(testString).digest('hex');
	const customResult = MD5.hash(testString);
	assertEquals(`MD5: ${key}`, nodeResult, customResult);
}

// ======================== Base64 编码测试 ========================
log('\n=== Base64 编码/解码 测试 ===', 'cyan');
for (const [key, testString] of Object.entries(testStrings)) {
	const bytes = new TextEncoder().encode(testString);
	const encoded = Base64.encode(bytes);
	const nodeResult = Buffer.from(testString).toString('base64');
	assertEquals(`Base64 编码: ${key}`, nodeResult, encoded);

	const decoded = Base64.decode(encoded);
	const decodedString = new TextDecoder().decode(decoded);
	assertEquals(`Base64 解码: ${key}`, testString, decodedString);
}

// ======================== AES-128 测试 ========================
log('\n=== AES-128 加密/解密 测试 ===', 'cyan');
const aes128Key = 'mySecretKey12345'; // 16字节密钥
for (const [key, testString] of Object.entries(testStrings)) {
	try {
		const encrypted = AES128.encrypt(testString, aes128Key);
		const decrypted = AES128.decrypt(encrypted, aes128Key);
		assertEquals(`AES-128 加密/解密: ${key}`, testString, decrypted);
	} catch (error) {
		testFailed(`AES-128 加密/解密: ${key}`, '成功', `错误: ${error.message}`);
	}
}

// ======================== AES-256 测试 ========================
log('\n=== AES-256 加密/解密 测试 ===', 'cyan');
const aes256Key = 'mySecretKey12345mySecretKey1234'; // 32字节密钥
for (const [key, testString] of Object.entries(testStrings)) {
	try {
		const encrypted = AES256.encrypt(testString, aes256Key);
		const decrypted = AES256.decrypt(encrypted, aes256Key);
		assertEquals(`AES-256 加密/解密: ${key}`, testString, decrypted);
	} catch (error) {
		testFailed(`AES-256 加密/解密: ${key}`, '成功', `错误: ${error.message}`);
	}
}

// ======================== RSA 测试 ========================
log('\n=== RSA 密钥生成和加密/解密 测试 ===', 'cyan');
try {
	log('生成RSA密钥对 (1024位)...', 'blue');
	const keyPair = RSA.generateKeyPair(1024);
	log('✓ RSA密钥对生成成功', 'green');

	const testMessage = 'hello RSA';
	log(`加密信息: "${testMessage}"`, 'blue');
	const encrypted = RSA.encrypt(testMessage, keyPair.publicKey);
	log('✓ RSA加密成功', 'green');

	const decrypted = RSA.decrypt(encrypted, keyPair.privateKey);
	assertEquals('RSA 加密/解密', testMessage, decrypted);
} catch (error) {
	testFailed('RSA 测试', '成功', `错误: ${error.message}`);
}

// ======================== SHA-3-256 测试 ========================
log('\n=== SHA-3-256 测试 (跳过) ===', 'cyan');
log('注意: SHA-3测试暂时跳过', 'yellow');

// ======================== SHA-3-512 测试 ========================
log('\n=== SHA-3-512 测试 (跳过) ===', 'cyan');
log('注意: SHA-3测试暂时跳过', 'yellow');
log('\n=== 测试完成 ===', 'cyan');
