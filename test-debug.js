import crypto from 'crypto';
import * as modules from './dist/index.js';

console.log('导出的模块:', Object.keys(modules));

const { SHA256 } = modules;

console.log('SHA256 对象:', SHA256);
console.log('SHA256.hash:', SHA256.hash);

const testString = 'hello world';
const nodeResult = crypto.createHash('sha256').update(testString).digest('hex');
console.log('Node.js SHA-256 结果:', nodeResult);

try {
	const customResult = SHA256.hash(testString);
	console.log('Custom SHA-256 结果:', customResult);
} catch (error) {
	console.error('错误:', error);
}
