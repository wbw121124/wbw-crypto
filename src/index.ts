/**
 * @file index.ts
 * @author wbw121124
 * @fileoverview AES-128、AES-256、RSA、SHA-256、SHA-512、SHA-3、MD5、base64的加密和解密（除hash以外）
 */

/**
 * AES-128 加密解密模块
 */
export namespace AES128 {
	// S盒 - 用于字节替换
	const SBOX: number[] = [
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	];

	// 逆S盒
	const INV_SBOX: number[] = [
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	];

	// 轮常数
	const RCON: number[] = [
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
	];

	/**
	 * 将字节数组转换为状态矩阵
	 * @param bytes 16字节数组
	 * @returns 4x4状态矩阵
	 */
	function bytesToState(bytes: Uint8Array): number[][] {
		const state: number[][] = [[], [], [], []];
		for (let i = 0; i < 16; i++) {
			state[i % 4][Math.floor(i / 4)] = bytes[i];
		}
		return state;
	}

	/**
	 * 将状态矩阵转换为字节数组
	 * @param state 4x4状态矩阵
	 * @returns 16字节数组
	 */
	function stateToBytes(state: number[][]): Uint8Array {
		const bytes = new Uint8Array(16);
		for (let i = 0; i < 16; i++) {
			bytes[i] = state[i % 4][Math.floor(i / 4)];
		}
		return bytes;
	}

	/**
	 * 密钥扩展算法 - 生成轮密钥
	 * @param key 原始密钥(16字节)
	 * @returns 轮密钥数组(11个4x4矩阵)
	 */
	function keyExpansion(key: Uint8Array): number[][][] {
		const nk = 4; // 128位密钥对应4个字
		const nr = 10; // 轮数
		const w: number[][] = [];

		// 初始化轮密钥
		for (let i = 0; i < nk; i++) {
			w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
		}

		// 生成剩余轮密钥
		for (let i = nk; i < 4 * (nr + 1); i++) {
			let temp = [...w[i - 1]];
			if (i % nk === 0) {
				// 循环左移1字节
				const rotated = [temp[1], temp[2], temp[3], temp[0]];
				// S盒替换
				temp = rotated.map(b => SBOX[b]);
				// 异或轮常数
				temp[0] ^= RCON[i / nk - 1];
			}
			// 与前一组异或
			w[i] = [];
			for (let j = 0; j < 4; j++) {
				w[i][j] = w[i - nk][j] ^ temp[j];
			}
		}

		// 转换为轮密钥矩阵形式
		const roundKeys: number[][][] = [];
		for (let round = 0; round <= nr; round++) {
			const keyMatrix: number[][] = [[], [], [], []];
			for (let col = 0; col < 4; col++) {
				const word = w[round * 4 + col];
				for (let row = 0; row < 4; row++) {
					keyMatrix[row][col] = word[row];
				}
			}
			roundKeys.push(keyMatrix);
		}
		return roundKeys;
	}

	/**
	 * SubBytes字节替换层
	 * @param state 状态矩阵
	 */
	function subBytes(state: number[][]): void {
		for (let i = 0; i < 4; i++) {
			for (let j = 0; j < 4; j++) {
				state[i][j] = SBOX[state[i][j]];
			}
		}
	}

	/**
	 * InvSubBytes逆字节替换层
	 * @param state 状态矩阵
	 */
	function invSubBytes(state: number[][]): void {
		for (let i = 0; i < 4; i++) {
			for (let j = 0; j < 4; j++) {
				state[i][j] = INV_SBOX[state[i][j]];
			}
		}
	}

	/**
	 * ShiftRows行移位层
	 * @param state 状态矩阵
	 */
	function shiftRows(state: number[][]): void {
		// 第二行左移1位
		const tempRow1 = [...state[1]];
		for (let i = 0; i < 4; i++) {
			state[1][i] = tempRow1[(i + 1) % 4];
		}
		// 第三行左移2位
		const tempRow2 = [...state[2]];
		for (let i = 0; i < 4; i++) {
			state[2][i] = tempRow2[(i + 2) % 4];
		}
		// 第四行左移3位
		const tempRow3 = [...state[3]];
		for (let i = 0; i < 4; i++) {
			state[3][i] = tempRow3[(i + 3) % 4];
		}
	}

	/**
	 * InvShiftRows逆行移位层
	 * @param state 状态矩阵
	 */
	function invShiftRows(state: number[][]): void {
		// 第二行右移1位
		const tempRow1 = [...state[1]];
		for (let i = 0; i < 4; i++) {
			state[1][i] = tempRow1[(i + 3) % 4];
		}
		// 第三行右移2位
		const tempRow2 = [...state[2]];
		for (let i = 0; i < 4; i++) {
			state[2][i] = tempRow2[(i + 2) % 4];
		}
		// 第四行右移3位
		const tempRow3 = [...state[3]];
		for (let i = 0; i < 4; i++) {
			state[3][i] = tempRow3[(i + 1) % 4];
		}
	}

	/**
	 * GF(2^8)乘法 使用不可约多项式x^8+x^4+x^3+x+1
	 * @param a 字节值
	 * @param b 字节值
	 * @returns 乘积结果
	 */
	function gfMult(a: number, b: number): number {
		let result = 0;
		for (let i = 0; i < 8; i++) {
			if (b & 1) result ^= a;
			const highBit = a & 0x80;
			a = (a << 1) & 0xff;
			if (highBit) a ^= 0x1b;
			b >>= 1;
		}
		return result;
	}

	/**
	 * MixColumns列混合层
	 * @param state 状态矩阵
	 */
	function mixColumns(state: number[][]): void {
		for (let col = 0; col < 4; col++) {
			const s0 = state[0][col];
			const s1 = state[1][col];
			const s2 = state[2][col];
			const s3 = state[3][col];

			state[0][col] = gfMult(0x02, s0) ^ gfMult(0x03, s1) ^ s2 ^ s3;
			state[1][col] = s0 ^ gfMult(0x02, s1) ^ gfMult(0x03, s2) ^ s3;
			state[2][col] = s0 ^ s1 ^ gfMult(0x02, s2) ^ gfMult(0x03, s3);
			state[3][col] = gfMult(0x03, s0) ^ s1 ^ s2 ^ gfMult(0x02, s3);
		}
	}

	/**
	 * InvMixColumns逆列混合层
	 * @param state 状态矩阵
	 */
	function invMixColumns(state: number[][]): void {
		for (let col = 0; col < 4; col++) {
			const s0 = state[0][col];
			const s1 = state[1][col];
			const s2 = state[2][col];
			const s3 = state[3][col];

			state[0][col] = gfMult(0x0e, s0) ^ gfMult(0x0b, s1) ^ gfMult(0x0d, s2) ^ gfMult(0x09, s3);
			state[1][col] = gfMult(0x09, s0) ^ gfMult(0x0e, s1) ^ gfMult(0x0b, s2) ^ gfMult(0x0d, s3);
			state[2][col] = gfMult(0x0d, s0) ^ gfMult(0x09, s1) ^ gfMult(0x0e, s2) ^ gfMult(0x0b, s3);
			state[3][col] = gfMult(0x0b, s0) ^ gfMult(0x0d, s1) ^ gfMult(0x09, s2) ^ gfMult(0x0e, s3);
		}
	}

	/**
	 * AddRoundKey轮密钥加层
	 * @param state 状态矩阵
	 * @param roundKey 轮密钥
	 */
	function addRoundKey(state: number[][], roundKey: number[][]): void {
		for (let i = 0; i < 4; i++) {
			for (let j = 0; j < 4; j++) {
				state[i][j] ^= roundKey[i][j];
			}
		}
	}

	/**
	 * AES-128加密单个块
	 * @param plaintext 16字节明文块
	 * @param key 16字节密钥
	 * @returns 16字节密文块
	 */
	function encryptBlock(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
		const state = bytesToState(plaintext);
		const roundKeys = keyExpansion(key);

		// 初始轮密钥加
		addRoundKey(state, roundKeys[0]);

		// 9轮完整轮变换
		for (let round = 1; round <= 9; round++) {
			subBytes(state);
			shiftRows(state);
			mixColumns(state);
			addRoundKey(state, roundKeys[round]);
		}

		// 最后一轮
		subBytes(state);
		shiftRows(state);
		addRoundKey(state, roundKeys[10]);

		return stateToBytes(state);
	}

	/**
	 * AES-128解密单个块
	 * @param ciphertext 16字节密文块
	 * @param key 16字节密钥
	 * @returns 16字节明文块
	 */
	function decryptBlock(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
		const state = bytesToState(ciphertext);
		const roundKeys = keyExpansion(key);

		// 初始轮密钥加
		addRoundKey(state, roundKeys[10]);

		// 9轮完整轮变换
		for (let round = 9; round >= 1; round--) {
			invShiftRows(state);
			invSubBytes(state);
			addRoundKey(state, roundKeys[round]);
			invMixColumns(state);
		}

		// 最后一轮
		invShiftRows(state);
		invSubBytes(state);
		addRoundKey(state, roundKeys[0]);

		return stateToBytes(state);
	}

	/**
	 * PKCS7填充
	 * @param data 原始数据
	 * @param blockSize 块大小(字节)
	 * @returns 填充后的数据
	 */
	function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
		const paddingLen = blockSize - (data.length % blockSize);
		const result = new Uint8Array(data.length + paddingLen);
		result.set(data);
		for (let i = data.length; i < result.length; i++) {
			result[i] = paddingLen;
		}
		return result;
	}

	/**
	 * PKCS7去填充
	 * @param data 填充后的数据
	 * @returns 原始数据
	 */
	function pkcs7Unpad(data: Uint8Array): Uint8Array {
		const paddingLen = data[data.length - 1];
		if (paddingLen < 1 || paddingLen > 16) {
			throw new Error("Invalid padding");
		}
		for (let i = data.length - paddingLen; i < data.length; i++) {
			if (data[i] !== paddingLen) {
				throw new Error("Invalid padding");
			}
		}
		return data.slice(0, data.length - paddingLen);
	}

	/**
	 * 加密任意长度数据
	 * @param plaintext 明文(UTF-8字符串)
	 * @param key 16字节密钥(可以是字符串或Uint8Array)
	 * @returns Base64编码的密文
	 */
	export function encrypt(plaintext: string, key: string | Uint8Array): string {
		let keyBytes: Uint8Array;
		if (typeof key === "string") {
			keyBytes = new TextEncoder().encode(key);
			if (keyBytes.length !== 16) {
				throw new Error("AES-128密钥必须是16字节");
			}
		} else {
			keyBytes = key;
			if (keyBytes.length !== 16) {
				throw new Error("AES-128密钥必须是16字节");
			}
		}

		const plainBytes = new TextEncoder().encode(plaintext);
		const padded = pkcs7Pad(plainBytes, 16);
		const cipherBlocks: Uint8Array[] = [];

		for (let i = 0; i < padded.length; i += 16) {
			const block = padded.slice(i, i + 16);
			const encrypted = encryptBlock(block, keyBytes);
			cipherBlocks.push(encrypted);
		}

		const ciphertext = new Uint8Array(cipherBlocks.length * 16);
		for (let i = 0; i < cipherBlocks.length; i++) {
			ciphertext.set(cipherBlocks[i], i * 16);
		}

		return Base64.encode(ciphertext);
	}

	/**
	 * 解密数据
	 * @param ciphertext Base64编码的密文
	 * @param key 16字节密钥
	 * @returns 解密后的明文字符串
	 */
	export function decrypt(ciphertext: string, key: string | Uint8Array): string {
		let keyBytes: Uint8Array;
		if (typeof key === "string") {
			keyBytes = new TextEncoder().encode(key);
			if (keyBytes.length !== 16) {
				throw new Error("AES-128密钥必须是16字节");
			}
		} else {
			keyBytes = key;
			if (keyBytes.length !== 16) {
				throw new Error("AES-128密钥必须是16字节");
			}
		}

		const cipherBytes = Base64.decode(ciphertext);
		if (cipherBytes.length % 16 !== 0) {
			throw new Error("密文长度必须是16的倍数");
		}

		const plainBlocks: Uint8Array[] = [];
		for (let i = 0; i < cipherBytes.length; i += 16) {
			const block = cipherBytes.slice(i, i + 16);
			const decrypted = decryptBlock(block, keyBytes);
			plainBlocks.push(decrypted);
		}

		const paddedPlaintext = new Uint8Array(plainBlocks.length * 16);
		for (let i = 0; i < plainBlocks.length; i++) {
			paddedPlaintext.set(plainBlocks[i], i * 16);
		}

		const plaintextBytes = pkcs7Unpad(paddedPlaintext);
		return new TextDecoder().decode(plaintextBytes);
	}
}

/**
 * AES-256 加密解密模块
 */
export namespace AES256 {
	// S盒 - 用于字节替换
	const SBOX: number[] = [
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	];

	// 逆S盒
	const INV_SBOX: number[] = [
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	];

	const RCON: number[] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

	/**
	 * 密钥扩展算法 - AES-256需要8个字的初始密钥和14轮
	 * @param key 32字节密钥
	 * @returns 轮密钥数组(15个4x4矩阵)
	 */
	function keyExpansion(key: Uint8Array): number[][][] {
		const nk = 8; // 256位密钥对应8个字
		const nr = 14; // 轮数
		const w: number[][] = [];

		// 初始化轮密钥
		for (let i = 0; i < nk; i++) {
			w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
		}

		// 生成剩余轮密钥
		for (let i = nk; i < 4 * (nr + 1); i++) {
			let temp = [...w[i - 1]];
			if (i % nk === 0) {
				// 循环左移1字节
				const rotated = [temp[1], temp[2], temp[3], temp[0]];
				// S盒替换
				temp = rotated.map(b => SBOX[b]);
				// 异或轮常数
				temp[0] ^= RCON[i / nk - 1];
			} else if (i % nk === 4) {
				// AES-256在nk=4时额外应用S-box
				temp = temp.map(b => SBOX[b]);
			}
			// 与前一组异或
			w[i] = [];
			for (let j = 0; j < 4; j++) {
				w[i][j] = w[i - nk][j] ^ temp[j];
			}
		}

		// 转换为轮密钥矩阵形式
		const roundKeys: number[][][] = [];
		for (let round = 0; round <= nr; round++) {
			const keyMatrix: number[][] = [[], [], [], []];
			for (let col = 0; col < 4; col++) {
				const word = w[round * 4 + col];
				for (let row = 0; row < 4; row++) {
					keyMatrix[row][col] = word[row];
				}
			}
			roundKeys.push(keyMatrix);
		}
		return roundKeys;
	}

	/**
	 * 字节替换层
	 */
	function subBytes(state: number[][]): void {
		for (let i = 0; i < 4; i++) {
			for (let j = 0; j < 4; j++) {
				state[i][j] = SBOX[state[i][j]];
			}
		}
	}

	/**
	 * 逆字节替换层
	 */
	function invSubBytes(state: number[][]): void {
		for (let i = 0; i < 4; i++) {
			for (let j = 0; j < 4; j++) {
				state[i][j] = INV_SBOX[state[i][j]];
			}
		}
	}

	/**
	 * 行移位层
	 */
	function shiftRows(state: number[][]): void {
		const tempRow1 = [...state[1]];
		for (let i = 0; i < 4; i++) state[1][i] = tempRow1[(i + 1) % 4];
		const tempRow2 = [...state[2]];
		for (let i = 0; i < 4; i++) state[2][i] = tempRow2[(i + 2) % 4];
		const tempRow3 = [...state[3]];
		for (let i = 0; i < 4; i++) state[3][i] = tempRow3[(i + 3) % 4];
	}

	/**
	 * 逆行移位层
	 */
	function invShiftRows(state: number[][]): void {
		const tempRow1 = [...state[1]];
		for (let i = 0; i < 4; i++) state[1][i] = tempRow1[(i + 3) % 4];
		const tempRow2 = [...state[2]];
		for (let i = 0; i < 4; i++) state[2][i] = tempRow2[(i + 2) % 4];
		const tempRow3 = [...state[3]];
		for (let i = 0; i < 4; i++) state[3][i] = tempRow3[(i + 1) % 4];
	}

	/**
	 * GF(2^8)乘法
	 */
	function gfMult(a: number, b: number): number {
		let result = 0;
		for (let i = 0; i < 8; i++) {
			if (b & 1) result ^= a;
			const highBit = a & 0x80;
			a = (a << 1) & 0xff;
			if (highBit) a ^= 0x1b;
			b >>= 1;
		}
		return result;
	}

	/**
	 * 列混合层
	 */
	function mixColumns(state: number[][]): void {
		for (let col = 0; col < 4; col++) {
			const s0 = state[0][col], s1 = state[1][col], s2 = state[2][col], s3 = state[3][col];
			state[0][col] = gfMult(0x02, s0) ^ gfMult(0x03, s1) ^ s2 ^ s3;
			state[1][col] = s0 ^ gfMult(0x02, s1) ^ gfMult(0x03, s2) ^ s3;
			state[2][col] = s0 ^ s1 ^ gfMult(0x02, s2) ^ gfMult(0x03, s3);
			state[3][col] = gfMult(0x03, s0) ^ s1 ^ s2 ^ gfMult(0x02, s3);
		}
	}

	/**
	 * 逆列混合层
	 */
	function invMixColumns(state: number[][]): void {
		for (let col = 0; col < 4; col++) {
			const s0 = state[0][col], s1 = state[1][col], s2 = state[2][col], s3 = state[3][col];
			state[0][col] = gfMult(0x0e, s0) ^ gfMult(0x0b, s1) ^ gfMult(0x0d, s2) ^ gfMult(0x09, s3);
			state[1][col] = gfMult(0x09, s0) ^ gfMult(0x0e, s1) ^ gfMult(0x0b, s2) ^ gfMult(0x0d, s3);
			state[2][col] = gfMult(0x0d, s0) ^ gfMult(0x09, s1) ^ gfMult(0x0e, s2) ^ gfMult(0x0b, s3);
			state[3][col] = gfMult(0x0b, s0) ^ gfMult(0x0d, s1) ^ gfMult(0x09, s2) ^ gfMult(0x0e, s3);
		}
	}

	/**
	 * 轮密钥加层
	 */
	function addRoundKey(state: number[][], roundKey: number[][]): void {
		for (let i = 0; i < 4; i++) {
			for (let j = 0; j < 4; j++) {
				state[i][j] ^= roundKey[i][j];
			}
		}
	}

	/**
	 * 字节数组转状态矩阵
	 */
	function bytesToState(bytes: Uint8Array): number[][] {
		const state: number[][] = [[], [], [], []];
		for (let i = 0; i < 16; i++) {
			state[i % 4][Math.floor(i / 4)] = bytes[i];
		}
		return state;
	}

	/**
	 * 状态矩阵转字节数组
	 */
	function stateToBytes(state: number[][]): Uint8Array {
		const bytes = new Uint8Array(16);
		for (let i = 0; i < 16; i++) {
			bytes[i] = state[i % 4][Math.floor(i / 4)];
		}
		return bytes;
	}

	/**
	 * AES-256加密单个块
	 */
	function encryptBlock(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
		const state = bytesToState(plaintext);
		const roundKeys = keyExpansion(key);

		addRoundKey(state, roundKeys[0]);

		for (let round = 1; round <= 13; round++) {
			subBytes(state);
			shiftRows(state);
			mixColumns(state);
			addRoundKey(state, roundKeys[round]);
		}

		subBytes(state);
		shiftRows(state);
		addRoundKey(state, roundKeys[14]);

		return stateToBytes(state);
	}

	/**
	 * AES-256解密单个块
	 */
	function decryptBlock(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
		const state = bytesToState(ciphertext);
		const roundKeys = keyExpansion(key);

		addRoundKey(state, roundKeys[14]);

		for (let round = 13; round >= 1; round--) {
			invShiftRows(state);
			invSubBytes(state);
			addRoundKey(state, roundKeys[round]);
			invMixColumns(state);
		}

		invShiftRows(state);
		invSubBytes(state);
		addRoundKey(state, roundKeys[0]);

		return stateToBytes(state);
	}

	/**
	 * PKCS7填充
	 */
	function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
		const paddingLen = blockSize - (data.length % blockSize);
		const result = new Uint8Array(data.length + paddingLen);
		result.set(data);
		for (let i = data.length; i < result.length; i++) result[i] = paddingLen;
		return result;
	}

	/**
	 * PKCS7去填充
	 */
	function pkcs7Unpad(data: Uint8Array): Uint8Array {
		const paddingLen = data[data.length - 1];
		if (paddingLen < 1 || paddingLen > 16) throw new Error("Invalid padding");
		for (let i = data.length - paddingLen; i < data.length; i++) {
			if (data[i] !== paddingLen) throw new Error("Invalid padding");
		}
		return data.slice(0, data.length - paddingLen);
	}

	/**
	 * AES-256加密
	 * @param plaintext 明文字符串
	 * @param key 32字节密钥(字符串或Uint8Array)
	 * @returns Base64编码的密文
	 */
	export function encrypt(plaintext: string, key: string | Uint8Array): string {
		let keyBytes: Uint8Array;
		if (typeof key === "string") {
			keyBytes = new TextEncoder().encode(key);
			if (keyBytes.length !== 32) throw new Error("AES-256密钥必须是32字节");
		} else {
			keyBytes = key;
			if (keyBytes.length !== 32) throw new Error("AES-256密钥必须是32字节");
		}

		const plainBytes = new TextEncoder().encode(plaintext);
		const padded = pkcs7Pad(plainBytes, 16);
		const cipherBlocks: Uint8Array[] = [];

		for (let i = 0; i < padded.length; i += 16) {
			cipherBlocks.push(encryptBlock(padded.slice(i, i + 16), keyBytes));
		}

		const ciphertext = new Uint8Array(cipherBlocks.length * 16);
		for (let i = 0; i < cipherBlocks.length; i++) ciphertext.set(cipherBlocks[i], i * 16);

		return Base64.encode(ciphertext);
	}

	/**
	 * AES-256解密
	 * @param ciphertext Base64编码的密文
	 * @param key 32字节密钥
	 * @returns 解密后的明文字符串
	 */
	export function decrypt(ciphertext: string, key: string | Uint8Array): string {
		let keyBytes: Uint8Array;
		if (typeof key === "string") {
			keyBytes = new TextEncoder().encode(key);
			if (keyBytes.length !== 32) throw new Error("AES-256密钥必须是32字节");
		} else {
			keyBytes = key;
			if (keyBytes.length !== 32) throw new Error("AES-256密钥必须是32字节");
		}

		const cipherBytes = Base64.decode(ciphertext);
		if (cipherBytes.length % 16 !== 0) throw new Error("密文长度必须是16的倍数");

		const plainBlocks: Uint8Array[] = [];
		for (let i = 0; i < cipherBytes.length; i += 16) {
			plainBlocks.push(decryptBlock(cipherBytes.slice(i, i + 16), keyBytes));
		}

		const paddedPlaintext = new Uint8Array(plainBlocks.length * 16);
		for (let i = 0; i < plainBlocks.length; i++) paddedPlaintext.set(plainBlocks[i], i * 16);

		const plaintextBytes = pkcs7Unpad(paddedPlaintext);
		return new TextDecoder().decode(plaintextBytes);
	}
}

/**
 * RSA 加密解密模块
 * 使用BigInt实现大数运算
 */
export namespace RSA {
	/**
	 * 生成随机大素数
	 * @param bits 位数
	 * @returns 大素数
	 */
	function generatePrime(bits: number): bigint {
		while (true) {
			let num = 0n;
			for (let i = 0; i < bits; i++) {
				num = (num << 1n) | (BigInt(Math.random() < 0.5 ? 1 : 0));
			}
			num |= 1n; // 确保奇数

			if (isPrime(num)) return num;
		}
	}

	/**
	 * Miller-Rabin素性测试
	 * @param n 待测试的数
	 * @param k 测试次数
	 * @returns 是否为素数
	 */
	function isPrime(n: bigint, k: number = 10): boolean {
		if (n === 2n || n === 3n) return true;
		if (n <= 1n || n % 2n === 0n) return false;

		let d = n - 1n;
		let r = 0;
		while (d % 2n === 0n) {
			d /= 2n;
			r++;
		}

		for (let i = 0; i < k; i++) {
			const a = BigInt(Math.floor(Math.random() * (Number(n) - 3))) + 2n;
			let x = modPow(a, d, n);
			if (x === 1n || x === n - 1n) continue;

			let composite = true;
			for (let j = 0; j < r - 1; j++) {
				x = (x * x) % n;
				if (x === n - 1n) {
					composite = false;
					break;
				}
			}
			if (composite) return false;
		}
		return true;
	}

	/**
	 * 模幂运算
	 * @param base 底数
	 * @param exp 指数
	 * @param mod 模数
	 * @returns base^exp mod mod
	 */
	function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
		let result = 1n;
		let b = base % mod;
		let e = exp;

		while (e > 0n) {
			if (e & 1n) result = (result * b) % mod;
			b = (b * b) % mod;
			e >>= 1n;
		}
		return result;
	}

	/**
	 * 扩展欧几里得算法求模逆
	 * @param a 参数a
	 * @param m 模数
	 * @returns a的模m逆元
	 */
	function modInv(a: bigint, m: bigint): bigint {
		let [old_r, r] = [a, m];
		let [old_s, s] = [1n, 0n];
		let [old_t, t] = [0n, 1n];

		while (r !== 0n) {
			const quotient = old_r / r;
			[old_r, r] = [r, old_r - quotient * r];
			[old_s, s] = [s, old_s - quotient * s];
			[old_t, t] = [t, old_t - quotient * t];
		}

		return (old_s % m + m) % m;
	}

	/**
	 * 生成RSA密钥对
	 * @param bits 密钥位数(通常1024、2048)
	 * @returns 公钥(n,e)和私钥(n,d)
	 */
	export function generateKeyPair(bits: number = 2048): {
		publicKey: { n: bigint; e: bigint };
		privateKey: { n: bigint; d: bigint };
	} {
		const p = generatePrime(bits / 2);
		const q = generatePrime(bits / 2);
		const n = p * q;
		const phi = (p - 1n) * (q - 1n);

		const e = 65537n;
		const d = modInv(e, phi);

		return {
			publicKey: { n, e },
			privateKey: { n, d }
		};
	}

	/**
	 * RSA加密
	 * @param plaintext 明文字符串
	 * @param publicKey 公钥(n,e)
	 * @returns 加密后的BigInt数组(Base64格式返回)
	 */
	export function encrypt(plaintext: string, publicKey: { n: bigint; e: bigint }): string {
		const bytes = new TextEncoder().encode(plaintext);
		const blockSize = Math.floor(Number(publicKey.n.toString(2).length) / 8) - 11; // PKCS#1 v1.5 padding预留11字节

		const encryptedBlocks: bigint[] = [];
		for (let i = 0; i < bytes.length; i += blockSize) {
			const block = bytes.slice(i, i + blockSize);
			let m = 0n;
			for (let j = 0; j < block.length; j++) {
				m = (m << 8n) | BigInt(block[j]);
			}
			const c = modPow(m, publicKey.e, publicKey.n);
			encryptedBlocks.push(c);
		}

		const result = new Uint8Array(encryptedBlocks.length * (Number(publicKey.n.toString(2).length) / 8));
		for (let i = 0; i < encryptedBlocks.length; i++) {
			const blockBytes = bigintToBytes(encryptedBlocks[i], Math.ceil(Number(publicKey.n.toString(2).length) / 8));
			result.set(blockBytes, i * blockBytes.length);
		}

		return Base64.encode(result);
	}

	/**
	 * RSA解密
	 * @param ciphertext Base64编码的密文
	 * @param privateKey 私钥(n,d)
	 * @returns 解密后的明文字符串
	 */
	export function decrypt(ciphertext: string, privateKey: { n: bigint; d: bigint }): string {
		const cipherBytes = Base64.decode(ciphertext);
		const blockSize = Math.ceil(Number(privateKey.n.toString(2).length) / 8);

		const encryptedBlocks: bigint[] = [];
		for (let i = 0; i < cipherBytes.length; i += blockSize) {
			const block = cipherBytes.slice(i, i + blockSize);
			let c = 0n;
			for (let j = 0; j < block.length; j++) {
				c = (c << 8n) | BigInt(block[j]);
			}
			encryptedBlocks.push(c);
		}

		const plainBytes: number[] = [];
		for (const c of encryptedBlocks) {
			const m = modPow(c, privateKey.d, privateKey.n);
			const bytes = bigintToBytes(m);
			for (let i = 0; i < bytes.length; i++) {
				plainBytes.push(bytes[i]);
			}
		}

		return new TextDecoder().decode(new Uint8Array(plainBytes));
	}

	/**
	 * BigInt转字节数组
	 */
	function bigintToBytes(num: bigint, minLength?: number): Uint8Array {
		let hex = num.toString(16);
		if (hex.length % 2 === 1) hex = "0" + hex;
		const bytes = new Uint8Array(hex.length / 2);
		for (let i = 0; i < bytes.length; i++) {
			bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
		}

		if (minLength && bytes.length < minLength) {
			const padded = new Uint8Array(minLength);
			padded.set(bytes, minLength - bytes.length);
			return padded;
		}
		return bytes;
	}
}

/**
 * SHA-256 哈希算法模块
 */
export namespace SHA256 {
	// 初始哈希值
	const H: number[] = [
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	];

	// 常数K
	const K: number[] = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];

	/**
	 * 循环右移
	 * @param x 数值
	 * @param n 移动位数
	 * @returns 循环右移结果
	 */
	function rotr(x: number, n: number): number {
		return ((x >>> n) | (x << (32 - n))) >>> 0;
	}

	/**
	 * 对消息进行填充
	 * @param message 原始消息字节数组
	 * @returns 填充后的消息(512位块的倍数)
	 */
	function pad(message: Uint8Array): Uint8Array {
		const ml = message.length * 8;
		const paddingLenBits = (448 - (ml + 1) % 512 + 512) % 512;
		// 0x80字节代表bit'1'和7个bit'0'，所以剩余padding bits需要转换为字节
		const paddingLenBytes = (paddingLenBits - 7) / 8;
		const result = new Uint8Array(message.length + 1 + paddingLenBytes + 8);

		result.set(message);
		result[message.length] = 0x80;

		for (let i = 0; i < 8; i++) {
			result[result.length - 8 + i] = (ml >>> (56 - i * 8)) & 0xff;
		}

		return result;
	}

	/**
	 * SHA-256哈希计算
	 * @param message 输入字符串
	 * @returns 哈希值的十六进制字符串
	 */
	export function hash(message: string): string {
		const msgBytes = new TextEncoder().encode(message);
		const padded = pad(msgBytes);
		const blocks: number[][] = [];

		for (let i = 0; i < padded.length; i += 64) {
			const block: number[] = [];
			for (let j = 0; j < 64; j += 4) {
				const word = (padded[i + j] << 24) | (padded[i + j + 1] << 16) | (padded[i + j + 2] << 8) | padded[i + j + 3];
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
				w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
			}

			let a = hash[0], b = hash[1], c = hash[2], d = hash[3];
			let e = hash[4], f = hash[5], g = hash[6], h = hash[7];

			for (let i = 0; i < 64; i++) {
				const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
				const ch = (e & f) ^ (~e & g);
				const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
				const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
				const maj = (a & b) ^ (a & c) ^ (b & c);
				const temp2 = (S0 + maj) >>> 0;

				h = g;
				g = f;
				f = e;
				e = (d + temp1) >>> 0;
				d = c;
				c = b;
				b = a;
				a = (temp1 + temp2) >>> 0;
			}

			hash[0] = (hash[0] + a) >>> 0;
			hash[1] = (hash[1] + b) >>> 0;
			hash[2] = (hash[2] + c) >>> 0;
			hash[3] = (hash[3] + d) >>> 0;
			hash[4] = (hash[4] + e) >>> 0;
			hash[5] = (hash[5] + f) >>> 0;
			hash[6] = (hash[6] + g) >>> 0;
			hash[7] = (hash[7] + h) >>> 0;
		}

		return hash.map(h => h.toString(16).padStart(8, "0")).join("");
	}
}

/**
 * SHA-512 哈希算法模块
 */
export namespace SHA512 {
	// 初始哈希值
	const H: bigint[] = [
		0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
		0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
	];

	// 常数K
	const K: bigint[] = [
		0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
		0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
		0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
		0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
		0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
		0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
		0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
		0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
		0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
		0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
		0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
		0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
		0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
		0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
		0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
		0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
		0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
		0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
		0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
		0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
	];

	/**
	 * 循环右移
	 */
	function rotr(x: bigint, n: number): bigint {
		return (x >> BigInt(n)) | (x << (64n - BigInt(n)));
	}

	/**
	 * 填充消息
	 */
	function pad(message: Uint8Array): Uint8Array {
		const ml = BigInt(message.length * 8);
		const paddingLenBits = Number((448n - (ml + 1n) % 1024n + 1024n) % 1024n);
		// 0x80字节代表bit'1'和7个bit'0'，所以剩余padding bits需要转换为字节
		const paddingLenBytes = (paddingLenBits - 7) / 8;
		const result = new Uint8Array(message.length + 1 + paddingLenBytes + 16);

		result.set(message);
		result[message.length] = 0x80;

		for (let i = 0; i < 8; i++) {
			result[result.length - 16 + i] = 0;
		}
		for (let i = 0; i < 8; i++) {
			result[result.length - 8 + i] = Number((ml >> (56n - BigInt(i * 8))) & 0xffn);
		}

		return result;
	}

	/**
	 * SHA-512哈希计算
	 * @param message 输入字符串
	 * @returns 哈希值的十六进制字符串
	 */
	export function hash(message: string): string {
		const msgBytes = new TextEncoder().encode(message);
		const padded = pad(msgBytes);
		const blocks: bigint[][] = [];

		for (let i = 0; i < padded.length; i += 128) {
			const block: bigint[] = [];
			for (let j = 0; j < 128; j += 8) {
				let word = 0n;
				for (let k = 0; k < 8; k++) {
					word = (word << 8n) | BigInt(padded[i + j + k]);
				}
				block.push(word);
			}
			blocks.push(block);
		}

		let hash = [...H];

		for (const block of blocks) {
			const w = new Array(80);
			for (let i = 0; i < 16; i++) w[i] = block[i];
			for (let i = 16; i < 80; i++) {
				const s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7n);
				const s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6n);
				w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffffffffffffn;
			}

			let a = hash[0], b = hash[1], c = hash[2], d = hash[3];
			let e = hash[4], f = hash[5], g = hash[6], h = hash[7];

			for (let i = 0; i < 80; i++) {
				const S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
				const ch = (e & f) ^ (~e & g);
				const temp1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffffffffffffn;
				const S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
				const maj = (a & b) ^ (a & c) ^ (b & c);
				const temp2 = (S0 + maj) & 0xffffffffffffffffn;

				h = g;
				g = f;
				f = e;
				e = (d + temp1) & 0xffffffffffffffffn;
				d = c;
				c = b;
				b = a;
				a = (temp1 + temp2) & 0xffffffffffffffffn;
			}

			hash[0] = (hash[0] + a) & 0xffffffffffffffffn;
			hash[1] = (hash[1] + b) & 0xffffffffffffffffn;
			hash[2] = (hash[2] + c) & 0xffffffffffffffffn;
			hash[3] = (hash[3] + d) & 0xffffffffffffffffn;
			hash[4] = (hash[4] + e) & 0xffffffffffffffffn;
			hash[5] = (hash[5] + f) & 0xffffffffffffffffn;
			hash[6] = (hash[6] + g) & 0xffffffffffffffffn;
			hash[7] = (hash[7] + h) & 0xffffffffffffffffn;
		}

		return hash.map(h => h.toString(16).padStart(16, "0")).join("");
	}
}

/**
 * SHA-3 (Keccak) 哈希算法模块
 * 实现SHA-3-256标准
 */
export namespace SHA3 {
	// 状态数组(5x5x64位)
	let state: bigint[][];
	// 速率(字节)
	const rate = 136; // 对于SHA3-256: 1088 bits = 136 bytes
	// 容量(字节)
	const capacity = 512 / 8; // 64 bytes

	/**
	 * 初始化状态
	 */
	function initialize(): void {
		state = [];
		for (let i = 0; i < 5; i++) {
			state[i] = [];
			for (let j = 0; j < 5; j++) {
				state[i][j] = 0n;
			}
		}
	}

	/**
	 * Keccak-f[1600]置换函数
	 */
	function keccakF(): void {
		const rc = [
			0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
			0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
			0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
			0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
			0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
			0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
		];

		for (let round = 0; round < 24; round++) {
			// θ步
			const c: bigint[] = new Array(5);
			for (let x = 0; x < 5; x++) {
				c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
			}
			const d: bigint[] = new Array(5);
			for (let x = 0; x < 5; x++) {
				d[x] = c[(x + 4) % 5] ^ ((c[(x + 1) % 5] << 1n) | (c[(x + 1) % 5] >> 63n));
			}
			for (let x = 0; x < 5; x++) {
				for (let y = 0; y < 5; y++) {
					state[x][y] ^= d[x];
				}
			}

			// ρ和π步
			let [x, y] = [1, 0];
			let current = state[x][y];
			for (let t = 0; t < 24; t++) {
				const [newX, newY] = [y, (2 * x + 3 * y) % 5];
				const temp = state[newX][newY];
				state[newX][newY] = ((current << BigInt(((t + 1) * (t + 2) / 2) % 64)) |
					(current >> (64n - BigInt(((t + 1) * (t + 2) / 2) % 64)))) & 0xffffffffffffffffn;
				current = temp;
				[x, y] = [newX, newY];
			}

			// χ步
			const newState: bigint[][] = [[], [], [], [], []];
			for (let x = 0; x < 5; x++) {
				for (let y = 0; y < 5; y++) {
					newState[x][y] = state[x][y] ^ ((~state[(x + 1) % 5][y]) & state[(x + 2) % 5][y]);
				}
			}
			state = newState;

			// ι步
			state[0][0] ^= rc[round];
		}
	}

	/**
	 * 吸收阶段
	 * @param data 输入数据
	 */
	function absorb(data: Uint8Array): void {
		for (let i = 0; i < data.length; i += rate) {
			const block = data.slice(i, Math.min(i + rate, data.length));
			for (let j = 0; j < block.length; j++) {
				const x = j % 5;
				const y = Math.floor(j / 5) % 5;
				const laneIndex = Math.floor(j / 25);
				if (laneIndex === 0) {
					state[x][y] ^= BigInt(block[j]) << (8n * BigInt(j % 8));
				}
			}
			keccakF();
		}
	}

	/**
	 * 挤压阶段
	 * @param outputLength 输出长度(字节)
	 * @returns 哈希值
	 */
	function squeeze(outputLength: number): Uint8Array {
		const result: number[] = [];
		while (result.length < outputLength) {
			for (let j = 0; j < rate && result.length < outputLength; j++) {
				const x = j % 5;
				const y = Math.floor(j / 5) % 5;
				const laneIndex = Math.floor(j / 25);
				if (laneIndex === 0) {
					const word = state[x][y];
					for (let k = 0; k < 8 && result.length < outputLength; k++) {
						result.push(Number((word >> (8n * BigInt(k))) & 0xffn));
					}
				}
			}
			if (result.length < outputLength) keccakF();
		}
		return new Uint8Array(result);
	}

	/**
	 * SHA-3-256哈希计算
	 * @param message 输入字符串
	 * @returns 哈希值的十六进制字符串
	 */
	export function hash256(message: string): string {
		initialize();
		const msgBytes = new TextEncoder().encode(message);

		// 添加填充
		const padded = new Uint8Array(msgBytes.length + 2);
		padded.set(msgBytes);
		padded[msgBytes.length] = 0x06;
		padded[padded.length - 1] = 0x80;

		absorb(padded);
		const result = squeeze(32);

		return Array.from(result).map(b => b.toString(16).padStart(2, "0")).join("");
	}

	/**
	 * SHA-3-512哈希计算
	 * @param message 输入字符串
	 * @returns 哈希值的十六进制字符串
	 */
	export function hash512(message: string): string {
		const rate512 = 72; // SHA3-512速率: 576 bits = 72 bytes
		initialize();
		const msgBytes = new TextEncoder().encode(message);

		const padded = new Uint8Array(msgBytes.length + 2);
		padded.set(msgBytes);
		padded[msgBytes.length] = 0x06;
		padded[padded.length - 1] = 0x80;

		for (let i = 0; i < padded.length; i += rate512) {
			const block = padded.slice(i, Math.min(i + rate512, padded.length));
			for (let j = 0; j < block.length; j++) {
				const x = j % 5;
				const y = Math.floor(j / 5) % 5;
				state[x][y] ^= BigInt(block[j]) << (8n * BigInt(j % 8));
			}
			keccakF();
		}

		const result: number[] = [];
		while (result.length < 64) {
			for (let j = 0; j < rate512 && result.length < 64; j++) {
				const x = j % 5;
				const y = Math.floor(j / 5) % 5;
				const word = state[x][y];
				for (let k = 0; k < 8 && result.length < 64; k++) {
					result.push(Number((word >> (8n * BigInt(k))) & 0xffn));
				}
			}
			if (result.length < 64) keccakF();
		}

		return result.map(b => b.toString(16).padStart(2, "0")).join("");
	}
}

/**
 * MD5哈希算法模块
 */
export namespace MD5 {
	// 初始向量
	let a0 = 0x67452301;
	let b0 = 0xefcdab89;
	let c0 = 0x98badcfe;
	let d0 = 0x10325476;

	// 移位量
	const s: number[] = [
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	];

	// 常数K
	const K: number[] = new Array(64);
	for (let i = 0; i < 64; i++) {
		K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
	}

	/**
	 * 循环左移
	 */
	function leftRotate(x: number, c: number): number {
		return (x << c) | (x >>> (32 - c));
	}

	/**
	 * 填充消息
	 */
	function pad(message: Uint8Array): Uint8Array {
		const ml = message.length * 8;
		const paddingLenBits = (448 - (ml + 1) % 512 + 512) % 512;
		// 0x80字节代表bit'1'和7个bit'0'，所以剩余padding bits需要转换为字节
		const paddingLenBytes = (paddingLenBits - 7) / 8;
		const result = new Uint8Array(message.length + 1 + paddingLenBytes + 8);

		result.set(message);
		result[message.length] = 0x80;

		for (let i = 0; i < 8; i++) {
			result[result.length - 8 + i] = (ml >>> (i * 8)) & 0xff;
		}

		return result;
	}

	/**
	 * MD5哈希计算
	 * @param message 输入字符串
	 * @returns 哈希值的十六进制字符串
	 */
	export function hash(message: string): string {
		const msgBytes = new TextEncoder().encode(message);
		const padded = pad(msgBytes);

		let a = a0, b = b0, c = c0, d = d0;

		for (let i = 0; i < padded.length; i += 64) {
			const block: number[] = [];
			for (let j = 0; j < 64; j += 4) {
				const word = (padded[i + j] | (padded[i + j + 1] << 8) | (padded[i + j + 2] << 16) | (padded[i + j + 3] << 24)) >>> 0;
				block.push(word);
			}

			let f: number, g: number;
			let aa = a, bb = b, cc = c, dd = d;

			for (let j = 0; j < 64; j++) {
				if (j < 16) {
					f = (b & c) | ((~b) & d);
					g = j;
				} else if (j < 32) {
					f = (d & b) | ((~d) & c);
					g = (5 * j + 1) % 16;
				} else if (j < 48) {
					f = b ^ c ^ d;
					g = (3 * j + 5) % 16;
				} else {
					f = c ^ (b | (~d));
					g = (7 * j) % 16;
				}

				const temp = d;
				d = c;
				c = b;
				b = b + leftRotate((a + f + K[j] + block[g]) >>> 0, s[j]);
				a = temp;
			}

			a = (a + aa) >>> 0;
			b = (b + bb) >>> 0;
			c = (c + cc) >>> 0;
			d = (d + dd) >>> 0;
		}

		const result = new Uint8Array(16);
		for (let i = 0; i < 4; i++) result[i] = (a >>> (i * 8)) & 0xff;
		for (let i = 0; i < 4; i++) result[i + 4] = (b >>> (i * 8)) & 0xff;
		for (let i = 0; i < 4; i++) result[i + 8] = (c >>> (i * 8)) & 0xff;
		for (let i = 0; i < 4; i++) result[i + 12] = (d >>> (i * 8)) & 0xff;

		return Array.from(result).map(b => b.toString(16).padStart(2, "0")).join("");
	}
}

/**
 * Base64编码解码模块
 */
export namespace Base64 {
	const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/**
	 * Base64编码
	 * @param data 字节数组
	 * @returns Base64字符串
	 */
	export function encode(data: Uint8Array): string {
		let result = "";
		for (let i = 0; i < data.length; i += 3) {
			const byte1 = data[i];
			const byte2 = i + 1 < data.length ? data[i + 1] : 0;
			const byte3 = i + 2 < data.length ? data[i + 2] : 0;

			const combined = (byte1 << 16) | (byte2 << 8) | byte3;

			const char1 = BASE64_CHARS[(combined >> 18) & 0x3f];
			const char2 = BASE64_CHARS[(combined >> 12) & 0x3f];
			const char3 = i + 1 < data.length ? BASE64_CHARS[(combined >> 6) & 0x3f] : "=";
			const char4 = i + 2 < data.length ? BASE64_CHARS[combined & 0x3f] : "=";

			result += char1 + char2 + char3 + char4;
		}
		return result;
	}

	/**
	 * Base64解码
	 * @param base64 Base64字符串
	 * @returns 解码后的字节数组
	 */
	export function decode(base64: string): Uint8Array {
		const result: number[] = [];
		const clean = base64.replace(/[^A-Za-z0-9+/=]/g, "");

		for (let i = 0; i < clean.length; i += 4) {
			const char1 = BASE64_CHARS.indexOf(clean[i]);
			const char2 = BASE64_CHARS.indexOf(clean[i + 1]);
			const char3 = clean[i + 2] === "=" ? 0 : BASE64_CHARS.indexOf(clean[i + 2]);
			const char4 = clean[i + 3] === "=" ? 0 : BASE64_CHARS.indexOf(clean[i + 3]);

			const combined = (char1 << 18) | (char2 << 12) | (char3 << 6) | char4;

			result.push((combined >> 16) & 0xff);
			if (clean[i + 2] !== "=") result.push((combined >> 8) & 0xff);
			if (clean[i + 3] !== "=") result.push(combined & 0xff);
		}

		return new Uint8Array(result);
	}
}