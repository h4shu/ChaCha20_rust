use std::u32;

fn qround(state: &mut [u32; 16], x: usize, y: usize, z: usize, w: usize) {
	state[x] = state[x].wrapping_add(state[y]);
	state[w] = state[w] ^ state[x];
	state[w] = state[w].rotate_left(16);

	state[z] = state[z].wrapping_add(state[w]);
	state[y] = state[y] ^ state[z];
	state[y] = state[y].rotate_left(12);

	state[x] = state[x].wrapping_add(state[y]);
	state[w] = state[w] ^ state[x];
	state[w] = state[w].rotate_left(8);

	state[z] = state[z].wrapping_add(state[w]);
	state[y] = state[y] ^ state[z];
	state[y] = state[y].rotate_left(7);
}

fn inner_block(state: &mut [u32; 16]) {
	qround(state, 0, 4, 8, 12);
	qround(state, 1, 5, 9, 13);
	qround(state, 2, 6, 10, 14);
	qround(state, 3, 7, 11, 15);
	qround(state, 0, 5, 10, 15);
	qround(state, 1, 6, 11, 12);
	qround(state, 2, 7, 8, 13);
	qround(state, 3, 4, 9, 14);
}

fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
	let state: [u32; 16] = [
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		key[0], key[1], key[2], key[3],
		key[4], key[5], key[6], key[7],
		counter, nonce[0], nonce[1], nonce[2]
	];
	let mut working_state: [u32; 16] = state;
	for _i in 0..10 {
		inner_block(&mut working_state);
	}
	for i in 0..16 {
		working_state[i] = working_state[i].wrapping_add(state[i]);
	}
	working_state
}

fn chacha20_encrypt(key: &[u32; 8], counter: u32, nonce: &[u32; 3], plaintext: &Vec<u8>) -> Vec<u8> {
	let mut encrypted_message: Vec<u8> = Vec::new();
	let mut key_stream: [u32; 16];
	let mut block: u32;
	let mut block4: [u8; 4] = [0; 4];
	let length: usize  = plaintext.len();
	let quot: usize = length / 64;
	let mut j: usize = 0;
	while j < quot {
		key_stream = chacha20_block(key, counter + (j as u32), nonce);
		for i in 0..16 {
			block4.copy_from_slice(plaintext.get(((j * 64) + (i * 4))..((j * 64) + ((i + 1) * 4))).unwrap());
			block = u32::from_be_bytes(block4);
			encrypted_message.append(&mut (block ^ key_stream[i].swap_bytes()).to_be_bytes().to_vec());
		}
		j = j + 1;
	}
	let rem: usize = length % 64;
	if rem != 0 {
		key_stream = chacha20_block(key, counter + (j as u32), nonce);
		let mut i: usize = 0;
		while i < (rem / 4) {
			block4.copy_from_slice(plaintext.get(((j * 64) + (i * 4))..((j * 64) + ((i + 1) * 4))).unwrap());
			block = u32::from_be_bytes(block4);
			encrypted_message.append(&mut (block ^ key_stream[i].swap_bytes()).to_be_bytes().to_vec());
			i = i + 1;
		}
		let rem4: usize = rem % 4;
		if rem4 != 0 {
			for k in 0..rem4 {
				encrypted_message.push(plaintext[(j * 64) + (i * 4) + k] ^ (((key_stream[i] >> (k * 8)) & 0xff) as u8));
			}
		}
	}
	encrypted_message
}

fn main() {
	let skey: [u32; 8] = [
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
	];
	let nonce: [u32; 3] = [0x00000000, 0x4a000000, 0x00000000];
	let block_count: u32 = 0x00000001;
	let text: String = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_string();
	let text_bytes: Vec<u8> = text.into_bytes();
	println!("text_bytes: '{:02x?}'\n", text_bytes);
	let cipher: Vec<u8> = chacha20_encrypt(&skey, block_count, &nonce, &text_bytes);
	println!("cipher: '{:02x?}'\n", cipher);
}

