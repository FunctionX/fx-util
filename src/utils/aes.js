const crypto = require('crypto');

const ALGORITHM = 'aes-128-gcm';

class Aes256Gcm {
  /**
   * @param text: String
   * @param key: String
   * @param nonce: string
   * @return {{ciphertext: string, tag: string, iv: Buffer, key: Buffer}}
   */
  static encode(text, key, nonce) {
    const keyBuffer = key;
    const iv = new Buffer(nonce, 'hex');
    const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);
    let ciphertext = cipher.update(text, 'utf8', 'hex');
    ciphertext += cipher.final('hex');

    return {
      ciphertext,
      keyBuffer,
      iv: Buffer.from(iv, 'hex'),
      tag: cipher.getAuthTag().toString('hex'),
    };
  }

  /**
   * @param ciphertext
   * @param keyBuffer
   * @param iv
   * @param tag
   * @return {string}
   */
  static decode(ciphertext, keyBuffer, iv, tag) {
    const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv);

    if (!tag) {
      tag = ciphertext.slice(-32);
      const arr = ciphertext.split('');
      arr.splice(-32, 32);
      ciphertext = arr.join('');
    }

    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let cleartext = decipher.update(ciphertext, 'hex', 'utf8');
    cleartext += decipher.final('utf8');

    return cleartext;
  }
}

/**
 * use example
 * const text = "valuetest123";
 * const key = "AES256Key-32Characters1234567890";
 * const nonce = "a1587bf79eec0edb9a91fc99";
 * const testb = Aes256Gcm.encode(text, key, nonce)
 * Aes256Gcm.decode(testb.ciphertext, testb.keyBuffer, testb.iv, testb.tag)
 */
export default Aes256Gcm;
