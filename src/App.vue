<template>
  <div id="app">
    <h1>fx-encode-demo</h1>
  </div>
</template>
<script>
import Aes256Gcm from './utils/aes';

const eccrypto = require('eccrypto');
const crypto = require('crypto');

const compressedPublickeyA = '03362772a97f5c07bd655d99e8094695f2e2d1da5baf3453261b1ef47f8c9dc62d';
const privatekeyB = 'f1f6d86c8f7ebed650167444fea5cd47230f0ddadb61169165d0ffa61e64cd3e';
const publickeyB = '04d7f20779eeaf7421e561b758539022d26eb162f52fd6c9f50186996fcd10d4dcffc9f36ed5b290e928f8e7c0c25ee508a3b6969f04c128de87144906a55a1350';
const publickeyA = '04362772a97f5c07bd655d99e8094695f2e2d1da5baf3453261b1ef47f8c9dc62dcae4cc37682acea1f6245e40bcf8495bcc33d6b1ca7f746ad467c79dc7e0eb3b';
const privatekeyB = 'f1f6d86c8f7ebed650167444fea5cd47230f0ddadb61169165d0ffa61e64cd3e';

export default {
  created() {
    this.init();
  },
  methods: {
    async init() {
      // Began to encrypt
      const { nonce, encrypt, mac } = await this.encode({ privatekeyB, compressedPublickeyA });

      // Began to decrypt
      await this.decode(nonce, encrypt, mac);
    },

    async getSharedKey() {
      const sharedKey1Buffer = await eccrypto
      .derive(new Buffer(privatekeyA, "hex"), new Buffer(publickeyB, "hex"))
        .then((Key) => {
          console.log('sharedKey1>>', Key.toString('hex'));
          return Key;
        });


      const sharedKey2Buffer = await eccrypto
        .derive(new Buffer(privatekeyB, 'hex'), new Buffer(publickeyA, 'hex'))
        .then((key) => {
          console.log('sharedKey2>>', key.toString('hex'));
          return key;
        });


      let sharedKey = '';
      if (
        sharedKey1Buffer.toString('hex') === sharedKey2Buffer.toString('hex')
      ) {
        sharedKey = sharedKey1Buffer.toString('hex');
      }

      return sharedKey
    },

    async encode({ privatekeyB, publickeyA }) {
      const privatekeyBBuffer = Buffer.from(privatekeyB, 'hex');
      const publickeyABuffer = Buffer.from(publickeyA, 'hex');

      const sharedKey = await this.getSharedKey();
      const hash = crypto.createHash('sha256').update(sharedKey, 'hex', 'hex').digest();
      const key = hash.slice(16);
      const mackey = hash.slice(0, 16);
      const nonce = 'a1587bf79eec0edb9a91fc99';
      const text = 'Hello, Jack!';
      const { ciphertext, tag } = Aes256Gcm.encode(text, key, nonce);
      const encrypt = ciphertext + tag;

      const newMackey = Buffer.concat([
        Buffer.from(key, 'hex'),
        Buffer.from(nonce, 'hex'),
        Buffer.from(encrypt, 'hex'),
      ]);

      const mac = crypto.createHmac('sha256', mackey).update(newMackey).digest();

      return {
        nonce,
        encrypt,
        mac,
      };
    },

    async decode(nonce, encrypt, mac) {
      const privatekeyBBuffer = Buffer.from(privatekeyB, 'hex');
      const publickeyABuffer = Buffer.from(publickeyA, 'hex');

      const sharedKey2Buffer = await eccrypto
        .derive(privatekeyBBuffer, publickeyABuffer).then((key) => key);

      const hash = crypto.createHash('sha256').update(sharedKey2Buffer, 'hex', 'hex').digest();
      const key = hash.slice(16);
      const mackey = hash.slice(0, 16);

      const newMackey = Buffer.concat([
        new Buffer(key, 'hex'),
        new Buffer(nonce, 'hex'),
        new Buffer(encrypt, 'hex'),
      ]);

      const newMac = crypto
        .createHmac('sha256', mackey)
        .update(newMackey)
        .digest();

      if (newMac.toString('hex') === mac.toString('hex')) {
        const decrypt = Aes256Gcm.decode(encrypt, key, new Buffer(nonce, 'hex'));
        console.log('decryp>>', decrypt);
      }
    },
  },
};
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

#nav {
  padding: 30px;
}

#nav a {
  font-weight: bold;
  color: #2c3e50;
}

#nav a.router-link-exact-active {
  color: #42b983;
}
</style>
