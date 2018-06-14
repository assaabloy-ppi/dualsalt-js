const util = require('../lib/util.js');
const nacl = require('../lib/nacl-fast.js');
const DualSalt = require('../src/dual-salt.js');

const dualsalt = DualSalt();


module.exports = () => {
  'use-strict';

  function stringToUint8Array(string) {
    const charList = unescape(encodeURIComponent(string)).split('');
    const uintArray = [];
    for (let i = 0; i < charList.length; i++) {
      uintArray.push(charList[i].charCodeAt(0));
    }
    return new Uint8Array(uintArray);
  }


  /* private */ function testKeyAddition(rand1, rand2) {
    console.info('\nTest key addition');
    const pubKeyA = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB = new Uint8Array(dualsalt.publicKeyLength);
    const secKeyA = new Uint8Array(dualsalt.secretKeyLength);
    const secKeyB = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKeyA, secKeyA, rand1);
    dualsalt.createKeyPair(pubKeyB, secKeyB, rand2);
    const pubKeyAB1 = dualsalt.addPublicKeys(pubKeyA, pubKeyB);
    const secScalarAB = dualsalt.addScalars(secKeyA, secKeyB);
    const secSecAB = new Uint8Array(dualsalt.secretKeyLength);
    util.arraycopy(secScalarAB, 0, secSecAB, 0, nacl.scalarMult.scalarLength);
    const pubKeyAB2 = dualsalt.calculatePublicKey(secSecAB);
    if (util.uint8ArrayEquals(pubKeyAB1, pubKeyAB2)) {
      console.info('Group public key ok');
    } else {
      console.info(`Rand1: ${util.ab2hex(secKeyA)}`);
      console.info(`Rand2: ${util.ab2hex(secKeyB)}`);
      console.info(`Group public key 1: ${util.ab2hex(pubKeyAB1)}`);
      console.info(`Group public key 2: ${util.ab2hex(pubKeyAB2)}`);
      throw new Error();
    }
  }
  function testRotateKeys(rand1, rand2, rand3) {
    console.info('\nTest rotate keys');
    const pubKeyA = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB = new Uint8Array(dualsalt.publicKeyLength);
    const secKeyA = new Uint8Array(dualsalt.secretKeyLength);
    const secKeyB = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKeyA, secKeyA, rand1);
    dualsalt.createKeyPair(pubKeyB, secKeyB, rand2);
    const oldSecRandA = new Uint8Array(secKeyA.subarray(32, dualsalt.secretKeyLength));
    const oldSecRandB = new Uint8Array(secKeyB.subarray(32, dualsalt.secretKeyLength));
    const pubKeyAB1 = dualsalt.addPublicKeys(pubKeyA, pubKeyB);
    const pubKeyA2 = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB2 = new Uint8Array(dualsalt.publicKeyLength);
    dualsalt.rotateKey(pubKeyA2, secKeyA, rand3, true);
    dualsalt.rotateKey(pubKeyB2, secKeyB, rand3, false);
    if (util.uint8ArrayEquals(pubKeyA, pubKeyB) ||
        util.uint8ArrayEquals(pubKeyA, pubKeyA2) ||
        util.uint8ArrayEquals(pubKeyA, pubKeyB2) ||
        util.uint8ArrayEquals(pubKeyB, pubKeyA2) ||
        util.uint8ArrayEquals(pubKeyB, pubKeyB2) ||
        util.uint8ArrayEquals(pubKeyA2, pubKeyB2)) {
      console.info(`A2 secret key: ${util.ab2hex(secKeyA)}`);
      console.info(`B2 secret key: ${util.ab2hex(secKeyB)}`);
      console.info(`Rand: ${util.ab2hex(rand3)}`);
      console.info('Fail, Some pub keys was the same');
      throw new Error();
    }
    const newSecRandA = new Uint8Array(secKeyA.subarray(32, dualsalt.secretKeyLength));
    const newSecRandB = new Uint8Array(secKeyB.subarray(32, dualsalt.secretKeyLength));
    if (util.uint8ArrayEquals(oldSecRandA, newSecRandA) ||
        util.uint8ArrayEquals(oldSecRandB, newSecRandB) ||
        util.uint8ArrayEquals(newSecRandA, newSecRandB)) {
      console.info(`A2 secret key: ${util.ab2hex(secKeyA)}`);
      console.info(`B2 secret key: ${util.ab2hex(secKeyB)}`);
      console.info(`Rand: ${util.ab2hex(rand3)}`);
      console.info('Fail, The secret random part has not changed correctly');
      throw new Error();
    }
    const pubKeyAB2 = dualsalt.addPublicKeys(pubKeyA2, pubKeyB2);
    if (util.uint8ArrayEquals(pubKeyAB1, pubKeyAB2)) {
      console.info('Success! The rotated virtual key has the same pub key');
    } else {
      console.info(`A2 secret key: ${util.ab2hex(secKeyA)}`);
      console.info(`B2 secret key: ${util.ab2hex(secKeyB)}`);
      console.info(`Rand: ${util.ab2hex(rand3)}`);
      console.info('Fail, The rotated virtual key did not produce the same pub key ');
      throw new Error();
    }
  }
  /* private */ function testSingleSign(rand, testString) {
    console.info('\nTest single sign');
    const publicKey = new Uint8Array(dualsalt.publicKeyLength);
    const secretKey = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(publicKey, secretKey, rand);
    const message = stringToUint8Array(testString);
    const signature = dualsalt.signCreate(message, publicKey, secretKey);

    if (dualsalt.signVerify(signature, publicKey)) {
      console.info('Verified signature succeeded');
    } else {
      console.info(`Rand: ${util.ab2hex(rand)}`);
      console.info(`Test string: "${testString}"`);
      console.info('Verified signature failed');
      throw new Error();
    }
  }
  /* private */ function testNegativeSingleSign(rand, testString) {
    console.info('\nTest negative single sign');
    const publicKey = new Uint8Array(dualsalt.publicKeyLength);
    const secretKey = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(publicKey, secretKey, rand);
    const message = stringToUint8Array(testString);
    const signature = dualsalt.signCreate(message, publicKey, secretKey);

    const steps = 10;
    for (let i = 0; i <= steps; i++) {
      const j = (((signature.length - 1) * i) / steps | 0);
      const tempSignature = new Uint8Array(signature.subarray());
      tempSignature[j] = ((tempSignature[j] ^ 1) | 0);
      if (dualsalt.signVerify(tempSignature, publicKey)) {
        console.info(`Rand: ${util.ab2hex(rand)}`);
        console.info(`Test string: "${testString}"`);
        console.info('Validated succeeded but it should not');
        throw new Error();
      }
    }

    for (let i = 0; i <= steps; i++) {
      const j = (((publicKey.length - 1) * i) / steps | 0);
      const tempPublicKey = new Uint8Array(publicKey.subarray());
      tempPublicKey[j] = ((tempPublicKey[j] ^ 1) | 0);
      if (dualsalt.signVerify(signature, tempPublicKey)) {
        console.info(`Rand: ${util.ab2hex(rand)}`);
        console.info(`Test string: "${testString}"`);
        console.info('Validated succeeded but it should not');
        throw new Error();
      }
    }

    console.info('Signature validation fail when it shall');
  }
  /* private */ function testSubtractPubKey(rand1, rand2) {
    console.info('\nTest subtract pub key');
    const pubKeyA = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB = new Uint8Array(dualsalt.publicKeyLength);
    const secKeyA = new Uint8Array(dualsalt.secretKeyLength);
    const secKeyB = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKeyA, secKeyA, rand1);
    dualsalt.createKeyPair(pubKeyB, secKeyB, rand2);
    const pubKeyC = dualsalt.addPublicKeys(pubKeyA, pubKeyB);
    const pubKeyA2 = dualsalt.subtractPublicKeys(pubKeyC, pubKeyB);
    const pubKeyB2 = dualsalt.subtractPublicKeys(pubKeyC, pubKeyA);
    if (util.uint8ArrayEquals(pubKeyA, pubKeyA2) && util.uint8ArrayEquals(pubKeyB, pubKeyB2)) {
      console.info('Success! The add and subtract did produce the same public key');
    } else {
      console.info(`Random 1 key: ${util.ab2hex(rand1)}`);
      console.info(`Random 2 key: ${util.ab2hex(rand2)}`);
      console.info('Fail, The add and subtract did not produce the same public key');
      throw new Error();
    }
  }

  function testDualSign(rand1, rand2, testString) {
    console.info('\nTest dual sign');
    const pubKeyA = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB = new Uint8Array(dualsalt.publicKeyLength);
    const secKeyA = new Uint8Array(dualsalt.secretKeyLength);
    const secKeyB = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKeyA, secKeyA, rand1);
    dualsalt.createKeyPair(pubKeyB, secKeyB, rand2);
    const message = stringToUint8Array(testString);
    const virtualPublicKey = dualsalt.addPublicKeys(pubKeyA, pubKeyB);
    const m1 = dualsalt.signCreateDual1(message, virtualPublicKey, secKeyA);
    const m2 = dualsalt.signCreateDual2(m1, secKeyB);
    const signature = dualsalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);
    if (dualsalt.signVerify(signature, virtualPublicKey)) {
      console.info('Verified signature succeeded');
    } else {
      console.info(`Rand 1: ${util.ab2hex(rand1)}`);
      console.info(`Rand 2: ${util.ab2hex(rand2)}`);
      console.info(`Test string: "${testString}"`);
      console.info('Verified signature failed');
      throw new Error();
    }
  }
  /* private */ function testNegativeDualSign(rand1, rand2, testString) {
    console.info('\nTest negative dual sign');
    const pubKeyA = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB = new Uint8Array(dualsalt.publicKeyLength);
    const secKeyA = new Uint8Array(dualsalt.secretKeyLength);
    const secKeyB = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKeyA, secKeyA, rand1);
    dualsalt.createKeyPair(pubKeyB, secKeyB, rand2);
    const message = stringToUint8Array(testString);
    const virtualPublicKey = dualsalt.addPublicKeys(pubKeyA, pubKeyB);
    const m1 = dualsalt.signCreateDual1(message, virtualPublicKey, secKeyA);
    const m2 = dualsalt.signCreateDual2(m1, secKeyB);

    const steps = 10;
    for (let i = 0; i <= steps; i++) {
      const j = (((m2.length - 1) * i) / steps | 0);
      const tempM2 = new Uint8Array(m2.subarray());
      tempM2[j] = ((tempM2[j] ^ 1) | 0);
      try {
        dualsalt.signCreateDual3(m1, tempM2, pubKeyA, secKeyA);
        console.info(`Rand1: ${util.ab2hex(rand1)}`);
        console.info(`Rand2: ${util.ab2hex(rand2)}`);
        console.info(`Test string: "${testString}"`);
        console.info('Validated succeeded but it should not');
        throw new Error();
      } catch (iae) {
        // do nothing
      }
    }

    for (let i = 0; i <= steps; i++) {
      const j = (((pubKeyA.length - 1) * i) / steps | 0);
      const tempPubKeyA = new Uint8Array(pubKeyA.subarray());
      tempPubKeyA[j] = ((tempPubKeyA[j] ^ 1) | 0);
      try {
        dualsalt.signCreateDual3(m1, m2, tempPubKeyA, secKeyA);
        console.info(`Rand1: ${util.ab2hex(rand1)}`);
        console.info(`Rand2: ${util.ab2hex(rand2)}`);
        console.info(`Test string: "${testString}"`);
        console.info('Validated succeeded but it should not');
        throw new Error();
      } catch (iae) {
        // do nothing
      }
    }

    console.info('Signature validation fail when it shall');
  }

  function testSingleDecrypt(rand1, rand2, rand3, testString) {
    console.info('\nTest single decrypt');
    const nonce = new Uint8Array(dualsalt.nonceLength);
    const pubKey = new Uint8Array(dualsalt.publicKeyLength);
    const secKey = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKey, secKey, rand1);
    const message = stringToUint8Array(testString);
    const cipherMessage = dualsalt.encrypt(message, rand2, pubKey, rand3);
    console.info(`Cipher message:  ${util.ab2hex(cipherMessage)}`);
    const decryptedMessage = dualsalt.decrypt(cipherMessage, nonce, secKey);
    if (util.uint8ArrayEquals(rand2, nonce) && util.uint8ArrayEquals(message, decryptedMessage)) {
      console.info('Decrypt message succeeded');
    } else {
      console.info(`Nonce:  ${util.ab2hex(nonce)}`);
      console.info(`Rand 2: ${util.ab2hex(rand2)}`);
      console.info(`Message:  ${util.ab2hex(message)}`);
      console.info(`DMessage: ${util.ab2hex(decryptedMessage)}`);
      console.info(`Rand 1: ${util.ab2hex(rand1)}`);
      console.info(`Rand 2: ${util.ab2hex(rand2)}`);
      console.info(`Rand 3: ${util.ab2hex(rand3)}`);
      console.info(`Test string: "${testString}"`);
      console.info('Decrypt message failed');
      throw new Error();
    }
  }
  /* private */ function testNegativeSingleDecrypt(rand1, rand2, rand3, testString) {
    console.info('\nTest negative single decrypt');
    const nonce = new Uint8Array(dualsalt.nonceLength);
    const pubKey = new Uint8Array(dualsalt.publicKeyLength);
    const secKey = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKey, secKey, rand1);
    const message = stringToUint8Array(testString);
    const cipherMessage = dualsalt.encrypt(message, rand2, pubKey, rand3);
    console.info(`Cipher message:  ${util.ab2hex(cipherMessage)}`);

    const steps = 10;
    for (let i = 0; i <= steps; i++) {
      const j = (((cipherMessage.length - 1) * i) / steps | 0);
      const tempCipherMessage = new Uint8Array(cipherMessage.subarray());
      tempCipherMessage[j] = ((tempCipherMessage[j] ^ 1) | 0);
      try {
        dualsalt.decrypt(tempCipherMessage, nonce, secKey);
        console.info(`Nonce:  ${util.ab2hex(nonce)}`);
        console.info(`Rand 2: ${util.ab2hex(rand2)}`);
        console.info(`Message:  ${util.ab2hex(message)}`);
        console.info(`Rand 1: ${util.ab2hex(rand1)}`);
        console.info(`Rand 2: ${util.ab2hex(rand2)}`);
        console.info(`Rand 3: ${util.ab2hex(rand3)}`);
        console.info(`Test string: "${testString}"`);
        console.info('Decryption succeeded but it should not');
        throw new Error();
      } catch (iae) {
        // do nothing
      }
    }

    console.info('Message decryption validation fail when it shall');
  }
  function testDualDecrypt(rand1, rand2, rand3, rand4, testString) {
    console.info('\nTest dual decrypt');
    const nonce = new Uint8Array(dualsalt.nonceLength);
    const pubKeyA = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB = new Uint8Array(dualsalt.publicKeyLength);
    const secKeyA = new Uint8Array(dualsalt.secretKeyLength);
    const secKeyB = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKeyA, secKeyA, rand1);
    dualsalt.createKeyPair(pubKeyB, secKeyB, rand2);
    const pubKeyAB = dualsalt.addPublicKeys(pubKeyA, pubKeyB);
    const message = stringToUint8Array(testString);
    const cipherMessage = dualsalt.encrypt(message, rand3, pubKeyAB, rand4);
    console.info(`Cipher message: ${util.ab2hex(cipherMessage)}`);
    const d1 = dualsalt.decryptDual1(cipherMessage, secKeyA);
    const decryptedMessage = dualsalt.decryptDual2(d1, cipherMessage, nonce, secKeyB);
    if (util.uint8ArrayEquals(rand3, nonce) && util.uint8ArrayEquals(message, decryptedMessage)) {
      console.info('Decrypt message succeeded');
    } else {
      console.info(`Nonce:  ${util.ab2hex(nonce)}`);
      console.info(`Rand 2: ${util.ab2hex(rand3)}`);
      console.info(`Message:  ${util.ab2hex(message)}`);
      console.info(`Rand 1: ${util.ab2hex(rand1)}`);
      console.info(`Rand 2: ${util.ab2hex(rand2)}`);
      console.info(`Rand 3: ${util.ab2hex(rand3)}`);
      console.info(`Rand 3: ${util.ab2hex(rand4)}`);
      console.info(`Test string: "${testString}"`);
      console.info('Decrypt message failed');
      throw new Error();
    }
  }
  /* private */ function testNegativeDualDecrypt(rand1, rand2, rand3, rand4, testString) {
    console.info('\nTest negative dual decrypt');
    const nonce = new Uint8Array(dualsalt.nonceLength);
    const pubKeyA = new Uint8Array(dualsalt.publicKeyLength);
    const pubKeyB = new Uint8Array(dualsalt.publicKeyLength);
    const secKeyA = new Uint8Array(dualsalt.secretKeyLength);
    const secKeyB = new Uint8Array(dualsalt.secretKeyLength);
    dualsalt.createKeyPair(pubKeyA, secKeyA, rand1);
    dualsalt.createKeyPair(pubKeyB, secKeyB, rand2);
    const pubKeyAB = dualsalt.addPublicKeys(pubKeyA, pubKeyB);
    const message = stringToUint8Array(testString);
    const cipherMessage = dualsalt.encrypt(message, rand3, pubKeyAB, rand4);
    console.info(`Cipher message: ${util.ab2hex(cipherMessage)}`);
    const d1 = dualsalt.decryptDual1(cipherMessage, secKeyA);

    const steps = 10;
    for (let i = 0; i <= steps; i++) {
      const j = (((cipherMessage.length - 1) * i) / steps | 0);
      const tempCipherMessage = new Uint8Array(cipherMessage.subarray());
      tempCipherMessage[j] = ((tempCipherMessage[j] ^ 1) | 0);
      try {
        dualsalt.decryptDual2(d1, tempCipherMessage, nonce, secKeyB);
        console.info(`Nonce:  ${util.ab2hex(nonce)}`);
        console.info(`Rand 2: ${util.ab2hex(rand2)}`);
        console.info(`Message:  ${util.ab2hex(message)}`);
        console.info(`Rand 1: ${util.ab2hex(rand1)}`);
        console.info(`Rand 2: ${util.ab2hex(rand2)}`);
        console.info(`Rand 3: ${util.ab2hex(rand3)}`);
        console.info(`Test string: "${testString}"`);
        console.info('Decryption succeeded but it should not');
        throw new Error();
      } catch (iae) {
        // do nothing
      }
    }

    for (let i = 0; i <= steps; i++) {
      const j = (((d1.length - 1) * i) / steps | 0);
      const tempD1 = new Uint8Array(d1.subarray());
      tempD1[j] = ((tempD1[j] ^ 1) | 0);
      try {
        dualsalt.decryptDual2(tempD1, cipherMessage, nonce, secKeyB);
        console.info(`Nonce:  ${util.ab2hex(nonce)}`);
        console.info(`Rand 2: ${util.ab2hex(rand2)}`);
        console.info(`Message:  ${util.ab2hex(message)}`);
        console.info(`Rand 1: ${util.ab2hex(rand1)}`);
        console.info(`Rand 2: ${util.ab2hex(rand2)}`);
        console.info(`Rand 3: ${util.ab2hex(rand3)}`);
        console.info(`Test string: "${testString}"`);
        console.info('Decryption succeeded but it should not');
        throw new Error();
      } catch (iae) { 
        // do nothing
      }
    }

    console.info('Message decryption validation fail when it shall');
  }
  /* private */ function run() {
    try {
      const rand1 = util.hex2Uint8Array('ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135');
      const rand2 = util.hex2Uint8Array('e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02');
      const rand3 = util.hex2Uint8Array('995afd8c14adb49410ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4');
      const nonce = util.hex2Uint8Array('10ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4');
      testKeyAddition(rand1, rand2);
      testKeyAddition(rand1, rand3);
      testKeyAddition(rand2, rand3);
      testRotateKeys(rand1, rand2, rand3);
      testRotateKeys(rand1, rand3, rand2);
      testRotateKeys(rand2, rand3, rand1);
      testSingleSign(rand1, 'The best signature in the world');
      testSingleSign(rand2, 'The best signature in the all the worlds, You know like all all');
      testSingleSign(rand3, 'There could be only one ultimate signature and this is it. Stop arguing');
      testSubtractPubKey(rand1, rand2);
      testSubtractPubKey(rand1, rand3);
      testSubtractPubKey(rand2, rand3);
      testDualSign(rand1, rand2, "The best signature in the world");
      testDualSign(rand1, rand3, "The best signature in the all the worlds, You know like all all");
      testDualSign(rand2, rand3, "There could be only one ultimate signature and this is it. Stop arguing");
      testSingleDecrypt(rand1, nonce, rand2, "The best decryption in the world");
      testSingleDecrypt(rand1, nonce, rand3, "The best decryption in the all the worlds, You know like all all");
      testSingleDecrypt(rand2, nonce, rand3, "There could be only one ultimate decryption and this is it. Stop arguing");
      testDualDecrypt(rand1, rand2, nonce, rand3, "The best decryption in the world");
      testDualDecrypt(rand3, rand1, nonce, rand2, "The best decryption in the all the worlds, You know like all all");
      testDualDecrypt(rand2, rand3, nonce, rand1, "There could be only one ultimate decryption and this is it. Stop arguing");
      testNegativeSingleSign(rand1, "The best signature in the world");
      testNegativeSingleSign(rand2, "The best signature in the all the worlds, You know like all all");
      testNegativeSingleSign(rand3, "There could be only one ultimate signature and this is it. Stop arguing");
      testNegativeDualSign(rand1, rand2, "The best signature in the world");
      testNegativeDualSign(rand1, rand3, "The best signature in the all the worlds, You know like all all");
      testNegativeDualSign(rand2, rand3, "There could be only one ultimate signature and this is it. Stop arguing");
      testNegativeSingleDecrypt(rand1, nonce, rand2, "The best decryption in the world");
      testNegativeSingleDecrypt(rand1, nonce, rand3, "The best decryption in the all the worlds, You know like all all");
      testNegativeSingleDecrypt(rand2, nonce, rand3, "There could be only one ultimate decryption and this is it. Stop arguing");
      testNegativeDualDecrypt(rand1, rand2, nonce, rand3, "The best decryption in the world");
      testNegativeDualDecrypt(rand3, rand1, nonce, rand2, "The best decryption in the all the worlds, You know like all all");
      testNegativeDualDecrypt(rand2, rand3, nonce, rand1, "There could be only one ultimate decryption and this is it. Stop arguing");
    } catch (e) {
      console.error(e.message, e);
      return;
    }

    console.info('\nSUCCESS! All tests passed.');
  }

  return {
    run,
  };
};
