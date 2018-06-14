const util = require('../lib/util.js');
const nacl = require('../lib/nacl-fast.js');

/**
 * Crypto library that enable dual signing and decryption (2 of 2) without the
 * secret keys never being in the same device. It also has signatures that is
 * compatible with TweetNaCl (EdDSA). The idea is that the end device that
 * validates a signature or encrypt a message dose not have to know that the the
 * public key it works on really is an addition of two public keys and that it
 * in fact are two devices that represent that public key.
 * @class
 */

module.exports = () => {
  'use-strict';

  const secretRandomLength = 32;
  const hashLength = 64;
  const secretKeyLength = nacl.scalarMult.scalarLength + secretRandomLength;
  const publicKeyLength = nacl.scalarMult.groupElementLength;
  const { nonceLength } = nacl.box;
  const { seedLength } = nacl.sign;
  const { signatureLength } = nacl.sign;
  const cipherMessageHeaderLength = nonceLength + publicKeyLength;
  const m1HeaderLength = nacl.scalarMult.groupElementLength + publicKeyLength;
  const m2Length = signatureLength;
  const d1Length = nacl.scalarMult.groupElementLength;

  /**
     * Create key pair. The secret key is not compatible with Tweetnacl but the
     * public key is compatible with tweetnacl signing.
     *
     * @param {Array} publicKey
     * (out) The created key pairs public key
     * @param {Array} secretKey
     * (out) The created key pairs secret key
     * @param {Array} random
     * Random data used to create the key pair
     */
  function createKeyPair(publicKey, secretKey, random) {
    if (publicKey.length !== publicKeyLength) { throw new TypeError('Public key has the wrong length'); }
    if (secretKey.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }
    if (random.length !== seedLength) { throw new TypeError('Random source has the wrong length'); }

    nacl.lowlevel.crypto_hash(secretKey, random, seedLength);
    secretKey[0] &= 248;
    secretKey[31] &= 127;
    secretKey[31] |= 64;

    const tempPublicKey = calculatePublicKey(secretKey);
    publicKey.set(tempPublicKey);
  }

  /**
     * Calculate the public key from a secret key. Can be used to make any
     * scalar to a group element representation
     *
     * @param {Array} secretKey
     * The secret key to calculate the public key from
     * @return {Array} Returns the public key
     */
  function calculatePublicKey(secretKey) {
    if (secretKey.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }

    const publicKey = new Uint8Array(publicKeyLength);
    const p = createUnpackedGroupEl();
    nacl.lowlevel.scalarbase(p, secretKey);
    nacl.lowlevel.pack(publicKey, p);
    return publicKey;
  }

  /**
     * This function is used to "rotate" the two secret keys used to build up a
     * dual key (virtual key pair). The two key pairs kan be changed in such a
     * way that the addition of there two public keys still adds up to the same
     * value. Run rotateKey() on the first key pair with the parameter first sat
     * to true and then run rotateKey() on the second key pair with the param
     * first set to false. Reuse the same data for parameter random both time.
     * Parameter random is recommended to be sent between devices in a encrypted
     * channel with forward secrecy such as saltChannel
     *
     * createKeyPair(A, a, r1)
     * createKeyPair(B, b, r2)
     * C1 = addPublicKeys(A, B)
     * rotateKey(A, a, r3, true) <- Change A and a rotateKey(B, b, r3, false) <- Change B and b C1
     * addPublicKeys(A, B)
     *
     * @param {Array} publicKey
     * (out) The new public key after rotation
     * @param {Array} secretKey
     * (in/out) The earlier secret key in and the resulting secret
     * key out after rotation
     * @param {Array} random
     * Random for the scalar multiplication part. Reuse for both
     * parts in a virtual key pair
     * @param {boolean} first
     * Shall be different between the to parts of the virtual key
     * pair
     */
  function rotateKey(publicKey, secretKey, random, first) {
    if (publicKey.length !== publicKeyLength) { throw new TypeError('Public key has the wrong length'); }
    if (secretKey.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }
    if (random.length !== seedLength) { throw new TypeError('Random source has the wrong length'); }

    const tempSecretKey = new Uint8Array(secretKeyLength);
    nacl.lowlevel.crypto_hash(tempSecretKey, random, seedLength);
    const scalarDiff = new Uint8Array(tempSecretKey.subarray(0, nacl.scalarMult.scalarLength));
    scalarDiff[0] &= 248;
    scalarDiff[31] &= 127;

    // To reviewer: The new scalar might not have the second highest bit set
    // to true. This is the case in key creation.
    // It is set to true with "secretKey[31] |= 64;". The highest bit can
    // also be set to
    // true even if it should be false "scalarDiff[31] &= 127;". Will this
    // break security?
    const newScalar = first ? addScalars(secretKey, scalarDiff) : subtractScalars(secretKey, scalarDiff);

    const randomDiff = new Uint8Array(tempSecretKey.subarray(nacl.scalarMult.scalarLength, secretKeyLength));
    const oldRandom = new Uint8Array(secretKey.subarray(nacl.scalarMult.scalarLength, secretKeyLength));
    const newRandom = addScalars(oldRandom, randomDiff);
    util.arraycopy(newScalar, 0, secretKey, 0, nacl.scalarMult.scalarLength);
    util.arraycopy(newRandom, 0, secretKey, nacl.scalarMult.scalarLength, secretRandomLength);
    const tempPublicKey = calculatePublicKey(secretKey);
    util.arraycopy(tempPublicKey, 0, publicKey, 0, publicKeyLength);
  }

  /**
     * Add two scalar to each others
     *
     * @param {Array} scalarA
     * The first scalar
     * @param {Array} scalarB
     * The second scalar
     * @return {Array} The result as a scalar
     * @private
     */
  /* private */ function addScalars(scalarA, scalarB) {
    let i;
    const scalar = new Uint8Array(nacl.scalarMult.scalarLength);
    const temp = new Float64Array(64);

    for (i = 0; i < 64; i++) { temp[i] = 0; }
    for (i = 0; i < 32; i++) { temp[i] = scalarA[i] & 0xff; }
    for (i = 0; i < 32; i++) { temp[i] += scalarB[i] & 0xff; }

    nacl.lowlevel.modL(scalar, temp);
    return scalar;
  }

  /**
     * Subtract one scalar from another
     *
     * @param {Array} scalarA
     * A scalar
     * @param {Array} scalarB
     * The scalar that is subtracted from the other
     * @return {Array} The result as a scalar
     * @private
     */
  /* private */ function subtractScalars(scalarA, scalarB) {
    let i;
    const scalar = new Uint8Array(nacl.scalarMult.scalarLength);
    const temp = new Float64Array(64);

    for (i = 0; i < 64; i++) { temp[i] = 0; }
    for (i = 0; i < 32; i++) { temp[i] = scalarA[i] & 0xff; }
    for (i = 0; i < 32; i++) { temp[i] -= scalarB[i] & 0xff; }

    nacl.lowlevel.modL(scalar, temp);
    return scalar;
  }

  /**
     * Add two public keys to each others. A public key is a group element and
     * this function is also used to add group element
     *
     * @param {Array} publicKeyA
     * The first public key
     * @param {Array} publicKeyB
     * The second public key
     * @return {Array} The result as a public key
     */
  function addPublicKeys(publicKeyA, publicKeyB) {
    const a = unpack(publicKeyA);
    const b = unpack(publicKeyB);
    nacl.lowlevel.add(a, b);

    const publicKeyAB = new Uint8Array(publicKeyLength);
    nacl.lowlevel.pack(publicKeyAB, a);
    return publicKeyAB;
  }

  /**
     * Subtract one public key from another. A public key is a group element and
     * this function is also used to subtract group element
     *
     * @param {Array} publicKeyA
     * A public key
     * @param {Array} publicKeyB
     * The public key that is subtracted from the other
     * @return {Array} The result as a public key
     */
  function subtractPublicKeys(publicKeyA, publicKeyB) {
    if (publicKeyB.length !== publicKeyLength) { throw new TypeError('One public key has the wrong length'); }

    const temp = new Uint8Array(publicKeyLength);
    util.arraycopy(publicKeyB, 0, temp, 0, publicKeyLength);
    temp[31] = ((temp[31] ^ 128) | 0); // ????
    return addPublicKeys(publicKeyA, temp);
  }

  /**
     * Creates an empty unpacked group element. Just for convenience
     *
     * @return {Array} Empty unpacked group element
     * @private
     */
  /* private */ function createUnpackedGroupEl() {
    const unpackedGroupEl =
        [
          new Float64Array(16),
          new Float64Array(16),
          new Float64Array(16),
          new Float64Array(16),
        ];

    return unpackedGroupEl;
  }

  /**
     * Unpack group element. Uses unpackneg() from TweetNaclFast and changes the
     * sign
     *
     * @param {Array} packedGroupEl
     * The group element that is to be unpacked
     * @return {Array} The resulting unpacked group element
     * @private
     */
  /* private */ function unpack(packedGroupEl) {
    const unpackedGroupEl = createUnpackedGroupEl();
    const result = nacl.lowlevel.unpackneg(unpackedGroupEl, packedGroupEl);
    if (result !== 0) { throw new TypeError('Group element can not be unpacked'); }

    nacl.lowlevel.Z(unpackedGroupEl[0], nacl.lowlevel.gf0, unpackedGroupEl[0]);
    nacl.lowlevel.M(unpackedGroupEl[3], unpackedGroupEl[0], unpackedGroupEl[1]);
    return unpackedGroupEl;
  }

  /**
     * Create a EdDSA signature.
     *
     * @param {Array} message
     * The message to be signed.
     * @param {Array} publicKey
     * The public key of the signer
     * @param {Array} secretKey
     * The secret key of the signer
     * @return {Array} The signature
     */
  function signCreate(message, publicKey, secretKey) {
    if (message == null) { throw new TypeError('Message is null'); }
    if (publicKey.length !== publicKeyLength) { throw new TypeError('Public key has the wrong length'); }
    if (secretKey.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }

    const sign = new Uint8Array(m2Length + message.length);

    const pseudoRandom = calculateRand(message, secretKey);
    const randomGroupEl = calculatePublicKey(pseudoRandom);
    const hash = calculateHash(randomGroupEl, publicKey, message);
    const signature = calculateSignature(pseudoRandom, hash, secretKey);
    util.arraycopy(randomGroupEl, 0, sign, 0, nacl.scalarMult.groupElementLength);
    util.arraycopy(signature, 0, sign, nacl.scalarMult.groupElementLength, nacl.scalarMult.scalarLength);
    util.arraycopy(message, 0, sign, signatureLength, message.length);
    return sign;
  }

  /**
     * Verify a EdDSA signature.
     *
     * @param {Array} signature
     * The signature to be verified
     * @param {Array} publicKey
     * The public key to verify the signature against
     * @return {boolean} True if the signature is valid
     */
  function signVerify(signature, publicKey) {
    if (signature == null) { throw new TypeError('Signature is null'); }
    if (signature.length < signatureLength) { throw new TypeError('Signature is to short'); }
    if (publicKey.length !== publicKeyLength) { throw new TypeError('Public key has the wrong length'); }

    const tmp = new Uint8Array(signature.length);
    return nacl.lowlevel.crypto_sign_open(tmp, signature, signature.length, publicKey) >= 0;
  }

  /**
     * The first of 3 functions that together creates one valid EdDSA signature
     * from two separate key pairs. Done is such a way that that two devices
     * with separate key pairs can sign without there key pairs ever existing in
     * the same device. Before this functions is executed the key pairs public
     * keys has to be added with addPublicKeys() to get the virtualPublicKey. m1
     * and m2 is recommended to be sent in a encrypted channel with forward
     * secrecy such as saltChannel.
     *
     * *****************************************
     * Device 1 Device 2 signCreateDual1() | |-----------m1--------> | |
     * signCreateDual2() | <---------m2----------| signCreateDual3() |
     * *****************************************
     *
     * @param {Array} message
     * The message to be signed
     * @param {Array} virtualPublicKey
     * The addition of the two key pairs public keys that shall sign
     * the message.
     * @param {Array} secretKeyA
     * The first secret key of the ones that shall sign
     * @return {Array} m1 message to be used in signCreateDual2() and signCreateDual3()
     */
  function signCreateDual1(message, virtualPublicKey, secretKeyA) {
    if (message == null) { throw new TypeError('Message is null'); }
    if (virtualPublicKey.length !== publicKeyLength) { throw new TypeError('Public key has the wrong length'); }
    if (secretKeyA.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }

    const m1 = new Uint8Array(m1HeaderLength + message.length);
    const pseudoRandomA = calculateRand(message, secretKeyA);
    const randomGroupElA = calculatePublicKey(pseudoRandomA);
    util.arraycopy(virtualPublicKey, 0, m1, 0, publicKeyLength);
    util.arraycopy(randomGroupElA, 0, m1, publicKeyLength, nacl.scalarMult.groupElementLength);
    util.arraycopy(message, 0, m1, m1HeaderLength, message.length);
    return m1;
  }

  /**
     * See description in signCreateDual1()
     *
     * @param {Array} m1
     * The m1 message from signCreateDual1
     * @param {Array} secretKeyB
     * The second secret key of the ones that shall sign
     * @return {Array} m2 message to be used in signCreateDual3()
     */
  function signCreateDual2(m1, secretKeyB) {
    if (m1.length < m1HeaderLength) { throw new TypeError('M1 message is to short'); }
    if (secretKeyB.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }
 
    const m2 = new Uint8Array(m2Length);
    const virtualPublicKey = new Uint8Array(m1.subarray(0, publicKeyLength));
    const randomGroupElA = new Uint8Array(m1.subarray(publicKeyLength, m1HeaderLength));
    const message = new Uint8Array(m1.subarray(m1HeaderLength, m1.length));
    const pseudoRandomB = calculateRand(message, secretKeyB);
    const randomGroupElB = calculatePublicKey(pseudoRandomB);
    const randomGroupEl = addPublicKeys(randomGroupElA, randomGroupElB);
    const hash = calculateHash(randomGroupEl, virtualPublicKey, message);
    const signatureB = calculateSignature(pseudoRandomB, hash, secretKeyB);
    util.arraycopy(randomGroupElB, 0, m2, 0, nacl.scalarMult.groupElementLength);
    util.arraycopy(signatureB, 0, m2, nacl.scalarMult.groupElementLength, nacl.scalarMult.scalarLength);
    return m2;
  }

  /**
     * See description in signCreateDual1()
     *
     * @param {Array} m1
     * The m1 message from signCreateDual1
     * @param {Array} m2
     * The m2 message from signCreateDual2
     * @param {Array} publicKeyA
     * The public key of the secret key used
     * @param {Array} secretKeyA
     * The first secret key of the ones that shall sign
     * @return {Array} The signature
     */
  function signCreateDual3(m1, m2, publicKeyA, secretKeyA) {
    if (m1.length < m1HeaderLength) { throw new TypeError('M1 message is to short'); }
    if (m2.length !== m2Length) { throw new TypeError('M2 message has the wrong length'); }
    if (publicKeyA.length !== publicKeyLength) { throw new TypeError('Public key has the wrong length'); }
    if (secretKeyA.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }

    const virtualPublicKey = new Uint8Array(m1.subarray(0, publicKeyLength));
    const message = new Uint8Array(m1.subarray(m1HeaderLength, m1.length));
    const randomGroupElB = new Uint8Array(m2.subarray(0, nacl.scalarMult.groupElementLength));
    const signatureB = new Uint8Array(m2.subarray(nacl.scalarMult.groupElementLength, m2Length));

    const sign = new Uint8Array(signatureLength + message.length);
    const pseudoRandomA = calculateRand(message, secretKeyA);
    const randomGroupElA = calculatePublicKey(pseudoRandomA);
    const randomGroupEl = addPublicKeys(randomGroupElA, randomGroupElB);
    const hash = calculateHash(randomGroupEl, virtualPublicKey, message);
    const publicKeyB = subtractPublicKeys(virtualPublicKey, publicKeyA);
    if (!validateSignatureSpecial(publicKeyB, randomGroupElB, signatureB, hash)) { throw new Error('M2 do not validate correctly'); }

    const signatureA = calculateSignature(pseudoRandomA, hash, secretKeyA);
    const signature = addScalars(signatureA, signatureB);
    util.arraycopy(randomGroupEl, 0, sign, 0, nacl.scalarMult.groupElementLength);
    util.arraycopy(signature, 0, sign, nacl.scalarMult.groupElementLength, nacl.scalarMult.scalarLength);
    util.arraycopy(message, 0, sign, signatureLength, message.length);
    return sign;
  }

  /**
     * Function used to create the pseudo random used used in a EdDSA signature
     *
     * @param {Array} message
     * The signature message used as seed to the random
     * @param {Array} secretKey
     * The secret key used as seed to the random
     * @return {Array} The pseudo random
     * @private
     */
  /* private */ function calculateRand(message, secretKey) {
    const rand = new Uint8Array(hashLength);
    const tempBuffer = new Uint8Array(secretRandomLength + message.length);

    util.arraycopy(secretKey, nacl.scalarMult.scalarLength, tempBuffer, 0, secretRandomLength);
    util.arraycopy(message, 0, tempBuffer, secretRandomLength, message.length);
    nacl.lowlevel.crypto_hash(rand, tempBuffer, secretRandomLength + message.length);
    nacl.lowlevel.reduce(rand);
    return rand;
  }

  /**
     * Used to calculate the hash used in both verify and create EdDSA
     * signatures
     *
     * @param {Array} randomGroupEl
     * The pseudo random point used in the signature
     * @param {Array} publicKey
     * The public key of the signature
     * @param {Array} message
     * The message of the signature
     * @return {Array} The hash value.
     * @private
     */
  /* private */ function calculateHash(randomGroupEl, publicKey, message) {
    const hash = new Uint8Array(hashLength);
    const tempBuffer = new Uint8Array(nacl.scalarMult.groupElementLength + publicKeyLength + message.length);

    util.arraycopy(randomGroupEl, 0, tempBuffer, 0, nacl.scalarMult.groupElementLength);
    util.arraycopy(publicKey, 0, tempBuffer, nacl.scalarMult.groupElementLength, publicKeyLength);
    util.arraycopy(message, 0, tempBuffer, nacl.scalarMult.groupElementLength + publicKeyLength, message.length);
    nacl.lowlevel.crypto_hash(hash, tempBuffer, tempBuffer.length);
    nacl.lowlevel.reduce(hash);
    return hash;
  }

  /**
     * The calculation of the scalars in a EdDSA signature
     *
     * @param {Array} rand
     * The pseudo random
     * @param {Array} hash
     * The hash value
     * @param {Array} secretKey
     * The secret key
     * @return {Array} The scalar to be included in the signature
     * @private
     */
  /* private */ function calculateSignature(rand, hash, secretKey) {
    const signature = new Uint8Array(nacl.scalarMult.scalarLength);
    let i;
    let j;
    const x = new Float64Array(64);

    for (i = 0; i < 64; i++) { x[i] = 0; }
    for (i = 0; i < 32; i++) { x[i] = rand[i] & 0xff; }
    for (i = 0; i < 32; i++) {
      for (j = 0; j < 32; j++) { x[i + j] += (hash[i] & 0xff) * (secretKey[j] & 0xff); }
    }

    nacl.lowlevel.modL(signature, x);
    return signature;
  }

  /**
     * In signCreateDual3() the function validates m2. M2 is quite close to a
     * signature with the difference how the hash is calculated. So this
     * function do the exact same as a usual EdDSA verify dose with the
     * exception that the hash comes from a parameter.
     *
     * @param {Array} publicKey
     * The public key the signature sghall be validated agains
     * @param {Array} randomGroupEl
     * The first part of the signature
     * @param {Array} signature
     * The second part of the signature
     * @param {Array} hash
     * The hash used in the validation
     * @return {boolean} True if valid
     * @private
     */
  /* private */ function validateSignatureSpecial(publicKey, randomGroupEl, signature, hash) {
    const p = createUnpackedGroupEl();
    const q = createUnpackedGroupEl();
    const t = new Uint8Array(nacl.scalarMult.groupElementLength);

    if (nacl.lowlevel.unpackneg(q, publicKey) !== 0) { return false; }
    nacl.lowlevel.scalarmult(p, q, hash);
    nacl.lowlevel.scalarbase(q, signature);
    nacl.lowlevel.add(p, q);
    nacl.lowlevel.pack(t, p);
    return nacl.lowlevel.crypto_verify_32(randomGroupEl, 0, t, 0) === 0;
  }

  /**
     * Encryption a message with forward secrecy if random is forgotten. Uses
     * Ed25519
     *
     * @param {Array} message
     * The message to be encrypted
     * @param {Array} nonce
     * The nonce use
     * @param {Array} toPublicKey
     * The public key to encrypt to
     * @param {Array} random
     * Random
     * @return {Array} The cipher message
     */
  function encrypt(message, nonce, toPublicKey, random) {
    if (message == null) { throw new TypeError('The message is null'); }
    if (nonce.length !== nonceLength) { throw new TypeError('Nonce has the wrong length'); }
    if (toPublicKey.length !== publicKeyLength) { throw new TypeError('Public key has the wrong length'); }
    if (random.length !== seedLength) { throw new TypeError('Random seed has the wrong length'); }

    const tempPublicKey = new Uint8Array(publicKeyLength);
    const tempSecretKey = new Uint8Array(secretKeyLength);
    const sharedGroupEl = new Uint8Array(nacl.scalarMult.groupElementLength);
    createKeyPair(tempPublicKey, tempSecretKey, random);

    const p = createUnpackedGroupEl();
    const q = unpack(toPublicKey);
    nacl.lowlevel.scalarmult(p, q, tempSecretKey);
    nacl.lowlevel.pack(sharedGroupEl, p);
    const cipherText = encryptWithSharedGroupEl(message, nonce, sharedGroupEl);

    const cipherMessage = new Uint8Array(cipherMessageHeaderLength + cipherText.length);
    util.arraycopy(nonce, 0, cipherMessage, 0, nonceLength);
    util.arraycopy(tempPublicKey, 0, cipherMessage, nonceLength, publicKeyLength);
    util.arraycopy(cipherText, 0, cipherMessage, cipherMessageHeaderLength, cipherText.length);
    return cipherMessage;
  }

  /**
     * Decryption function
     *
     * @param {Array} cipherMessage
     * The cipher message
     * @param {Array} nonce
     * (out) The nonce that was use in hte encryption
     * @param {Array} secretKey
     * The secret key encrypted to
     * @return {Array} The decrypted message
     */
  function decrypt(cipherMessage, nonce, secretKey) {
    if (cipherMessage.length <= cipherMessageHeaderLength) { throw new TypeError('The cipher message is to short'); }
    if (nonce.length !== nonceLength) { throw new TypeError('Nonce has the wrong length'); }
    if (secretKey.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }

    const cipherText = new Uint8Array(cipherMessage.subarray(cipherMessageHeaderLength, cipherMessage.length));
    util.arraycopy(cipherMessage, 0, nonce, 0, nonceLength);
    const sharedGroupEl = decryptDual1(cipherMessage, secretKey);
    return decryptWithSharedGroupEl(cipherText, nonce, sharedGroupEl);
  }

  /**
     * The first of 2 functions that together can decrypt a cipher message from
     * encrypt() encrypted to an virtual key pair. d1 is recommended to be sent
     * in a encrypted channel with forward secrecy such as saltChannel
     * ***************************************** Device 1 Device 2
     * decryptDual1() | |-----------d1--------> | | decryptDual2()
     * *****************************************
     *
     * @param {Array} cipherMessage
     * The cipher message to be decrypted
     * @param {Array} secretKeyA
     * The first secret key to be used in hte decryption
     * @return {Array} d1 a message used in decryptDual2() to finish the decryption
     */
  function decryptDual1(cipherMessage, secretKeyA) {
    if (cipherMessage.length <= cipherMessageHeaderLength) { throw new TypeError('The cipher message is to short'); }
    if (secretKeyA.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }

    const d1 = new Uint8Array(d1Length);
    const tempPublicKey = new Uint8Array(cipherMessage.subarray(nonceLength, cipherMessageHeaderLength));
    const p = createUnpackedGroupEl();
    const q = unpack(tempPublicKey);
    nacl.lowlevel.scalarmult(p, q, secretKeyA);
    nacl.lowlevel.pack(d1, p);
    return d1;
  }

  /**
         * See description in decryptDual1()
         *
         * @param {Array} d1
         * d1 a message from decryptDual1()
         * @param {Array} cipherMessage
         * The cipher message to be decrypted
         * @param {Array} nonce
         * (out) The nonce that was use in hte encryption
         * @param {Array} secretKeyB
         * The second secret key to be used in hte decryption
         * @return {Array} The decrypted message
         */
  function decryptDual2(d1, cipherMessage, nonce, secretKeyB) {
    if (d1.length !== d1Length) { throw new TypeError('D1 has the wrong length'); }
    if (cipherMessage.length <= cipherMessageHeaderLength) { throw new TypeError('The cipher message is to short'); }
    if (nonce.length !== nonceLength) { throw new TypeError('Nonce has the wrong length'); }
    if (secretKeyB.length !== secretKeyLength) { throw new TypeError('Secret key has the wrong length'); }

    util.arraycopy(cipherMessage, 0, nonce, 0, nonceLength);
    const tempPublicKey = new Uint8Array(cipherMessage.subarray(nonceLength, cipherMessageHeaderLength));
    const cipherText = new Uint8Array(cipherMessage.subarray(cipherMessageHeaderLength, cipherMessage.length));

    const sharedGroupEl = new Uint8Array(nacl.scalarMult.groupElementLength);
    const p = createUnpackedGroupEl();
    let q = unpack(tempPublicKey);
    nacl.lowlevel.scalarmult(p, q, secretKeyB);
    q = unpack(d1);
    nacl.lowlevel.add(p, q);
    nacl.lowlevel.pack(sharedGroupEl, p);
    return decryptWithSharedGroupEl(cipherText, nonce, sharedGroupEl);
  }

  /**
     * Encrypt a message with a shared group element. A wrapper around the
     * TweetNaCl functions to not have to handel all buffers in the higher
     * layers
     *
     * @param {Array} message
     * Message to be encrypted
     * @param {Array} nonce
     * The nonce
     * @param {Array} sharedGroupEl
     * The shared group element used as key
     * @return {Array} The cipher text
     * @private
     */
  /* private */ function encryptWithSharedGroupEl(message, nonce, sharedGroupEl) {
    const sharedKey = new Uint8Array(nacl.box.sharedKeyLength);
    nacl.lowlevel.crypto_core_hsalsa20(sharedKey, nacl.lowlevel._0, sharedGroupEl, nacl.lowlevel.sigma);

    const messageBuffer = new Uint8Array(nacl.lowlevel.crypto_box_ZEROBYTES + message.length);
    const cipherBuffer = new Uint8Array(messageBuffer.length);
    util.arraycopy(message, 0, messageBuffer, nacl.lowlevel.crypto_box_ZEROBYTES, message.length);
    nacl.lowlevel.crypto_box_afternm(cipherBuffer, messageBuffer, messageBuffer.length, nonce, sharedKey);
    return new Uint8Array(cipherBuffer.subarray(nacl.lowlevel.crypto_box_BOXZEROBYTES, cipherBuffer.length));
  }

  /**
         * Decrypt a cipher text with a shared group element. A wrapper around the
         * TweetNaCl functions to not have to handel all buffers in the higher
         * layers
         *
         * @param {Array} cipherText
         * Data to be decrypted
         * @param {Array} nonce
         * The nonce
         * @param {Array} sharedGroupEl
         * The shared group element used as key
         * @return {Array} The decrypted message
         * @private
         */
  /* private */ function decryptWithSharedGroupEl(cipherText, nonce, sharedGroupEl) {
    const sharedKey = new Uint8Array(nacl.box.sharedKeyLength);
    nacl.lowlevel.crypto_core_hsalsa20(sharedKey, nacl.lowlevel._0, sharedGroupEl, nacl.lowlevel.sigma);
    const cipherBuffer = new Uint8Array(nacl.lowlevel.crypto_box_BOXZEROBYTES + cipherText.length);
    const messageBuffer = new Uint8Array(cipherBuffer.length);
    util.arraycopy(cipherText, 0, cipherBuffer, nacl.lowlevel.crypto_box_BOXZEROBYTES, cipherText.length);

    if (nacl.lowlevel.crypto_secretbox_open(messageBuffer, cipherBuffer, cipherBuffer.length, nonce, sharedKey) !== 0) { throw new Error('Can not decrypt message'); }
    return new Uint8Array(messageBuffer.subarray(nacl.lowlevel.crypto_box_ZEROBYTES, messageBuffer.length));
  }

  return {
    /* public properties */
    secretKeyLength,
    publicKeyLength,
    nonceLength,
    seedLength,

    /* public functions */
    addScalars, /* made public for testing */

    createKeyPair,
    calculatePublicKey,
    rotateKey,
    addPublicKeys,
    subtractPublicKeys,
    signCreate,
    signVerify,
    signCreateDual1,
    signCreateDual2,
    signCreateDual3,
    encrypt,
    decrypt,
    decryptDual1,
    decryptDual2,
  };
};
