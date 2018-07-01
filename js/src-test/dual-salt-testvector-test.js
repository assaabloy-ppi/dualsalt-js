const util = require('../lib/util.js');
//const nacl = require('../lib/nacl-fast.js');
const DualSalt = require('../src/dual-salt.js');
//const DualSaltTest = require('./dual-salt-test.js');

const dualsalt = DualSalt();
//const dualsalttest = DualSaltTest();

module.exports = () => {
  'use-strict';

 /* private */ function testEddsaTestVector() {
    console.info('\nTest EdDSA test vector');
    
    let counter = 0;
    util.parseTestVectorFile('sign.input', function (record) {
        const dutSecretKey = util.hex2Uint8Array(record[0]);
        const dutPublicKey = util.hex2Uint8Array(record[1]);
        const dutMessage = util.hex2Uint8Array(record[2]);
        const dutSignature = util.hex2Uint8Array(record[3]);

        let secretKeySeed = dutSecretKey.subarray(0, dualsalt.seedLength);
        let secretKey = new Uint8Array(dualsalt.secretKeyLength);
        let publicKey = new Uint8Array(dualsalt.publicKeyLength);

        dualsalt.createKeyPair(publicKey, secretKey, secretKeySeed);
        if (!util.uint8ArrayEquals(dutPublicKey, publicKey)) {
            throw new Error("Public key do not match");
        }

        const signature = dualsalt.signCreate(dutMessage, publicKey, secretKey);
        if (!dualsalt.signVerify(signature, publicKey)) {
            throw new Error("Signature do not verify correctly");
        }
        if (!util.uint8ArrayEquals(dutSignature, signature)) {
            throw new Error("Signature do not match");
        }

        if (++counter % 100 === 0)
          console.info("... vectors processed: ", counter);
      }
    );

    console.info('\nTest succeeded');
  }  

    /*private*/ function testSignDualTestVector() {
        console.info('\nTest sign dual test vector');
    
        let counter = 0;
        util.parseTestVectorFile('signDual.input', function (record) {
            const dutKeySeedA = util.hex2Uint8Array(record[0]);
            const dutPublicPartA = util.hex2Uint8Array(record[1]);
            const dutKeySeedB = util.hex2Uint8Array(record[2]);
            const dutPublicPartB = util.hex2Uint8Array(record[3]);
            const dutVirtualPublicKey = util.hex2Uint8Array(record[4]);
            const dutMessage = util.hex2Uint8Array(record[5]);
            const dutSignature = util.hex2Uint8Array(record[6]);

            let secretKeyA = new Uint8Array(dualsalt.secretKeyLength);
            let publicKeyA = new Uint8Array(dualsalt.publicKeyLength);
            let secretKeyB = new Uint8Array(dualsalt.secretKeyLength);
            let publicKeyB = new Uint8Array(dualsalt.publicKeyLength);                            

            dualsalt.createKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
            if (!util.uint8ArrayEquals(dutPublicPartA, publicKeyA)) {
                throw new Error("Public key A do not match");
            }

            dualsalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
            if (!util.uint8ArrayEquals(dutPublicPartB, publicKeyB)) {
                throw new Error("Public key B do not match");
            }

            const virtualPublicKey = dualsalt.addPublicKeys(publicKeyA, publicKeyB);
            if (!util.uint8ArrayEquals(dutVirtualPublicKey, virtualPublicKey)) {
                throw new Error("Virtual public key do not match");
            }

            const m1 = dualsalt.signCreateDual1(dutMessage, virtualPublicKey, secretKeyA);
            const m2 = dualsalt.signCreateDual2(m1, secretKeyB);
            const signature = dualsalt.signCreateDual3(m1, m2, publicKeyA, secretKeyA);

            if (!dualsalt.signVerify(signature, virtualPublicKey)) {
                throw new Error("Signature do not verify correctly");
            }
            
            if (!util.uint8ArrayEquals(signature, dutSignature)) {
                throw new Error("Signature do not match test signature");
            }
    
            if (++counter % 100 === 0)
              console.info("... vectors processed: ", counter);
          }
        );
    
        console.info('\nTest succeeded');
    }


    /*private*/ function testDecryptTestVector() {
        console.info('\nTest decrypt test vector');
    
        let counter = 0;
        util.parseTestVectorFile('decrypt.input', function (record) {
            const dutKeySeed = util.hex2Uint8Array(record[0]);
            const dutPublicKey = util.hex2Uint8Array(record[1]);
            const dutTempKeySeed = util.hex2Uint8Array(record[2]);
            const dutMessage = util.hex2Uint8Array(record[3]);
            const dutChipperText = util.hex2Uint8Array(record[4]);

            let secretKey = new Uint8Array(dualsalt.secretKeyLength);
            let publicKey = new Uint8Array(dualsalt.publicKeyLength);

            dualsalt.createKeyPair(publicKey, secretKey, dutKeySeed);
            if (!util.uint8ArrayEquals(dutPublicKey, publicKey)) {
                throw new Error("Public key do not match");
            }

            const chipperText = dualsalt.encrypt(dutMessage, publicKey, dutTempKeySeed);
            const message = dualsalt.decrypt(chipperText, secretKey);            

            if (!util.uint8ArrayEquals(chipperText, dutChipperText)) {
                throw new Error("Did not encrypt correctly");
            }

            if (!util.uint8ArrayEquals(message, dutMessage)) {
                throw new Error("Did not decrypt correctly");
            }          

            if (++counter % 100 === 0)
              console.info("... vectors processed: ", counter);
          }
        );
    
        console.info('\nTest succeeded');
    }

    /*private*/ function testDecryptDualTestVector() {
        console.info('\nTest decrypt dual test vector');
    
        let counter = 0;
        util.parseTestVectorFile('decryptDual.input', function (record) {
            const dutKeySeedA = util.hex2Uint8Array(record[0]);
            const dutPublicPartA = util.hex2Uint8Array(record[1]);
            const dutKeySeedB = util.hex2Uint8Array(record[2]);
            const dutPublicPartB = util.hex2Uint8Array(record[3]);
            const dutVirtualPublicKey = util.hex2Uint8Array(record[4]);
            const dutTempKeySeed = util.hex2Uint8Array(record[5]);
            const dutMessage = util.hex2Uint8Array(record[6]);
            const dutChipperText = util.hex2Uint8Array(record[7]);

            let secretKeyA = new Uint8Array(dualsalt.secretKeyLength);
            let publicKeyA = new Uint8Array(dualsalt.publicKeyLength);
            let secretKeyB = new Uint8Array(dualsalt.secretKeyLength);
            let publicKeyB = new Uint8Array(dualsalt.publicKeyLength); 

            dualsalt.createKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
            if (!util.uint8ArrayEquals(dutPublicPartA, publicKeyA)) {
                throw new Error("Public key A do not match");
            }

            dualsalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
            if (!util.uint8ArrayEquals(dutPublicPartB, publicKeyB)) {
                throw new Error("Public key B do not match");
            }

            const virtualPublicKey = dualsalt.addPublicKeys(publicKeyA, publicKeyB);
            if (!util.uint8ArrayEquals(dutVirtualPublicKey, virtualPublicKey)) {
                throw new Error("Virtual public key do not match");
            }

            const chipperText = dualsalt.encrypt(dutMessage, virtualPublicKey, dutTempKeySeed);
            const d1 = dualsalt.decryptDual1(chipperText, secretKeyA);
            const message = dualsalt.decryptDual2(d1, chipperText, secretKeyB);          

            if (!util.uint8ArrayEquals(chipperText, dutChipperText)) {
                throw new Error("Did not encrypt correctly");
            }

            if (!util.uint8ArrayEquals(message, dutMessage)) {
                throw new Error("Did not decrypt correctly");
            }        

            if (++counter % 100 === 0)
              console.info("... vectors processed: ", counter);
          }
        );
    
        console.info('\nTest succeeded');
    }    


    /*private*/ function testKeyRotateTestVector() {
        console.info('\nTest key rotate test vector');
    
        let counter = 0;
        util.parseTestVectorFile('keyRotate.input', function (record) {
            const dutKeySeedA = util.hex2Uint8Array(record[0]);
            const dutPublicPartA = util.hex2Uint8Array(record[1]);
            const dutKeySeedB = util.hex2Uint8Array(record[2]);
            const dutPublicPartB = util.hex2Uint8Array(record[3]);
            const dutVirtualPublicKey = util.hex2Uint8Array(record[4]);
            const dutRotateRandom = util.hex2Uint8Array(record[5]);
            const dutNewSecretKeyA = util.hex2Uint8Array(record[6]);
            const dutNewSecretKeyB = util.hex2Uint8Array(record[7]);

            let secretKeyA = new Uint8Array(dualsalt.secretKeyLength);
            let publicKeyA = new Uint8Array(dualsalt.publicKeyLength);
            let secretKeyB = new Uint8Array(dualsalt.secretKeyLength);
            let publicKeyB = new Uint8Array(dualsalt.publicKeyLength); 

            dualsalt.createKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
            if (!util.uint8ArrayEquals(dutPublicPartA, publicKeyA)) {
                throw new Error("Public key A do not match");
            }

            dualsalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
            if (!util.uint8ArrayEquals(dutPublicPartB, publicKeyB)) {
                throw new Error("Public key B do not match");
            }

            const virtualPublicKey = dualsalt.addPublicKeys(publicKeyA, publicKeyB);
            if (!util.uint8ArrayEquals(dutVirtualPublicKey, virtualPublicKey)) {
                throw new Error("Virtual public key do not match");
            }

            const newPublicPartA = new Uint8Array(dualsalt.publicKeyLength);
            const newPublicPartB = new Uint8Array(dualsalt.publicKeyLength);

            dualsalt.rotateKey(newPublicPartA, secretKeyA, dutRotateRandom, true);
            dualsalt.rotateKey(newPublicPartB, secretKeyB, dutRotateRandom, false);

            const newVirtualPublicKey = dualsalt.addPublicKeys(newPublicPartA, newPublicPartB);

            if (!util.uint8ArrayEquals(dutVirtualPublicKey, newVirtualPublicKey)) {
                throw new Error("Virtual public key do not match");
            }

            if (!util.uint8ArrayEquals(secretKeyA, dutNewSecretKeyA)) {
                throw new Error("Secret Key A was not updated correctly");
            }

            if (!util.uint8ArrayEquals(secretKeyB, dutNewSecretKeyB)) {
                throw new Error("Secret Key B was not updated correctly");
            }            

            if (++counter % 100 === 0)
              console.info("... vectors processed: ", counter);
          }
        );
    
        console.info('\nTest succeeded');
    } 

    function run() {
        try {
            testEddsaTestVector();
            testSignDualTestVector();
            testDecryptTestVector();
            testDecryptDualTestVector();
            testKeyRotateTestVector();
        }
        catch (e) {
            console.error(e.message, e);
            return;
        }
        
        console.info("\nSUCCESS! All tests were successful.");
    }        

    
    /* public members */
    return {
        run,
    };    
};
