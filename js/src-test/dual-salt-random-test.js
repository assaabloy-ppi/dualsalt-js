const nacl = require('../lib/nacl-fast.js');
const DualSalt = require('../src/dual-salt.js');
const DualSaltTest = require('./dual-salt-test.js');

const dualsalt = DualSalt();
const dualsalttest = DualSaltTest();

module.exports = () => {
  'use-strict';

    /*private*/ function testRotateKeysRandom() {
        console.info("\nTest rotate keys random");
        for (let index = 0; index < 1000; index++) {
            const rand1 = nacl.randomBytes(dualsalt.seedLength);
            const rand2 = nacl.randomBytes(dualsalt.seedLength);
            const rand3 = nacl.randomBytes(dualsalt.seedLength);
            dualsalttest.testRotateKeys(rand1, rand2, rand3);
        }
    }

    /*private*/ function testDualSignRandom() {
        console.info("\nTest dual sign random");
        for (let index = 0; index < 1000; index++) {
            const rand1 = nacl.randomBytes(dualsalt.seedLength);
            const rand2 = nacl.randomBytes(dualsalt.seedLength);
            dualsalttest.testDualSign(rand1, rand2, "Sen vart det bara en tummetott");
        }    
    }

    /*private*/ function testSingleDecryptRandom() {
        console.info("\nTest dual sign random");
        for (let index = 0; index < 1000; index++) {
            const rand1 = nacl.randomBytes(dualsalt.seedLength);
            const rand2 = nacl.randomBytes(dualsalt.nonceLength);
            const rand3 = nacl.randomBytes(dualsalt.seedLength);
            dualsalttest.testSingleDecrypt(rand1, rand2, rand3, "Sen vart det bara en tummetott");
        }
    }

    /*private*/ function testDualDecryptRandom() {
        console.info("\nTest dual decrypt random");
        for (let index = 0; index < 1000; index++) {
            const rand1 = nacl.randomBytes(dualsalt.seedLength);
            const rand2 = nacl.randomBytes(dualsalt.seedLength);
            const rand3 = nacl.randomBytes(dualsalt.nonceLength);
            const rand4 = nacl.randomBytes(dualsalt.seedLength);
            dualsalttest.testDualDecrypt(rand1, rand2, rand3, rand4, "Sen vart det bara en tummetott");
        }        
    }

    function run() {
        try {
            testRotateKeysRandom();
            testDualSignRandom();
            testSingleDecryptRandom();
            testDualDecryptRandom();
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
