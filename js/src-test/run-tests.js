const DualSaltTest = require('./dual-salt-test.js');
const DualSaltRandomTest = require('./dual-salt-random-test.js')

const dualSaltTest = DualSaltTest();
const dualSaltRandomTest = DualSaltRandomTest();

dualSaltTest.run();
dualSaltRandomTest.run();
