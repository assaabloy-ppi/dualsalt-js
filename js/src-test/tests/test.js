var chai = require('chai');
var assert = chai.assert;
var expect = chai.expect;
var should = chai.should;


describe('Working test', () => {
  describe('2==2', () => {
    it('should be ok', () => {
      assert.equal(2, 2);
    });
  });
});

describe('Failing test', () => {
  describe('3==2', () => {
    it('should be failing', () => {
      assert.equal(3, 2);
    });
  });
});

