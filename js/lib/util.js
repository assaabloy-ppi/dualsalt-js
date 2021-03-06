// Takes a hex-string and returns a Uint8Array
exports.hex2Uint8Array = (str) => {
  str = str.trim().toLowerCase();
  if (str.substring(0, 2) === '0x') {
    str = str.substring(2, str.length);
  }
  if (str.length % 2 !== 0) {
    throw new Error(`${'String length has to be even. \n\t' +
            'Length: '}${str.length}`);
  }
  let byte;
  const arr = [];
  for (let i = 0; i < str.length; i += 2) {
    byte = str.substring(i, i + 2);
    if (!((/[0-9a-fA-F]{2}/).test(byte))) {
      throw new Error(`${'Bad string format, must be hexadecimal.\n\t' +
                'String: '}${str}\n\t` +
                `Byte: ${byte}\n\t` +
                `Pos: ${i}`);
    }
    arr.push(parseInt(byte, 16));
  }
  return new Uint8Array(arr);
};

// Takes a hex-string and returns an ArrayBuffer
exports.hex2ab = (hex) => {
  if (typeof hex !== 'string') {
    throw new Error(`Input must be string, was ${typeof hex}`);
  }
  hex = hex.trim();
  if (hex.length % 2 !== 0) {
    throw new Error('String length must be even');
  }
  if (hex.substring(0, 2) === '0x') {
    hex = hex.substring(2, hex.length);
  }

  const arr = [];
  for (let i = 0; i < hex.length; i += 2) {
    arr.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return new Uint8Array(arr).buffer;
};

// Takes an ArrayBuffer and returns a hex-string
exports.ab2hex = buffer => Array.prototype.map.call(
  new Uint8Array(buffer),
    		x => (`00${x.toString(16)}`).slice(-2)).join('');

// Compares two Uint8Arrays for byte equality
exports.uint8ArrayEquals = (uints1, uints2) => {
  if (!(uints1 instanceof Uint8Array) ||
		!(uints2 instanceof Uint8Array)) {
    throw new Error('Expected Uint8Arrays');
  }
  if (uints1.length !== uints2.length) {
    return false;
  }
  for (let i = 0; i < uints1.length; i++) {
    if (uints1[i] !== uints2[i]) {
      return false;
    }
  }
  return true;
};

// Compares two ArrayBuffers for byte equality
exports.bufferEquals = (buffer1, buffer2) => {
  if (!(buffer1 instanceof ArrayBuffer) ||
		!(buffer2 instanceof ArrayBuffer)) {
    throw new Error('Expected ArrayBuffers');
  }
  const bytes1 = new Uint8Array(buffer1);
  const bytes2 = new Uint8Array(buffer2);
  if (bytes1.length !== bytes2.length) {
    return false;
  }
  for (let i = 0; i < bytes1.length; i++) {
    if (bytes1[i] !== bytes2[i]) {
      return false;
    }
  }
  return true;
};

// Returns the number of ms since Unix epoch
// Like Java's System.currentTimeMillis
exports.currentTimeMs = () => {
  if (!Date.now) {
    return new Date.getTime();
  }
  return Date.now();
};

// Returns true iff arg is a string
exports.isString = arg => typeof arg === 'string' || arg instanceof String;

// Returns true iff arg is an array
exports.isArray = (arg) => {
  if (!Array.isArray) {
	    return Object.prototype.toString.call(arg) === '[object Array]';
  	}
  		return Array.isArray(arg);
};


exports.arraycopy = (src, srcPos, dest, destPos, length) => {
  dest.set(src.subarray(srcPos, srcPos + length), destPos);
};

exports.parseTestVectorFile = (fileName, recordCb) => {

  const fs = require('fs');
  //const filename = 'sign.input';
  
  let fd = fs.openSync(fileName, 'r');
  let bufferSize = 1024;
  let buffer = new Buffer(bufferSize);
  
  let leftOver = '';
  let read, line, idxStart, idx;
  while ((read = fs.readSync(fd, buffer, 0, bufferSize, null)) !== 0) {
    leftOver += buffer.toString('ascii', 0, read);
    idxStart = 0
    while ((idx = leftOver.indexOf('\n', idxStart)) !== -1) {
      line = leftOver.substring(idxStart, idx);
      recordCb(line.split(':'));

      idxStart = idx + 1;
    }
    leftOver = leftOver.substring(idxStart);
  }
};

// exports.stringToUint8Array = (str) => {
//
// }
