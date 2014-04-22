/*

sha1.coffee

Implementation of SHA-1 hash and HMAC algorithms in CoffeeScript, by Stephen
Waits.

The MIT License

Copyright (c) 2011 Stephen Waits <steve@waits.net>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/var SHA1;
SHA1 = (function() {
  var byte_string, bytes_to_big_endian_32, bytes_to_hex, char_code_to_bytes, hmac_sha1, num_to_big_endian_64, sha1, sha1_string, str_to_bytes, verify_hmac_sha1;
  function SHA1() {}
  char_code_to_bytes = function(char) {
    var result;
    result = [];
    while (char) {
      result.unshift(char & 0xff);
      char >>= 8;
    }
    return result;
  };
  str_to_bytes = function(str) {
    var char, result, _i, _len;
    result = [];
    for (_i = 0, _len = str.length; _i < _len; _i++) {
      char = str[_i];
      result = result.concat(char_code_to_bytes(char.charCodeAt(0)));
    }
    return result;
  };
  num_to_big_endian_64 = function(num) {
    return [(num & 0xff00000000000000) >>> 56, (num & 0x00ff000000000000) >>> 48, (num & 0x0000ff0000000000) >>> 40, (num & 0x000000ff00000000) >>> 32, (num & 0x00000000ff000000) >>> 24, (num & 0x0000000000ff0000) >>> 16, (num & 0x000000000000ff00) >>> 8, num & 0x00000000000000ff];
  };
  bytes_to_big_endian_32 = function(array) {
    var i, _ref, _results;
    _results = [];
    for (i = 0, _ref = array.length; (0 <= _ref ? i < _ref : i > _ref); i += 4) {
      _results.push((array[i] << 24) | (array[i + 1] << 16) | (array[i + 2] << 8) | array[i + 3]);
    }
    return _results;
  };
  bytes_to_hex = function(bytes) {
    var hextab, x;
    hextab = "0123456789abcdef";
    return ((function() {
      var _i, _len, _results;
      _results = [];
      for (_i = 0, _len = bytes.length; _i < _len; _i++) {
        x = bytes[_i];
        _results.push(hextab[(x >>> 4) & 0x0f] + hextab[x & 0x0f]);
      }
      return _results;
    })()).join("");
  };
  sha1 = function(byte_array) {
    var a, b, c, d, e, h0, h1, h2, h3, h4, i, i_chunk, message, message_size_in_bits, rol, s, temp, w, _ref, _ref2, _ref3, _ref4;
    rol = function(x, i) {
      return (x << i) | (x >>> (32 - i));
    };
    message = byte_array.slice(0);
    message_size_in_bits = message.length * 8;
    _ref = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], h0 = _ref[0], h1 = _ref[1], h2 = _ref[2], h3 = _ref[3], h4 = _ref[4];
    message.push(0x80);
    while ((message.length + 8) % 64) {
      message.push(0);
    }
    message = message.concat(num_to_big_endian_64(message_size_in_bits));
    for (i_chunk = 0, _ref2 = message.length; (0 <= _ref2 ? i_chunk < _ref2 : i_chunk > _ref2); i_chunk += 64) {
      w = bytes_to_big_endian_32(message.slice(i_chunk, i_chunk + 64));
      _ref3 = [h0, h1, h2, h3, h4], a = _ref3[0], b = _ref3[1], c = _ref3[2], d = _ref3[3], e = _ref3[4];
      for (i = 0; i < 80; i++) {
        s = i & 0xf;
        if (i >= 16) {
          temp = w[(s + 13) & 0xf] ^ w[(s + 8) & 0xf] ^ w[(s + 2) & 0xf] ^ w[s];
          w[s] = (temp << 1) | (temp >>> 31);
        }
        if (i < 20) {
          temp = (rol(a, 5) + (d ^ (b & (c ^ d))) + e + 0x5a827999 + w[s]) & 0xffffffff;
        } else if (i < 40) {
          temp = (rol(a, 5) + (b ^ c ^ d) + e + 0x6ed9eba1 + w[s]) & 0xffffffff;
        } else if (i < 60) {
          temp = (rol(a, 5) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdc + w[s]) & 0xffffffff;
        } else {
          temp = (rol(a, 5) + (b ^ c ^ d) + e + 0xca62c1d6 + w[s]) & 0xffffffff;
        }
        _ref4 = [temp, a, rol(b, 30), c, d], a = _ref4[0], b = _ref4[1], c = _ref4[2], d = _ref4[3], e = _ref4[4];
      }
      h0 = (h0 + a) & 0xffffffff;
      h1 = (h1 + b) & 0xffffffff;
      h2 = (h2 + c) & 0xffffffff;
      h3 = (h3 + d) & 0xffffffff;
      h4 = (h4 + e) & 0xffffffff;
    }
    return [(h0 >>> 24) & 0xff, (h0 >>> 16) & 0xff, (h0 >>> 8) & 0xff, h0 & 0xff, (h1 >>> 24) & 0xff, (h1 >>> 16) & 0xff, (h1 >>> 8) & 0xff, h1 & 0xff, (h2 >>> 24) & 0xff, (h2 >>> 16) & 0xff, (h2 >>> 8) & 0xff, h2 & 0xff, (h3 >>> 24) & 0xff, (h3 >>> 16) & 0xff, (h3 >>> 8) & 0xff, h3 & 0xff, (h4 >>> 24) & 0xff, (h4 >>> 16) & 0xff, (h4 >>> 8) & 0xff, h4 & 0xff];
  };
  verify_hmac_sha1 = function() {
    var t, test_vectors, _i, _len;
    test_vectors = [["Jefe", "what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"], [byte_string(0x0b, 20), "Hi There", "b617318655057264e28bc0b6fb378c8ef146be00"], [byte_string(0xaa, 20), byte_string(0xdd, 50), "125d7342b9ac11cd91a39af48aa17b4f63f175d3"], [byte_string(0x0c, 20), "Test With Truncation", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"], [byte_string(0xaa, 80), "Test Using Larger Than Block-Size Key - Hash Key First", "aa4ae5e15272d00e95705637ce8a3b55ed402112"], [byte_string(0xaa, 80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"]];
    for (_i = 0, _len = test_vectors.length; _i < _len; _i++) {
      t = test_vectors[_i];
      if (hmac_sha1(t[0], t[1]) !== t[2]) {
        return false;
      }
    }
    return true;
  };
  sha1_string = function(str) {
    return bytes_to_hex(sha1(str_to_bytes(str)));
  };
  byte_string = function(byte, size) {
    var i;
    return ((function() {
      var _results;
      _results = [];
      for (i = 0; (0 <= size ? i < size : i > size); (0 <= size ? i += 1 : i -= 1)) {
        _results.push(String.fromCharCode(byte));
      }
      return _results;
    })()).join("");
  };
  hmac_sha1 = function(key_str, message_str) {
    var i, ipad, key, message, opad;
    key = str_to_bytes(key_str);
    message = str_to_bytes(message_str);
    if (key.length > 64) {
      key = sha1(key);
    }
    while (key.length < 64) {
      key.push(0);
    }
    opad = (function() {
      var _results;
      _results = [];
      for (i = 0; i < 64; i++) {
        _results.push(0x5c ^ key[i]);
      }
      return _results;
    })();
    ipad = (function() {
      var _results;
      _results = [];
      for (i = 0; i < 64; i++) {
        _results.push(0x36 ^ key[i]);
      }
      return _results;
    })();
    return bytes_to_hex(sha1(opad.concat(sha1(ipad.concat(message)))));
  };
  SHA1.hash = sha1_string;
  SHA1.hmac = hmac_sha1;
  SHA1.test = verify_hmac_sha1;
  return SHA1;
})();
