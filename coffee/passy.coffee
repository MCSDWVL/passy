###

passy.coffee

Implementation of passy algorithm in CoffeeScript, by Stephen Waits.

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

###

passy = (text, secret) ->


  #
  # SHA1 code
  #

  # convert a single character code to its byte representation
  char_code_to_bytes = (char_code) ->
    result = []
    while char_code
      result.unshift(char_code & 0xff)
      char_code >>= 8
    result
  
  # convert a string into a byte array, including multibytes chars
  str_to_bytes = (str) ->
    result = []
    for char_code in str
      result = result.concat(char_code_to_bytes(char_code.charCodeAt(0)))
    result
  
  # convert a number to an array of 8 bytes representing a 64 bit big-endian integer
  num_to_big_endian_64 = (num) ->
    [
      (num & 0xff00000000000000) >>> 56,
      (num & 0x00ff000000000000) >>> 48,
      (num & 0x0000ff0000000000) >>> 40,
      (num & 0x000000ff00000000) >>> 32,
      (num & 0x00000000ff000000) >>> 24,
      (num & 0x0000000000ff0000) >>> 16,
      (num & 0x000000000000ff00) >>>  8,
      (num & 0x00000000000000ff)       
    ]
  
  # convert an array of bytes to an array of int32 (big-endian)
  bytes_to_big_endian_32 = (array) ->
    ((array[i] << 24) | (array[i+1] << 16) | (array[i+2] <<  8) | array[i+3]) for i in [0...array.length] by 4
  
  # take an array of bytes and return the hex string
  bytes_to_hex = (bytes) ->
    hextab = "0123456789abcdef"
    (hextab[(x >>> 4) & 0x0f] + hextab[x & 0x0f] for x in bytes).join("")
 
  # compute SHA1 hash
  #
  # input is an array of bytes (big-endian order)
  # returns an array of 20 bytes
  sha1 = (byte_array) ->

    # helper function (rotate left)
    rol = (x,i) -> (x << i) | (x >>> (32-i))

    # initialize variables
    message              = byte_array.slice(0) # copy array, since we will modify it
    message_size_in_bits = message.length * 8  # store message size for later use
  
    # initialize hash state variables
    [h0, h1, h2, h3, h4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
  
    # Preprocess message in preparation for hasing:

    # append the bit '1' to the message
    message.push(0x80) 

    # append (0 <= k < 512) bits '0', so that the resulting message length (in bits) is congruent to 448 = -64 (mod 512)
    message.push(0) while ((message.length + 8) % 64)  

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message = message.concat(num_to_big_endian_64(message_size_in_bits))
  
    # Process the message in successive 512-bit chunks:

    # break message into 512-bit chunks
    for i_chunk in [0...message.length] by 64
      # convert bytes into int32
      w = bytes_to_big_endian_32(message.slice(i_chunk, i_chunk+64))
  
      # init state with current hash
      [a, b, c, d, e] = [h0, h1, h2, h3, h4]
  
      # hash rounds
      for i in [0...80]
        s = i & 0xf
        if (i >= 16)
          temp = w[(s + 13) & 0xf] ^ w[(s + 8) & 0xf] ^ w[(s + 2) & 0xf] ^ w[s]
          w[s] = (temp << 1) | (temp >>> 31)
        if (i < 20)
          #       rol(a,5) + _________f[i]________ + e + ___k[i]___ + w[s]
          temp = (rol(a,5) + ( d ^ (b & (c ^ d)) ) + e + 0x5a827999 + w[s]) & 0xffffffff
        else if (i < 40)
          #       rol(a,5) + _____f[i]____ + e + ___k[i]___ + w[s]
          temp = (rol(a,5) + ( b ^ c ^ d ) + e + 0x6ed9eba1 + w[s]) & 0xffffffff
        else if (i < 60)
          #       rol(a,5) + ___________f[i]________________ + e + ___k[i]___ + w[s]
          temp = (rol(a,5) + ( (b & c) | (b & d) | (c & d) ) + e + 0x8f1bbcdc + w[s]) & 0xffffffff
        else
          #       rol(a,5) + _____f[i]____ + e + ___k[i]___ + w[s]
          temp = (rol(a,5) + ( b ^ c ^ d ) + e + 0xca62c1d6 + w[s]) & 0xffffffff
        [a, b, c, d, e] = [temp, a, rol(b,30), c, d]
  
      # Add this chunk's hash to result so far:
      h0 = (h0 + a) & 0xffffffff
      h1 = (h1 + b) & 0xffffffff
      h2 = (h2 + c) & 0xffffffff
      h3 = (h3 + d) & 0xffffffff
      h4 = (h4 + e) & 0xffffffff
  
    # Return the final hash value (big-endian):
    [
      (h0 >>> 24) & 0xff,  (h0 >>> 16) & 0xff,  (h0 >>> 8) & 0xff,  h0 & 0xff, 
      (h1 >>> 24) & 0xff,  (h1 >>> 16) & 0xff,  (h1 >>> 8) & 0xff,  h1 & 0xff, 
      (h2 >>> 24) & 0xff,  (h2 >>> 16) & 0xff,  (h2 >>> 8) & 0xff,  h2 & 0xff, 
      (h3 >>> 24) & 0xff,  (h3 >>> 16) & 0xff,  (h3 >>> 8) & 0xff,  h3 & 0xff, 
      (h4 >>> 24) & 0xff,  (h4 >>> 16) & 0xff,  (h4 >>> 8) & 0xff,  h4 & 0xff
    ] # note: returning this as a byte array is quite expensive!
  
  # compute SHA1
  #
  # input is a string
  # returns a hex string
  sha1_string = (str) ->
    # convert hex string to a byte array, hash, and convert back to a hex string
    bytes_to_hex(sha1(str_to_bytes(str)))
  

  #
  # HMAC-SHA1 code
  #

  # compute HMAC-SHA1
  #
  # key_str and message_str are both strings
  # returns a hex string
  hmac_sha1 = (key_str, message_str) ->
    # convert key & message to byte arrays
    key     = str_to_bytes(key_str)
    message = str_to_bytes(message_str)
  
    # initialize key
    key = sha1(key) if key.length > 64 # keys longer than 64 are truncated to sha1 result
    key.push(0) while key.length < 64  # keys shorter than 64 are padded with zeroes
    
    # setup pads
    opad = (0x5c ^ key[i] for i in [0...64])
    ipad = (0x36 ^ key[i] for i in [0...64])
  
    # calculate HMAC
    bytes_to_hex(sha1(opad.concat(sha1(ipad.concat(message)))))
  
  # create a byte string of length "size" of "b"s
  byte_string = (b, size) ->
    (String.fromCharCode(b) for i in [0...size]).join("")

	# test HMAC-SHA1 with known test vectors, which naturally tests SHA1
  verify_hmac_sha1 = ->
    # SHA1 test data from RFC
    test_vectors = [
      [ "Jefe",                "what do ya want for nothing?",                                              "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" ],
      [ byte_string(0x0b, 20), "Hi There",                                                                  "b617318655057264e28bc0b6fb378c8ef146be00" ],
      [ byte_string(0xaa, 20), byte_string(0xdd, 50),                                                       "125d7342b9ac11cd91a39af48aa17b4f63f175d3" ],
      [ byte_string(0x0c, 20), "Test With Truncation",                                                      "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04" ],
      [ byte_string(0xaa, 80), "Test Using Larger Than Block-Size Key - Hash Key First",                    "aa4ae5e15272d00e95705637ce8a3b55ed402112" ],
      [ byte_string(0xaa, 80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" ]
    ]
  
    # run tests
    for t in test_vectors
      # return false if a test fails
      return false if hmac_sha1(t[0], t[1]) != t[2]
  
    # all tests passed
    true


  #
  # passy code
  #

  # returns true if string contains one of each [A-H], [a-h], [2-9], and [#$%*+=@?]
  good_passy = (str) ->
    str.match(/[A-H]/) &&
    str.match(/[a-h]/) &&
    str.match(/[2-9]/) &&
    str.match(/[#$%*+=@?]/)

  # given a long string, find the minimum length "good" passy (i.e. has one of each
  # character type, and meets minimum length of 16 characters)
  good_passy_length = (str) ->
    for i in [16..str.length]
      return i if good_passy(str.substr(0,i))
    return str.length # uh-oh, that's a long passy!

  # encode a hex string (typically a single octet) to a passy string
  encode_passy = (secret, text) ->

    # our symbol table for passy
    symtab = "ABCDEFGHabcdefgh23456789#$%*+=@?"

    # convert a hex string to a single passy character
    # * modulo and lookup in symtab string
    hex2passy = (x) -> symtab[parseInt(x,16) % symtab.length]

    # encode a hex string into a passy string
    # 1. split a string into two character strings (octets)
    # 2. encode each two char string (octet) into a single passy char
    # 3. join resulting array of passy chars into a single passy string
    encode = (str) ->
      (hex2passy(str.substr(i,2)) for i in [0...str.length] by 2).join("")

    # this is the hmac_sha1 concatenated with the sha1(hmac_sha1)
    double_hmac = hmac_sha1(secret,text)
    double_hmac = double_hmac + sha1_string(double_hmac)

    # convert the hex hmac-sha1 string to a passy string
    encoded = encode(double_hmac)

    # determine the length of the passy
    len = good_passy_length(encoded)

    # finally, return the passy string
    encoded.substr(0,len)

  # encode a hex string into the old version of a passy string
  encode_passy_legacy = (secret, text) ->
    hmac_sha1(secret,text).substr(0,10)

  # begin main passy function

  # return an error if passy fails on this javascript
  return ["Error!","Error!"] unless  (
    encode_passy(                "0123",                    "a") == "Gad6DdC2e3cD6dF937c82h5%" &&
    encode_passy(    "ABab12!@CDcd34#$", "aB234SLKDJF(*#@jfsdk") == "d+B8#@hh5CB%=Fef" &&
    encode_passy("11111111111111111111", "00000000000000000000") == "Fgh5bE?94A2chdhF"
  )

  # return both new and old passy results (for now)
  [encode_passy(secret,text),encode_passy_legacy(secret,text)]


# add to the DOM (for Google closure compiler)
window['passy'] = passy

