#################################################################################
#
# phpass.py version 0.1
#   Python module port of phpass-0.1 library, originally written by Solar Designer.
#
# Copyright (c) 2008, Alexander Chemeris <Alexander.Chemeris@nospam@gmail.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The name of the author may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#################################################################################

import hashlib

def encode64(input_val, count, itoa64):
    ''' Encode binary data from input_val to ASCII string.

    Every six bits of input_val are represented by corresponding
    char from 64-char length itoa64 array. That is 0 will be
    represented in resulting string with char itoa64[0], 1 will
    be represented with itoa64[1], ..., 63 will be represented
    with itoa64[63].
    '''
    output = ''
    i = 0

    while i<count:
        value = ord(input_val[i])
        i = i+1
        output = output + itoa64[value&0x3f]

        if i < count:
            value = value | (ord(input_val[i]) << 8)

        output = output + itoa64[(value>>6)&0x3f]

        i = i+1
        if i >= count:
            break

        if i < count:
            value = value | (ord(input_val[i]) << 16)

        output = output + itoa64[(value>>12)&0x3f]

        i = i+1
        if i >= count:
            break

        output = output + itoa64[(value>>18)&0x3f]

    return output

def crypt_private(passwd, passwd_hash, hash_prefix='$P$'):
    ''' Hash password, using same salt and number of
        iterations as in passwd_hash.

    This is useful when you want to check password match.
    In this case you pass your raw password and password
    hash to this function and then compare its return
    value with password hash again:

       is_valid = (crypt_private(passwd, hash) == hash)

    hash_prefix is used to check that passwd_hash is of
    supported type. It is compared with first 3 chars of
    passwd_hash and if does not match error is returned.

    NOTE: all arguments must be ASCII strings, not unicode!
    If you want to support unicode passwords, you could
    use any encoding you want. For compatibility with PHP
    it is recommended to use UTF-8:

       passwd_ascii = passwd.encode('utf-8')
	   is_valid = (crypt_private(passwd_ascii, hash) == hash)

	Here hash is already assumed to be an ASCII string.

	In case of error '*0' is usually returned. But if passwd_hash
	begins with '*0', then '*1' is returned to prevent false
	positive results of password check.
    '''
    itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    output = '*0'
    # Prevent output from being the same as passwd_hash, because
    # this may lead to false positive password check results.
    if passwd_hash[0:2] == output:
        output = '*1'

    # Check for correct hash type
    if passwd_hash[0:3] != hash_prefix:
        return output

    count_log2 = itoa64.index(passwd_hash[3])
    if count_log2<7 or count_log2>30:
        return output
    count = 1<<count_log2

    salt = passwd_hash[4:12]
    if len(salt) != 8:
        return output

    m = hashlib.md5()
    m.update(salt)
    m.update(passwd)
    tmp_hash = m.digest()
    for i in xrange(count):
        m = hashlib.md5()
        m.update(tmp_hash)
        m.update(passwd)
        tmp_hash = m.digest()

    output = passwd_hash[0:12]+encode64(tmp_hash, 16, itoa64)
    return output
