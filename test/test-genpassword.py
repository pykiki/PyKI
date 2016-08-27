#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

'''
    PyKI - PKI openssl for managing TLS certificates
    Copyright (C) 2016 MAIBACH ALAIN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Contact: alain.maibach@gmail.com / 1133 route de Saint Jean 06600 Antibes - FRANCE.
'''

import random, string

def codegenerator(pwlen = 25, alphabet = False):
    if not alphabet:
        #alphabet = string.printable
        alphabet = string.digits + string.ascii_letters + string.punctuation

    pw_length = pwlen
    mypw = ""

    for i in range(pw_length):
        next_index = random.randrange(len(alphabet))
        mypw = mypw + alphabet[next_index]
    return mypw

if __name__ == '__main__':
    print( codegenerator(pwlen = 26) )
    print( codegenerator(pwlen = 42) )
    print( codegenerator(pwlen = 3) )
    print( codegenerator(alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") )
    print( codegenerator(alphabet= 'azerty', pwlen=2) )
