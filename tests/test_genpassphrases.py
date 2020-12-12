#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from xkcdpass import xkcd_password as xp

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

    Contact: alain.maibach@gmail.com / 34 rue appienne 13480 - FRANCE.
'''

if __name__ == '__main__':
    # create a wordlist from the default wordfile
    # use words between 7 and 12 letters long
    wordfile = xp.locate_wordfile()
    mywords = xp.generate_wordlist(
        wordfile=wordfile, min_length=7, max_length=12)

    # create a password with acrostic "face"
    # you wil output 4 word with the begining letters of word 'face'. Eg:
    # 'f'luidly 'a'tticism 'c'hivalrous 'e'xhilarated
    print(xp.generate_xkcdpassword(mywords, acrostic="face"))
    # create a password with acrostic "hand" --> 4 words
    print(xp.generate_xkcdpassword(mywords, acrostic="hand"))
    # create a password with acrostic "computer" --> 8 words
    print(xp.generate_xkcdpassword(mywords, acrostic="computer"))
    # create a password with acrostic "certificates" --> 12 words
    print(xp.generate_xkcdpassword(mywords, acrostic="certificates"))
    # create a password with acrostic "pki" --> 3 words
    print(xp.generate_xkcdpassword(mywords, acrostic="pki"))
