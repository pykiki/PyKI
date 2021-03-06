#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from re import sub as resub
from unicodedata import normalize as uninormalize

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


def strip_accents(text):
    """
    Strip accents from input String.

    :param text: The input string.
    :type text: String.

    :returns: The processed String.
    :rtype: String.
    """
    try:
        text = unicode(text, 'utf-8')
    except NameError:  # unicode is a default on python 3
        pass
    text = uninormalize('NFD', text)
    text = text.encode('ascii', 'ignore')
    text = text.decode("utf-8")
    return str(text)


def rmSpecialChar(instr):
    cleanStr = resub('\W+', '_', instr)
    return(cleanStr)


def cleanStr(txt):
    string = rmSpecialChar(strip_accents(txt))
    return(string)

if __name__ == "__main__":
    string = "wiki.maibach.fr"
    print(cleanStr(string))
