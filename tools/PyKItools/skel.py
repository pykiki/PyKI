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

from PyKI import PyKInit

if __name__ == '__main__':
    args = argCommandline()

    curScriptDir = os.path.dirname(os.path.abspath(__file__))
    configFilePath = curScriptDir + '/config/config.ini'
    
    pyki = PyKInit.PyKIsetup(configFilePath)
    pki = pyki.pki

    pki.remove_lockf("INFO: PKI unlocked.")
    del(pki)
    exit(0)
