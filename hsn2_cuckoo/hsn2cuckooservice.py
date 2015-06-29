#!/usr/bin/python -tt

# Copyright (c) NASK, NCSC
# 
# This file is part of HoneySpider Network 2.0.
# 
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
from os import path

from hsn2_commons.hsn2service import HSN2Service
from hsn2_commons.hsn2service import startService
from hsn2cuckootaskprocessor import CuckooTaskProcessor


class CuckooService(HSN2Service):
	serviceName = "cuckoo"
	description = "HSN 2 Cuckoo Service"

	'''
	This is the HSN2 service which utilizes the Cuckoo sandbox.
	'''

	def extraOptions(self, parser):
		'''Arguments specific to this service. Receives a parser with the standard options. Returns a modified parser.'''
		parser.add_argument('--cuckoo', '-C', action = 'store', help = 'path to the cuckoo directory', default = "/opt/cuckoo", required = False, dest = 'cuckoo')
		parser.add_argument('--timeout', '-t', action = 'store', help = 'path to the cuckoo directory', type = int , default = 900, required = False, dest = 'timeout')
		return parser

	def sanityChecks(self, cliargs):
		passed = HSN2Service.sanityChecks(self, cliargs)
		if not path.isdir(cliargs.cuckoo):
			logging.error("'%s' is not a dir" % cliargs.cuckoo)
			passed = False
		else:
			if not path.isfile(path.join(cliargs.cuckoo, "cuckoo.py")):
				logging.error("'%s' is not a file" % path.join(cliargs.cuckoo, "cuckoo.py"))
				passed = False
		return passed

if __name__ == '__main__':
	startService(CuckooService, CuckooTaskProcessor)
