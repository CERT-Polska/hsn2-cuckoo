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

'''
Created on 30-05-2012

@author: wojciechm
'''

import sys
sys.path.append("/opt/hsn2/python/commlib")
from hsn2taskprocessor import HSN2TaskProcessor
from hsn2taskprocessor import ParamException, ProcessingException
from hsn2osadapter import ObjectStoreException
import hsn2objectwrapper as ow
import logging
import subprocess
import os
import time
import tempfile
import hashlib
import shutil
import sqlite3
import json
import base64

def md5File(filePath):
	return hashlib.md5(open(filePath).read()).hexdigest()

def mvContentToFile(content, filename = None):
	fileDir = tempfile.mkdtemp()
	if filename is None:
		filename = md5File(content)
	file_path = os.path.join(fileDir, filename)
	shutil.move(content, file_path)
	os.chmod(fileDir, 0705)
	os.chmod(file_path, 0704)
	return file_path

def urlToFile(url):
	fileDir = tempfile.mkdtemp()
	file_path = os.path.join(fileDir, "%s.url" % hashlib.md5(url).hexdigest())
	file_handle = open(file_path, "w")
	file_handle.write(url)
	file_handle.close()
	os.chmod(fileDir, 0705)
	os.chmod(file_path, 0704)
	return file_path

def rmTmpDirByFilepath(filename):
	shutil.rmtree(os.path.split(filename)[0], True)

def get_task_by_id(tId, dbObj = None):
	"""
	Retrieves a task with a specific id.
	@param tId: the task's id
	@return: the task if one was found or None
	"""
	if not dbObj.cursor:
		return None
	try:
		dbObj.cursor.execute("SELECT * FROM tasks " \
							 "WHERE id = %d " \
							 "LIMIT 1;" % tId)
	except sqlite3.OperationalError, why:
		logging.debug(why)
		return None

	for row in dbObj.cursor.fetchall():
		return row
	return None

class CuckooTaskProcessor(HSN2TaskProcessor):
	'''
	Task processor for Cuckoo.
	What should be done in processing:
	1) launch appropriate Cuckoo methods with required arguments
	2) read output - determine whether successful or failed
	3a) If failed throw TaskFailedException
	3b) If successful return tuple (task, warnings)
	'''
	cuckooDir = None
	cuckooConfig = None
	cuckooDefaultTimeout = None

	def __init__(self, connector, datastore, serviceName, serviceQueue, objectStoreQueue, **extra):
		'''
		Runs Process init first and then creates required connections.
		To do: Implement data store connection.
		To do: Implement object store interaction.
		'''
		HSN2TaskProcessor.__init__(self, connector, datastore, serviceName, serviceQueue, objectStoreQueue, **extra)
		self.cuckooDir = extra.get("cuckoo")
		self.cuckooFinalTimeout = extra.get("timeout")
		sys.path.append(self.cuckooDir)
		import lib.cuckoo.core.database
		import lib.cuckoo.common.config
		os.chdir(self.cuckooDir)
		self.cuckooConfig = lib.cuckoo.common.config.Config()
		self.cuckooDB = lib.cuckoo.core.database.Database()
		self.cuckooDefaultTimeout = self.cuckooConfig.get("cuckoo").get("analysis_timeout", 120)

	def taskProcess(self):
		'''	This method should be overridden with what is to be performed.
			Returns a list of warnings (warnings). The current task is available at self.currentTask'''
		logging.debug(self.__class__)
		logging.debug(self.currentTask)
		logging.debug(self.objects)
		if len(self.objects) == 0:
			raise ObjectStoreException("Task processing didn't find task object.")
		if self.objects[0].isSet("filename"):
			filename = self.objects[0].filename
		else:
			filename = None
		if self.objects[0].isSet("content"):
			filePath = self.dsAdapter.saveTmp(self.currentTask.job, self.objects[0].content.getKey())
			filePath = mvContentToFile(content, filename)
		elif self.objects[0].isSet("url_original"):
			url = self.objects[0].url_original
			filePath = urlToFile(url)
			options = "url=" + base64.b64encode(url).rstrip('=')
		elif self.objects[0].isSet("url_normalized"):
			url = self.objects[0].url_normalized
			filePath = urlToFile(url)
		else:
			raise ParamException("content, url_original and url_normalized are missing.")
		params = {
			"timeout" :self.cuckooDefaultTimeout,
			"priority" : 0,
			"package" : "ie",
			"vm_id" : "",
			"save_pcap" : False,
			"save_report_json" : True,
			"save_report_html" : False,
			"save_screenshots" : True,
			"operating_system" : None,
			"rating_whitelist" : 0.5,
			"rating_services" : 0.5,
			"rating_hidden" : 1.5,
			"rating_orphan" : 1.5,
			"rating_api_unknown" : 1.5,
			"rating_api_known" : 0.5,
			"rating_malfind_pe" : 1.5,
			"rating_malfind" : 0.5,
			"behavioral_importance" : 1,
			"rating_threshold_benign" : 1,
			"rating_threshold_suspicious" : 1.5,
		}

		logging.debug(params)

		try:
			for param in self.currentTask.parameters:
				if param.name in params:
					value = params.get(param.name)
					if isinstance(value, bool):
						value = self.paramToBool(param)
					elif isinstance(value, int):
						value = int(param.value)
					elif isinstance(value, float):
						value = float(param.value)
					else:
						value = str(param.value)
					params[param.name] = value
		except BaseException as e:
			raise ParamException("%s" % str(e))
		logging.debug("Parameters are: %s" % repr(params))
		analysisDir = ""
		try:
			self.objects[0].addTime("cuckoo_time_start", int(time.time() * 1000))
			md5 = md5File(filePath)
			cuckooTaskId = self.cuckooDB.add(filePath,
					priority = params.get("priority"),
					package = params.get("package"),
					machine = params.get("vm_id"),
					platform = None,
					options = options,
					custom = json.dumps(params),
					timeout = params.get("timeout"),
					md5 = md5
				)
			if cuckooTaskId is None:
				raise ProcessingException("Cuckoo return None as task_id.")
			######################################################################
			#WAITING FOR CUCKOO TASK COMPLETION AND ANALYSIS HAPPENS HERE - START#
			######################################################################

			logging.debug("Cuckoo taskId is: %d" % cuckooTaskId)
			task = get_task_by_id(cuckooTaskId, self.cuckooDB)
			timeSlept = 0
			while task.get("completed_on") is None and timeSlept < self.cuckooFinalTimeout and self.keepRunning:
				logging.debug("Wait loop. Time passed: %d" % timeSlept)
				timeSlept = timeSlept + 2
				time.sleep(2)
				task = get_task_by_id(cuckooTaskId, self.cuckooDB)
				logging.debug("Task is: %s" % repr(task))
			if task.get("status") == 1:
				raise ProcessingException("Cuckoo marked processing as failed.")
			if task.get("status") == 0:
				if self.keepRunning:
					raise ProcessingException("Cuckoo processing passed it's timeout.")
				else:
					return []

			analysisDir = os.path.join("storage", "analyses", "%d" % cuckooTaskId)
			if not os.path.isdir(analysisDir):
				raise ProcessingException("Couldn't find the task analysis directory '%s'" % analysisDir)

			if params.get("save_pcap"):
				fileUp = os.path.join(self.cuckooDir, analysisDir, "dump.pcap")
				timeSpent = self.waitForLog(fileUp, isDir = False, timeout = self.cuckooFinalTimeout - timeSlept)
				if timeSpent is not None:
					self.objects[0].addBytes("cuckoo_pcap", self.dsAdapter.putFile(fileUp, self.currentTask.job))
					timeSlept = timeSlept + timeSpent
				else:
					raise ProcessingException("Didn't find '%s'" % fileUp)
			if params.get("save_report_html"):
				fileUp = os.path.join(self.cuckooDir, analysisDir, "reports", "report.html")
				timeSpent = self.waitForLog(fileUp, isDir = False, timeout = self.cuckooFinalTimeout - timeSlept)
				if timeSpent is not None:
					self.objects[0].addBytes("cuckoo_report_html", self.dsAdapter.putFile(fileUp, self.currentTask.job))
					timeSlept = timeSlept + timeSpent
				else:
					raise ProcessingException("Didn't find '%s'" % fileUp)

			fileUp = os.path.join(self.cuckooDir, analysisDir, "reports", "report.json")
			timeSpent = self.waitForLog(fileUp, isDir = False, timeout = self.cuckooFinalTimeout - timeSlept)
			if timeSpent is not None:
				fh = open(fileUp)
				report = json.load(fh)
				fh.close()
				logging.debug(report)
				rating = self.sumRating(report, params)
				if rating[0] is not None:
					self.objects[0].addString("cuckoo_classification", rating[0])
				if rating[1] is not None:
					self.objects[0].addString("cuckoo_classification_reason", rating[1])
				if params.get("save_report_json"):
					self.objects[0].addBytes("cuckoo_report_json", self.dsAdapter.putFile(fileUp, self.currentTask.job))
				timeSlept = timeSlept + timeSpent
			else:
				raise ProcessingException("Didn't find '%s'" % fileUp)
			if params.get("save_screenshots"):
				fileUp = os.path.join(analysisDir, "shots")
				timeSpent = self.waitForLog(fileUp, isDir = True, timeout = self.cuckooFinalTimeout - timeSlept)
				if timeSpent is not None:
					self.storeZip(fileUp)
					timeSlept = timeSlept + timeSpent
				else:
					raise ProcessingException("Didn't find '%s'" % fileUp)

			####################################################################
			#WAITING FOR CUCKOO TASK COMPLETION AND ANALYSIS HAPPENS HERE - END#
			####################################################################
			self.objects[0].addTime("cuckoo_time_stop", int(time.time() * 1000))
		finally:
			rmTmpDirByFilepath(filePath)
			if len(analysisDir) > 0 and os.path.isdir(analysisDir):
				rmTmpDirByFilepath(os.path.join(analysisDir, "analysis.log"))
		return []

	def sumRating(self, results, params):
		maxPid = None
		nPid = None
		summedResults = {}
		overallRating = 0
		volatilityResults = results.get("volatility")
		procmonResults = results.get("procmon")
		if not volatilityResults and not procmonResults:
			return (None, None)
		if volatilityResults:
			for result in volatilityResults:
				summedResults[result] = volatilityResults[result]["summed_rating"]
		if procmonResults:
			for result in procmonResults:
				try:
					summedResults[result] += procmonResults[result]["summed_rating"]
				except KeyError:
					summedResults[result] = procmonResults[result]["summed_rating"]
		if summedResults.get("-"):
			overallRating = summedResults["-"]
			del summedResults["-"]
		for result in summedResults:
			if maxPid is None or summedResults[result] > maxPid:
				maxPid = summedResults[result]
				nPid = result
		if maxPid is None:
			maxPid = 0
		overallRating += maxPid
		textRating = "BENIGN"
		if overallRating >= params.get("rating_threshold_benign"):
			textRating = "SUSPICIOUS"
		if overallRating >= params.get("rating_threshold_suspicious"):
			textRating = "MALICIOUS"
		reason = "Pid:%s. " % str(nPid)
		if volatilityResults and volatilityResults.get(nPid):
			reason += str(volatilityResults[nPid])
		if procmonResults and procmonResults.get(nPid):
			reason += str(procmonResults[nPid])
		return (textRating, reason)

	def waitForLog(self, filePath, timeout = 30, interval = 2, isDir = False):
		'''
		Wait for log files to be created.
		@param filePath: The path to the file to wait for.
		@param timeout: Time to wait in seconds.
		@param interval: How often to check.
		@param isDir: Does the path point to a directory?
		@return: If files appeared then the time spent waiting and otherwise None.
		'''
		i = 0
		while i < timeout and self.keepRunning:
			logging.debug("Wait for log '%s'. Time passed: %d/%d" % (filePath, i, timeout))
			if isDir:
				if os.path.isdir(filePath):
					return i
			else:
				if os.path.isfile(filePath):
					return i
			i = i + interval
			time.sleep(interval)
		return None

	def storeZip(self, dirPath):
		zip = shutil.make_archive(dirPath, "zip", dirPath, verbose = False)
		self.objects[0].addBytes("cuckoo_screenshots", self.dsAdapter.putFile(zip, self.currentTask.job))
		logging.debug("'%s' zip stored" % zip)
		os.remove(zip)
