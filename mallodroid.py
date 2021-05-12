#!/usr/bin/env python3
# encoding: utf-8
"""
# This file is part of MalloDroid which is built up-on Androguard.
#
# Copyright (C) 2013, Sascha Fahl <fahl at dcsec.uni-hannover.de>
# All rights reserved.
#
# MalloDroid is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MalloDroid is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with MalloDroid.  If not, see <http://www.gnu.org/licenses/>.
"""

from androguard.core.analysis.analysis import Analysis, ExternalMethod
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.decompiler.decompiler import DecompilerJADX, DecompilerDAD

import os
import base64
import argparse

import json
import xmltodict

from enum import Enum, auto

import logging
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s', datefmt='%Y-%m-%d:%H:%M:%S', level='ERROR')
logger = logging.getLogger(__name__)


class Output(Enum):
	JSON = auto()
	XML = auto()

class Decompiler(Enum):
	DAD = auto()
	JADX = auto()

def _get_java_code(classAnalysis):
	try:
		return classAnalysis.get_vm_class().get_source()
	except Exception as e:
		logger.debug(f"Error getting Java source code for: {classAnalysis.get_vm_class().get_name()}")
	return None
	
def _has_signature(method, signatures):

	name = method.name
	_return = method.get_information().get('return', None)
	params = [_[1] for _ in method.get_information().get('params', [])]
	access_flags = method.get_access_flags_string()

	for signature in signatures:
		if (access_flags == signature['access_flags']) \
				and (name == signature['name']) \
				and (_return == signature['return']) \
				and (params == signature['params']):
			return True
	return False

def _class_implements_interface(classAnalysis, _interfaces):

	i = classAnalysis.implements
	j = [True for _ in _interfaces if _ in classAnalysis.implements]
	return (i and any(j))	

def _class_extends_class(classAnalysis, classes):

	return any([True for _ in classes if _ == classAnalysis.extends])

def _get_method_instructions(method):

	code = method.get_code()
	instructions = []
	if code:
		bc = code.get_bc()
		for instr in bc.get_instructions():
			instructions.append(instr)
	return instructions

def _returns_true(method):

	instructions = _get_method_instructions(method)
	if len(instructions) == 2:
		i = "->".join([instructions[0].get_output(), instructions[1].get_name() + "," + instructions[1].get_output()])
		i = i.replace(" ", "")
		v = instructions[0].get_output().split(",")[0]
		x = "{:s},1->return,{:s}".format(v, v)
		return i == x
	return False

def _returns_void(method):

	instructions = _get_method_instructions(method)
	if len(instructions) == 1:
		return instructions[0].get_name() == "return-void"
	return False

def _instantiates_allow_all_hostname_verifier(method):

	if not method.get_class_name() == "Lorg/apache/http/conn/ssl/SSLSocketFactory;":
		instructions = _get_method_instructions(method)
		for i in instructions:
			if i.get_name() == "new-instance" and i.get_output().endswith('Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;'):
				return True
			elif i.get_name() == "sget-object" and 'Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER' in i.get_output():
				return True
	return False

def _instantiates_get_insecure_socket_factory(method):

	instructions = _get_method_instructions(method)
	for i in instructions:
		if i.get_name() == "invoke-static" and i.get_output().endswith('Landroid/net/SSLCertificateSocketFactory;->getInsecure(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;'):
			return True
	return False

def _get_javab64_xref(classAnalysis):

	java_code = _get_java_code(classAnalysis)
	java_b64 = base64.b64encode(java_code.encode('utf-8'))
	xref = None
	try:
		xref = classAnalysis.get_xref_from()
	except AttributeError:
		pass
	return java_b64, xref

def _check_trust_manager(method, analysis):

	_check_server_trusted = {'access_flags' : 'public', 'return' : 'void', 'name' : 'checkServerTrusted', 'params' : ['java.security.cert.X509Certificate[]', 'java.lang.String']}
	_trustmanager_interfaces = ['Ljavax/net/ssl/TrustManager;', 'Ljavax/net/ssl/X509TrustManager;']
	custom_trust_manager = []
	insecure_socket_factory = []
	
	classAnalysis = analysis.get_class_analysis(method.get_class_name())
	
	if _has_signature(method, [_check_server_trusted]):

		if _class_implements_interface(classAnalysis, _trustmanager_interfaces):
			java_b64, xref = _get_javab64_xref(classAnalysis)
			_empty = _returns_true(method) or _returns_void(method)
			custom_trust_manager.append({'class' : classAnalysis, 'xref' : xref, 'java_b64' : java_b64, 'empty' : _empty})
			
	if _instantiates_get_insecure_socket_factory(method):

		java_b64, xref = _get_javab64_xref(classAnalysis)
		insecure_socket_factory.append({'class' : classAnalysis, 'method' : method, 'java_b64' : java_b64})

	return custom_trust_manager, insecure_socket_factory

def _check_hostname_verifier(method, analysis):

	verify_string_sslsession = {'access_flags' : 'public', 'return' : 'boolean', 'name' : 'verify', 'params' : ['java.lang.String', 'javax.net.ssl.SSLSession']}
	verify_string_x509cert = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'java.security.cert.X509Certificate']}
	verify_string_sslsocket = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'javax.net.ssl.SSLSocket']}
	verify_string_subj_alt = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'java.lang.String[]', 'java.lang.String[]']}
	verifier_interfaces = ['Ljavax/net/ssl/HostnameVerifier;', 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;']
	verifier_classes = ['L/org/apache/http/conn/ssl/AbstractVerifier;', 'L/org/apache/http/conn/ssl/AllowAllHostnameVerifier;', \
				'L/org/apache/http/conn/ssl/BrowserCompatHostnameVerifier;', 'L/org/apache/http/conn/ssl/StrictHostnameVerifier;']
	custom_hostname_verifier = []
	allow_all_hostname_verifier = []

	classAnalysis = analysis.get_class_analysis(method.get_class_name())
	
	if _has_signature(method, [verify_string_sslsession, verify_string_x509cert, verify_string_sslsocket, verify_string_subj_alt]):
		
		if _class_implements_interface(classAnalysis, verifier_interfaces) or _class_extends_class(classAnalysis, verifierclasses):
			java_b64, xref = _get_javab64_xref(classAnalysis)
			_empty = _returns_true(method) or _returns_void(method)
			custom_hostname_verifier.append({'class' : classAnalysis, 'xref' : xref, 'java_b64' : java_b64, 'empty' : _empty})
	if _instantiates_allow_all_hostname_verifier(method):
		
		java_b64, xref = _get_javab64_xref(classAnalysis)
		allow_all_hostname_verifier.append({'class' : _class, 'method' : method, 'java_b64' : java_b64})
	
	return custom_hostname_verifier, allow_all_hostname_verifier

def _check_ssl_error(method, analysis):

	_on_received_ssl_error = {'access_flags' : 'public', 'return' : 'void', 'name' : 'onReceivedSslError', 'params' : ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError']}
	_webviewclientclasses = ['Landroid/webkit/WebViewClient;']
	custom_on_received_ssl_error = []
	
	if _has_signature(method, [_on_received_ssl_error]):
		classAnalysis = analysis.get_class_analysis(method.get_class_name())
		if _class_extends_class(classAnalysis, _webviewclientclasses) or True:
			java_b64, xref = _get_javab64_xref(classAnalysis)
			_empty = _returns_true(method) or _returns_void(method)
			custom_on_received_ssl_error.append({'class' : classAnalysis, 'xref' : xref, 'java_b64' : java_b64, 'empty' : _empty})
	
	return custom_on_received_ssl_error

def _check_all(analysis):
	
	custom_trust_manager = []
	insecure_socket_factory = []
	
	custom_hostname_verifier = []
	allow_all_hostname_verifier = []
	
	custom_on_received_ssl_error = []

	for method in analysis.methods:
	
		#method = methodAnalysis.getmethod()
		
		if not isinstance(method, ExternalMethod):
		
			hv, a = _check_hostname_verifier(method, analysis)
			
			if len(hv) > 0:
				custom_hostname_verifier += hv
			if len(a) > 0:
				allow_all_hostname_verifier += a

			tm, i = _check_trust_manager(method, analysis)
			if len(tm) > 0:
				custom_trust_manager += tm
			if len(i) > 0:
				insecure_socket_factory += i

			ssl = _check_ssl_error(method, analysis)
			if len(ssl) > 0:
				custom_on_received_ssl_error += ssl

	return { 'trustmanager' : custom_trust_manager, 'insecuresocketfactory' : insecure_socket_factory, 'customhostnameverifier' : custom_hostname_verifier, 'allowallhostnameverifier' : allow_all_hostname_verifier, 'onreceivedsslerror' : custom_on_received_ssl_error}

def _print_result(result, java=True):

	print("Analysis result:")
	
	if len(result['trustmanager']) > 0:
		if len(result['trustmanager']) == 1:
			print("App implements custom TrustManager:")
		elif len(result['trustmanager']) > 1:
			print("App implements {len(result['trustmanager'])} custom TrustManagers")
			
		for tm in result['trustmanager']:
			class_name = tm['class'].name
			print(f"\tCustom TrustManager is implemented in class {_translate_class_name(class_name)}")
			if tm['empty']:
				print("\tImplements naive certificate check. This TrustManager breaks certificate validation!")
			for xref in tm['xref']:
				print(f"\t\tReferenced in method {_translate_class_name(xref.name)}->{xref.name}")
			if java:
				print("\t\tJavaSource code:")
				print(f"{base64.b64decode(tm['java_b64']).decode('utf-8')}")
	
	if len(result['insecuresocketfactory']) > 0:
		if len(result['insecuresocketfactory']) == 1:
			print("App instantiates insecure SSLSocketFactory:")
		elif len(result['insecuresocketfactory']) > 1:
			print(f"App instantiates {len(result['insecuresocketfactory'])} insecure SSLSocketFactorys")
		
		for isf in result['insecuresocketfactory']:
			class_name = _translate_class_name(isf['class'].name)
			print(f"\tInsecure SSLSocketFactory is instantiated in {class_name}->{isf['method'].name}")
			if java:
				print("\t\tJavaSource code:")
				print(f"{base64.b64decode(isf['java_b64']).decode('utf-8')}")

	if len(result['customhostnameverifier']) > 0:
		if len(result['customhostnameverifier']) == 1:
			print("App implements custom HostnameVerifier:")
		elif len(result['customhostnameverifier']) > 1:
			print(f"App implements {len(result['customhostnameverifier'])} custom HostnameVerifiers")

		for chnv in result['customhostnameverifier']:
			class_name = chnv['class'].name
			print(f"\tCustom HostnameVerifiers is implemented in class {_translate_class_name(class_name)}")
			if chnv['empty']:
				print("\tImplements naive hostname verification. This HostnameVerifier breaks certificate validation!")
			for xref in chnv['xref']:
				print(f"\t\tReferenced in method {_translate_class_name(xref.name)}->{xref.name}")
			if java:
				print("\t\tJavaSource code:")
				print(f"{base64.b64decode(chnv['java_b64']).decode('utf-8')}")

	if len(result['allowallhostnameverifier']) > 0:
		if len(result['allowallhostnameverifier']) == 1:
			print("App instantiates AllowAllHostnameVerifier:")
		elif len(result['allowallhostnameverifier']) > 1:
			print(f"App instantiates {len(result['allowallhostnameverifier'])} AllowAllHostnameVerifiers")

		for ahnv in result['allowallhostnameverifier']:
			class_name = _translate_class_name(ahnv['class'].name)
			print(f"\tAllowAllHostnameVerifier is instantiated in {class_name}->{ahnv['method'].name}")
		if java:
			print("\t\tJavaSource code:")
			print(f"{base64.b64decode(ahnv['java_b64']).decode('utf-8')}")

def _result_xml(package_name, result):

	from xml.etree.ElementTree import Element, SubElement, tostring, dump
	import xml.dom.minidom
	
	result_xml = Element('result')
	result_xml.set('package', package_name)
	trustmanagers = SubElement(result_xml, 'trustmanagers')
	hostnameverifiers = SubElement(result_xml, 'hostnameverifiers')
	onreceivedsslerrors = SubElement(result_xml, 'onreceivedsslerrors')

	for tm in result['trustmanager']:
		class_name = _translate_class_name(tm['class'].name)
		t = SubElement(trustmanagers, 'trustmanager')
		t.set('class', class_name)
		if tm['empty']:
			t.set('broken', 'True')
		else:
			t.set('broken', 'Maybe')
		
		for r in tm['xref']:
			rs = SubElement(t, 'xref')
			rs.set('class', _translate_class_name(r.get_class_name()))
			rs.set('method', r.name)
	
	if len(result['insecuresocketfactory']):
		for isf in result['insecuresocketfactory']:
			class_name = _translate_class_name(isf['class'].name)
			i = SubElement(trustmanagers, 'insecuresslsocket')
			i.set('class', class_name)
			i.set('method', isf['method'].name)
	else:
		i = SubElement(trustmanagers, 'insecuresslsocket')


	for chnv in result['customhostnameverifier']:
		class_name = _translate_class_name(chnv['class'].name)
		hnv = SubElement(hostnameverifiers, 'hostnameverifier')
		hnv.set('class', class_name)
		if chnv['empty']:
			hnv.set('broken', 'True')
		else:
			hnv.set('broken', 'Maybe')
		
		for xref in chnv['xref']:
			chnv_xref = SubElement(hnv, 'xref')
			chnv_xref.set('class', _translate_class_name(xref.name))
			chnv_xref.set('method', xref.name)
	
	if len(result['allowallhostnameverifier']):
		for ahnv in result['allowallhostnameverifier']:
			class_name = _translate_class_name(ahnv['class'].name)
			ahn = SubElement(hostnameverifiers, 'allowhostnames')
			ahn.set('class', class_name)
			ahn.set('method', ahnv['method'].name)
	else:
		ahn = SubElement(hostnameverifiers, 'allowhostnames')

	for orsse in result['onreceivedsslerror']:
		class_name = _translate_class_name(orsse['class'].name)
		sse = SubElement(onreceivedsslerrors, 'sslerror')
		sse.set('class', class_name)
		if orsse['empty']:
			sse.set('broken', 'True')
		else:
			sse.set('broken', 'Maybe')

		for xref in orsse['xref']:
			sse_xref = SubElement(sse, 'xref')
			sse_xref.set('class', _translate_class_name(xref.name))
			sse_xref.set('method', xref.name)
	
	_xml = xml.dom.minidom.parseString(tostring(result_xml, method="xml"))
	
	logger.debug("\nXML output:\n")
	logger.debug(f'{_xml.toprettyxml()}')
	
	return(_xml.toprettyxml())

def _translate_class_name(class_name):
	
	class_name = class_name[1:-1]
	class_name = class_name.replace("/", ".")
	return class_name

def _file_name(class_name, _basedir):

	class_name = class_name[1:-1]
	_f = os.path.join(_basedir, class_name + ".java")
	return _f

def _ensuredir(d):

	d = os.path.dirname(d)
	if not os.path.exists(d):
		os.makedirs(d)

def _store_java(analysis, folder):

	for classAnalysis in analysis.get_internal_classes():
		
		source = classAnalysis.get_vm_class().get_source()
		
		try:
			filename = _file_name(classAnalysis.name, folder)
			_ensuredir(filename)
			
			with open(filename, "w") as f:
			
				f.write(source)
				
		except Exception as e:
		
			logger.debug(f"Could not process {classAnalysis.name}: {e}")
					
def _parseargs():

	parser = argparse.ArgumentParser(description="Analyse Android Apps for broken SSL certificate validation.")
	parser.add_argument("-f", "--file", help="APK File to check", type=str, required=True)
	parser.add_argument("-j", "--java", help="Show Java code for results for non-XML output", action="store_true", required=False)
	parser.add_argument("-x", "--xml", help="Print XML output", action="store_true", required=False)
	parser.add_argument("-d", "--dir", help="Store decompiled App's Java code for further analysis in dir", type=str, required=False)
	parser.add_argument("-D", "--decompiler", help="Specify decompiler: DAD or JADX.", type=str, required=False, default='DAD')
	arguments = parser.parse_args()

	return arguments

def check_apk(path_to_apk: str, output: Output, decompiler: Decompiler, store_source:bool =False):

	apk = APK(path_to_apk)
	dex = DalvikVMFormat(apk)
	analysis = Analysis(dex)
		
	if decompiler == Decompiler.JADX:

		decompiler = DecompilerJADX(dex, analysis)

	elif decompiler == Decompiler.DAD:
	
		decompiler = DecompilerDAD(dex, analysis)

	dex.set_decompiler(decompiler)
	dex.set_vmanalysis(analysis)
		
	package_name = apk.get_package()
	
	if store_source:
		(apk_folder, apk_file) = os.path.split(path_to_apk)
		(apk_name, _) = os.path.splitext(apk_file)
		java_out_folder = os.path.join(apk_folder, apk_name)
		print(f"Store decompiled Java code in {java_out_folder}")
		_store_java(analysis, java_out_folder)
		
	return check_analysis(analysis, package_name, output)
	
def check_analysis(analysis: Analysis, package_name: str, output: Output):
	
	result = _check_all(analysis)
	
	x = _result_xml(package_name, result)
	
	if output == Output.XML:
	
		return(x)
		
	elif output == Output.JSON:

		return json.dumps(xmltodict.parse(x, attr_prefix=''), indent='\t')	
	
def main():

	arguments = _parseargs()
	
	apk = APK(arguments.file)
	dex = DalvikVMFormat(apk)
	analysis = Analysis(dex)

	D = arguments.decompiler
	if D == 'JADX':
		decompiler = DecompilerJADX(dex, analysis)#, jadx = path_to_jadx)
	elif D == 'DAD':
		decompiler = DecompilerDAD(dex, analysis)
	else:
		print(f'Warning: unknown decompiler {D}. Defaulting to DAD.')
		decompiler = DecompilerDAD(dex, analysis)		
	
	dex.set_decompiler(decompiler)
	dex.set_vmanalysis(analysis)
	
	print(f"Analyse file: {arguments.file}")
	print(f"Package name: {apk.get_package()}")
		
	if 'android.permission.INTERNET' in apk.get_permissions():
		print("App requires INTERNET permission. Continue analysis...")

		result = {'trustmanager' : [], 'hostnameverifier' : [], 'onreceivedsslerror' : []}
		result = _check_all(analysis)
		
		package_name = apk.get_package()
		
		if not arguments.xml:
			_print_result(result, java=arguments.java)
		else:
			print(_result_xml(package_name, result))
			
		if arguments.dir:
			folder = arguments.dir
			print(f"Store decompiled Java code in {folder}")
			_store_java(dex, folder)
			
	else:
		print("App does not require INTERNET permission. No need to worry about SSL misuse. Analysis not carried out.")

if __name__ == "__main__":
	main()
