#!/usr/bin/python
# CryPyNarf! Poit. ZOT!
# A threaded test of which SSL/TLS ciphers are
# supported on the server.

# Requires openssl for testing.


suites = {"ssl2": [
'DES-CBC3-MD5',
'IDEA-CBC-MD5',
'RC2-CBC-MD5',
'RC4-MD5',
'DES-CBC-MD5',
'EXP-RC2-CBC-MD5',
'EXP-RC4-MD5'],
"ssl3" : [
'DHE-RSA-AES256-SHA',
'DHE-DSS-AES256-SHA',
'AES256-SHA',
'DHE-RSA-CAMELLIA256-SHA',
'DHE-DSS-CAMELLIA256-SHA',
'CAMELLIA256-SHA',
'EDH-RSA-DES-CBC3-SHA',
'EDH-DSS-DES-CBC3-SHA',
'DES-CBC3-SHA',
'DHE-RSA-AES128-SHA',
'DHE-DSS-AES128-SHA',
'AES128-SHA',
'DHE-RSA-CAMELLIA128-SHA',
'DHE-DSS-CAMELLIA128-SHA',
'CAMELLIA128-SHA',
'IDEA-CBC-SHA',
'RC4-SHA',
'RC4-MD5',
'EDH-RSA-DES-CBC-SHA',
'EDH-DSS-DES-CBC-SHA',
'DES-CBC-SHA',
'EXP-EDH-RSA-DES-CBC-SHA',
'EXP-EDH-DSS-DES-CBC-SHA',
'EXP-DES-CBC-SHA',
'EXP-RC2-CBC-MD5',
'EXP-RC4-MD5'], 
"tls1" : [
'DHE-RSA-AES256-SHA',
'DHE-DSS-AES256-SHA',
'AES256-SHA',
'DHE-RSA-CAMELLIA256-SHA',
'DHE-DSS-CAMELLIA256-SHA',
'CAMELLIA256-SHA',
'EDH-RSA-DES-CBC3-SHA',
'EDH-DSS-DES-CBC3-SHA',
'DES-CBC3-SHA',
'DHE-RSA-AES128-SHA',
'DHE-DSS-AES128-SHA',
'AES128-SHA',
'DHE-RSA-CAMELLIA128-SHA',
'DHE-DSS-CAMELLIA128-SHA',
'CAMELLIA128-SHA',
'IDEA-CBC-SHA',
'RC4-SHA',
'RC4-MD5',
'EDH-RSA-DES-CBC-SHA',
'EDH-DSS-DES-CBC-SHA',
'DES-CBC-SHA',
'EXP-EDH-RSA-DES-CBC-SHA',
'EXP-EDH-DSS-DES-CBC-SHA',
'EXP-DES-CBC-SHA',
'EXP-RC2-CBC-MD5',
'EXP-RC4-MD5']}

import threading as th, sys, subprocess as sub

# Input validation. Sort of.
if len(sys.argv) != 2:
	sys.stderr.write("Syntax error! Correct usage:\n%s <target IP:target port> e.g. %s 127.0.0.1:443\n" % (sys.argv[0], sys.argv[0]))
	sys.exit(2)

# Build the dictionaries to store results.
failciphers = {"ssl2": [], "ssl3": [], "tls1": []}
yayciphers = {"ssl2": [], "ssl3": [], "tls1": []}

# The thread class to spawn off all of the tests.
class ciphtest(th.Thread):
	def __init__ (self, suite, host, cipher):
		# Accept parameters passed in.
		self.suite = suite
		self.host = host
		self.cipher = cipher
		th.Thread.__init__ ( self )

	def run(self):
		# Build the openssl command, run it, and poll for results.
		cmd = 'openssl	 s_client -' + self.suite + ' -connect ' + self.host + ' -cipher ' + self.cipher
		p = sub.Popen(cmd, shell=True, stdout=sub.PIPE, stderr=sub.PIPE)
		p.poll()
		if	p.returncode == None:
			# If we have no return yet, read input, and kill ourself. (Emo, yeah!)
			p.stdout.readline()
			p.kill()
			pcom = p.communicate()
			# Check for stdout as failures report to stderr.
			if pcom[0] != '':
				yayciphers[self.suite].append(self.cipher)
			else:
				failciphers[self.suite].append(self.cipher)

# Spawn the threads.
for zed in suites:
	for x in suites[zed]:
		ciphtest(zed, sys.argv[1], x).start()

# Ungraceful, but effective for now. Display the results for each suite.
print "#####################"
print "##  SSLv2 Ciphers  ##"
print "#####################"
for a in yayciphers["ssl2"]:
	print a

print "#####################"
print "##  SSLv3 Ciphers  ##"
print "#####################"
for a in yayciphers["ssl3"]:
	print a

print "#####################"
print "##  TLSv1 Ciphers  ##"
print "#####################"
for a in yayciphers["tls1"]:
	print a
