from attestationlibrary import AttestationServer
import http.server
import http.cookies
import time
import ssl
from io import BytesIO
import random
import string
import base64
import json

hostName = "localhost"
serverPort = 8080
myAttestationServer= AttestationServer()

def initglobalstate():
	global confirmationEnabled
	confirmationEnabled = False  
	return
def initializeRegistration(user):
	return myAttestationServer.getInitialRegistrationParameters(user)

def verifyCertificateChain(user,certificateChain):
	return (myAttestationServer.parseCertificateChain(user,certificateChain), myAttestationServer.getKeyProperties(user))

def initializeTransaction(sender,receiver,amount):
	prompt = "SENDING "+ amount +" TO "+receiver
	returnval =myAttestationServer.getInitialConfirmationParameters(sender,prompt)
	print(returnval)
	return returnval

def verifyConfirmationMessage(user,confirmationMessage):

	return myAttestationServer.verifyConfirmationSignature(user,confirmationMessage)

class MyServer(http.server.BaseHTTPRequestHandler):
	
	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-type", "text/html")
		self.end_headers()
		self.wfile.write(bytes("<html><head><title>Payment Server</title></head>", "utf-8"))
		self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
		self.wfile.write(bytes("<body>", "utf-8"))
		self.wfile.write(bytes("<p>SUCCESS.</p>", "utf-8"))
		self.wfile.write(bytes("</body></html>", "utf-8"))
	def do_POST(self):
		#Add declaration for global variables here as well
		global confirmationEnabled
		content_length =  int(self.headers['Content-Length'])
		body = self.rfile.read(content_length).decode("latin_1")
		if "ConfirmationRequest" in body:
			message={}
			message["Request"] = body[body.find("Request")+11:body.find("ConfirmationMessage")-4]
			message["ConfirmationMessage"] = body[body.find("ConfirmationMessage")+23:-2]
		else:
			message = json.loads(body)
			if message["Username"] ==  "jackielee" and message["Password"] == "brucechan":
				self.send_response(200)
				cookie=http.cookies.SimpleCookie()
				cookie['user'] = message["Username"]
				for morsel in cookie.values():
					self.send_header("Set-Cookie",morsel.OutputString())
				self.end_headers()
				response = BytesIO()
				response.write(b'LOGGED IN')
				self.wfile.write(response.getvalue())
			else:
				self.send_response(200)
				self.end_headers()
				response = BytesIO()
				response.write(b'FAILED')
				self.wfile.write(response.getvalue())
		elif message["Request"] == "Payment":
			self.send_response(200)
			cookie=http.cookies.SimpleCookie(self.headers.get("Cookie"))
			if cookie['user'] == "NA":
				self.end_headers
				response = BytesIO()
				response.write(b'SIGN IN AGAIN')
				self.wfile.write(response,getvalue())
			else:
				for morsel in cookie.values():
					self.send_header("Set-Cookie",morsel.OutputString())
				self.end_headers()
				response = BytesIO()
				if confirmationEnabled == True:
					promptDetails = initializeTransaction(str(cookie['user']),message["Recipient"],message["Amount"])
					response.write(promptDetails.encode("utf-8"))
				else:
					response.write(b'SENT ')
					response.write(str(message["Amount"]).encode("utf-8"))
					response.write(b" TO ")
					response.write(str(message["Recipient"]).encode("utf-8"))
				self.wfile.write(response.getvalue())
		elif message["Request"] == "RegisterConfirmation":
			self.send_response(200)
			cookie=http.cookies.SimpleCookie(self.headers.get("Cookie"))
			if cookie['user'] == "NA":
				self.end_headers
				response = BytesIO()
				response.write(b'SIGN IN AGAIN')
				self.wfile.write(response,getvalue())
			else:
				for morsel in cookie.values():
					self.send_header("Set-Cookie",morsel.OutputString())
				self.end_headers()
				response = BytesIO()
				initVars=initializeRegistration(str(cookie['user']))
				response.write(initVars.encode("utf-8"))
				self.wfile.write(response.getvalue())
		elif message["Request"] == "RegisterCertificates":
			self.send_response(200)
			cookie=http.cookies.SimpleCookie(self.headers.get("Cookie"))
			if cookie['user'] == "NA":
				self.end_headers
				response = BytesIO()
				response.write(b'SIGN IN AGAIN')
				self.wfile.write(response,getvalue())
			else:
				for morsel in cookie.values():
					self.send_header("Set-Cookie",morsel.OutputString())
				self.end_headers()
				response = BytesIO()
				confirmationRegistrationSuccess,keyProperties = verifyCertificateChain(str(cookie['user']), message["CertificateChain"])
				print(keyProperties)
				print(confirmationRegistrationSuccess)
				confirmationEnabled = confirmationRegistrationSuccess
				response.write(str(confirmationRegistrationSuccess).encode("utf-8"))
				self.wfile.write(response.getvalue())
		elif message["Request"] == "ConfirmationRequest":
			self.send_response(200)
			cookie=http.cookies.SimpleCookie(self.headers.get("Cookie"))
			if cookie['user'] == "NA":
				self.end_headers
				response = BytesIO()
				response.write(b'SIGN IN AGAIN')
				self.wfile.write(response,getvalue())
			else:
				for morsel in cookie.values():
					self.send_header("Set-Cookie",morsel.OutputString())
				self.end_headers()
				response = BytesIO()
				confirmationMessageSuccess = verifyConfirmationMessage(str(cookie['user']), message["ConfirmationMessage"])
				response.write(str(confirmationMessageSuccess).encode("utf-8"))
				self.wfile.write(response.getvalue())
		else:
			self.send_response(400)
			self.end_headers()


if __name__ == "__main__":
	initglobalstate()
	webServer = http.server.HTTPServer((hostName, serverPort), MyServer)
	webServer.socket = ssl.wrap_socket(webServer.socket, server_side=True,certfile='servercert.pem',ssl_version=ssl.PROTOCOL_TLS)
	print("Server started http://%s:%s" % (hostName, serverPort))

	try:
		webServer.serve_forever()
	except KeyboardInterrupt:
		pass

	webServer.server_close()    
	print("Server stopped.")