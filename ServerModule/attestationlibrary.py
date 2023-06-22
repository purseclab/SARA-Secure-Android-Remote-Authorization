from http.server import HTTPServer, BaseHTTPRequestHandler

from io import BytesIO
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
import random
import string
import base64

def lengthParser(lengthHex):
	firstOctet=lengthHex[:2]
	length=-1
	rem=""
	if int(firstOctet,16) & int("80",16) == 0:
		length = int(firstOctet,16)
		rem=lengthHex[2:]
	else:
		noOctets= int(firstOctet,16) & int("7f",16)
		length=int(lengthHex[2:2+(noOctets*2)],16)
		rem=lengthHex[2+(noOctets*2):]	
	return (rem,length)

def extractContent(hexDump,length):
	rem=hexDump[length*2:]
	content=hexDump[:length*2]
	return (rem,content)

def tagParser(hexDump):
	firstOctet=hexDump[:2]
	tagClass=(int(firstOctet,16) & int("c0",16))>>6
	tagNumber=0
	rem=""
	PC=(int(firstOctet,16) & int("20",16))>>5
	if int(firstOctet,16) & int("1f",16) != int("1f",16):
		tagNumber=int(firstOctet,16) & int("1f",16)
		rem=hexDump[2:]
	else:
		i=2
		tagNumber=0
		while True:
			curOctet=hexDump[i:i+2]
			tagNumber=(tagNumber << 7)
			newBits= int(curOctet,16) & int("7f",16)
			tagNumber =  tagNumber | newBits
			if int(curOctet,16) & int("80",16) != int("80",16):
				break
			i=i+2
		rem=hexDump[i+2:]
	return(tagClass,PC,tagNumber,rem)
			
def octParseHelper(octRem):
	while True:
		(octTagClass,octPC,octTagNumber,octRem)=tagParser(octRem)
		(octRem,octLen)=lengthParser(octRem)
		(octRem,octContent)=extractContent(octRem,octLen)
		if octTagClass==0:
			if octTagNumber==1:
				print("Boolean==> ",octContent)
			elif octTagNumber==2:
				print("Integer==> ",int(octContent,16))
			elif octTagNumber==3:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:
					print("Hex String ==> ",octContent)
			elif octTagNumber==4:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:							
					print("Hex String ==> ",octContent)
			elif octTagNumber==16 or octTagNumber==17:
				octParseHelper(octContent)
		if len(octRem)==0:
			break
				

def authListParser(hexDump,uid):
	global keypropertiesDict
	rem=hexDump
	if len(rem) == 0:
		return
	while True:
		(tagClass,PC,tagNumber,rem)=tagParser(rem)
		(rem,length)=lengthParser(rem)
		(rem,content)=extractContent(rem,length)
		if tagNumber == 1:
			keypropertiesDict[uid]['PURPOSE']=[]
			if content[:2] == "31":
				(setRem,setLen)=lengthParser(content[2:])
				while True:
					(setTagClass,setPC,setTagNumber,setRem)=tagParser(setRem)
					(setRem,setLen)=lengthParser(setRem)
					(setRem,setContent)=extractContent(setRem,setLen)
					keypropertiesDict[uid]['PURPOSE'].append(int(setContent,16))
					if len(setRem)==0:
						break
			
		elif tagNumber ==2:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['ALGORITHM'].append(int(intContent,16))
		elif tagNumber ==3:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['KEYSIZE'].append(int(intContent,16))
			
		elif tagNumber ==5:
			
			if content[:2] == "31":
				(setRem,setLen)=lengthParser(content[2:])
				while True:
					(setTagClass,setPC,setTagNumber,setRem)=tagParser(setRem)
					(setRem,setLen)=lengthParser(setRem)
					(setRem,setContent)=extractContent(setRem,setLen)
					keypropertiesDict[uid]['DIGEST'].append(int(setContent,16))
					if len(setRem)==0:
						break
			
		elif tagNumber ==6:
			
			if content[:2] == "31":
				(setRem,setLen)=lengthParser(content[2:])
				while True:
					(setTagClass,setPC,setTagNumber,setRem)=tagParser(setRem)
					(setRem,setLen)=lengthParser(setRem)
					(setRem,setContent)=extractContent(setRem,setLen)
					keypropertiesDict[uid]['PADDING'].append(int(setContent,16))
					if len(setRem)==0:
						break
			
		elif tagNumber ==10:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['ECCURVE'].append(int(intContent,16))
			
		elif tagNumber ==200:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['RSA PUBLIC EXPONENT'].append(int(intContent,16))
			
		elif tagNumber ==303:
			
			if content[:2] == "05":
				keypropertiesDict[uid]['ROLLBACK RESISTANT'].append(True)
			else:
				keypropertiesDict[uid]['ROLLBACK RESISTANT'].append(False)
			
		elif tagNumber ==400:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['ACTIVE DATETIME'].append(int(intContent,16))
			
		elif tagNumber ==401:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['ORIGINATION EXPIRE DATE TIME'].append(int(intContent,16))
			
		elif tagNumber ==402:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['USAGE EXPIRE DATE TIME'].append(int(intContent,16))
			
		elif tagNumber ==503:
			
			if content[:2] == "05":
				keypropertiesDict[uid]['NO AUTH REQUIRED'].append(True)
			else:
				keypropertiesDict[uid]['NO AUTH REQUIRED'].append(False)
			
		elif tagNumber ==504:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['USER AUTH TYPE'].append(int(intContent,16))
			
		elif tagNumber ==505:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['AUTH TIMEOUT'].append(int(intContent,16))
			
		elif tagNumber ==506:
			
			if content[:2] == "05":
				keypropertiesDict[uid]['ALLOW WHILE ON BODY'].append(True)
			else:
				keypropertiesDict[uid]['ALLOW WHILE ON BODY'].append(False)
			
		elif tagNumber ==507:
			
			if content[:2] == "05":
				keypropertiesDict[uid]['TRUSTED USER PRESENCE REQUIRED'].append(True)
			else:
				keypropertiesDict[uid]['TRUSTED USER PRESENCE REQUIRED'].append(False)
			
		elif tagNumber ==508:
			keypropertiesDict[uid]["TRUSTED CONFIRMATION REQUIRED"]=[]
			if content[:2] == "05":
				keypropertiesDict[uid]["TRUSTED CONFIRMATION REQUIRED"].append(True)
			else:
				keypropertiesDict[uid]["TRUSTED CONFIRMATION REQUIRED"].append(False)
			
		elif tagNumber ==509:
			
			if content[:2] == "05":
				keypropertiesDict[uid]['UNLOCKED DEVICE REQUIRED'].append(True)
			else:
				keypropertiesDict[uid]['UNLOCKED DEVICE REQUIRED'].append(False)
			
		elif tagNumber ==600:
			
			if content[:2] == "05":
				keypropertiesDict[uid]['ALL APPLICATION'].append(True)
			else:
				keypropertiesDict[uid]['ALL APPLICATION'].append(False)
			
		elif tagNumber ==601:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			
		elif tagNumber ==701:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['CREATION DATETIME'].append(int(intContent,16))
			
		elif tagNumber ==702:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['ORIGIN'].append(int(intContent,16))
			
		elif tagNumber ==703:
			
			if content[:2] == "05":
				keypropertiesDict[uid]['ROLLBACK RESISTANT'].append(True)
			else:
				keypropertiesDict[uid]['ROLLBACK RESISTANT'].append(False)
			
		elif tagNumber ==704:
			
			(rotTagClass, rotPC, rotTagNumber, rotRem)=tagParser(content)
			(rotRem,rotLen)=lengthParser(rotRem)
			(rotRem,rotContent)=extractContent(rotRem,rotLen)
			if(rotTagNumber==16):
				(rotTagClass, rotPC, rotTagNumber, rotRem)=tagParser(rotContent)
				(rotRem,rotLen)=lengthParser(rotRem)
				(rotRem,rotContent)=extractContent(rotRem,rotLen)				
				keypropertiesDict[uid]['VERIFIED BOOT KEY'].append(rotContent)
				(rotTagClass, rotPC, rotTagNumber, rotRem)=tagParser(rotRem)
				(rotRem,rotLen)=lengthParser(rotRem)
				(rotRem,rotContent)=extractContent(rotRem,rotLen)
				keypropertiesDict[uid]['DEVICE LOCKED'].append(int(rotContent,16))
				(rotTagClass, rotPC, rotTagNumber, rotRem)=tagParser(rotRem)
				(rotRem,rotLen)=lengthParser(rotRem)
				(rotRem,rotContent)=extractContent(rotRem,rotLen)
				keypropertiesDict[uid]['VERIFIED BOOT STATE'].append(int(rotContent,16))
				(rotTagClass, rotPC, rotTagNumber, rotRem)=tagParser(rotRem)
				(rotRem,rotLen)=lengthParser(rotRem)
				(rotRem,rotContent)=extractContent(rotRem,rotLen)
				keypropertiesDict[uid]['VERIFIED BOOT HASH'].append(rotContent)
				if len(rotRem)>0:
					print("ERROR PARSING ROOT OF TRUST")
					
			
		elif tagNumber ==705:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['OS VERSION'].append(int(intContent,16))
			
		elif tagNumber ==706:
			
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['OS PATCH LEVEL'].append(int(intContent,16))
			
		elif tagNumber ==709:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			
		elif tagNumber ==710:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			
		elif tagNumber ==711:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			
		elif tagNumber ==712:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			
		elif tagNumber ==713:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			
		elif tagNumber ==714:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			
		elif tagNumber ==715:
			
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			 
		elif tagNumber ==716:
			 
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			 
		elif tagNumber ==717:
			 
			(octTagClass,octPC,octTagNumber,octRem)=tagParser(content)
			(octRem,octLen)=lengthParser(octRem)
			(octRem,octContent)=extractContent(octRem,octLen)
			try:
				octParseHelper(octContent)
			except:
				try:
					print("Decoded String==> ",bytearray.fromhex(octContent).decode())
				except:				
					print("Hex String ==> ",octContent)
			 
		elif tagNumber ==718:
			 
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['VENDOR PATCH LEVEL'].append(int(intContent,16))
			 
		elif tagNumber ==719:
			 
			(intTagClass,intPC,intTagNumber,intRem)=tagParser(content)
			(intRem,intLen)=lengthParser(intRem)
			(intRem,intContent)=extractContent(intRem,intLen)
			keypropertiesDict[uid]['BOOT PATCH LEVEL'].append(int(intContent,16))
			 
		else:
			print("NOT FOUND: ",tagNumber)
		if len(rem) == 0:
			break
	
	return

def parse(hexDump,uid):
	global keypropertiesDict
	if hexDump[:2] == "04":
		(remOctet,lengthOctet)=lengthParser(hexDump[2:])
		if remOctet[:2]=="30":
			(rem8Seq,length8Seq)=lengthParser(remOctet[2:])
			if rem8Seq[:2] == "02":
				(rem,length)=lengthParser(rem8Seq[2:])
				(rem,content)=extractContent(rem,length)
				attestationVersion=int(content,16)
				if rem[:2] == "0a":
					(rem,length)=lengthParser(rem[2:])
					(rem,content)=extractContent(rem,length)
					attestationSecurityLevel=int(content,16)
					
					if rem[:2] == "02":
						(rem,length)=lengthParser(rem[2:])
						(rem,content)=extractContent(rem,length)
						keymasterVersion=int(content,16)
						
						if rem[:2] == "0a":
							(rem,length)=lengthParser(rem[2:])
							(rem,content)=extractContent(rem,length)
							keymasterSecurityLevel=int(content,16)
							
							if rem[:2] == "04":
								(rem,length)=lengthParser(rem[2:])
								(rem,content)=extractContent(rem,length)
								attestationChallenge=bytes.fromhex(content).decode('utf-8')
								
								if rem[:2] == "04":
									(rem,length)=lengthParser(rem[2:])
									(rem,content)=extractContent(rem,length)
									uniqueID=bytes.fromhex(content).decode('utf-8')
									
									if rem[:2] == "30":
										(rem,length)=lengthParser(rem[2:])
										(rem,content)=extractContent(rem,length)
										
										authListParser(content,uid)
										if rem[:2] == "30":
											(rem,length)=lengthParser(rem[2:])
											(rem,content)=extractContent(rem,length)
											
											authListParser(content,uid)
											if len(rem) != 0:
												print("Unable to parse additional content in attestion certificate:" , rem)				
			
		else:
			print("couldn't find key description")
	else:
		print("OCTET STRING NOT FOUND")
	



class AttestationServer:
	def __init__(self):
		
		global certDict
		global store
		global nonceDict
		global keypropertiesDict
		global attestationChallengeDict
		certDict={}
		nonceDict={}
		keypropertiesDict={}
		attestationChallengeDict={}
		store = crypto.X509Store()

	def startReceiving(self,uid,rtype,message=''):
		global step
		global stepMax
		global userid
		global rectype
		global returnval
		global keeprunning
		global confirmmessage
		confirmmessage=message
		keeprunning = True
		userid = uid
		rectype = rtype


		step=0
		stepMax=0
		run(self.ip,self.port)
		if rtype == 1:
			return returnval

	def getInitialRegistrationParameters(self,uid):
		global attestationChallengeDict
		global keypropertiesDict
		attestationChallenge = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 16))
		attestationChallengeDict[uid] = attestationChallenge
		keypropertiesDict[uid]={}
		return attestationChallenge

	def parseCertificateChain(self,uid,certificateChainString):
		global store
		global keypropertiesDict
		global certDict
		certificateChains=certificateChainString.split("<|==|>")
		for certificateChain in certificateChains:
			certificates = certificateChain.split("<==>")
			for certificate in certificates:
				i=0
				start= "-----BEGIN CERTIFICATE-----\n".encode('utf-8')
				end= "-----END CERTIFICATE-----\n".encode('utf-8')
				pemCert=start
				while (i+64<len(certificate)):
					pemCert=pemCert+certificate[i:i+64].encode('utf-8')
					pemCert=pemCert+"\n".encode('utf-8')
					i+=64
				pemCert=pemCert+certificate[i:].encode('utf-8')
				pemCert=pemCert+"\n".encode('utf-8')
				pemCert=pemCert+end
				ourExtension="" 
				verCert=crypto.load_certificate(crypto.FILETYPE_PEM, pemCert.decode('utf-8'))
				storeCtx=crypto.X509StoreContext(store,verCert)
				try:
					str(storeCtx.verify_certificate())
					store.add_cert(verCert)
					
				except Exception as e:
					certException=str(e)
					certException=certException.split("\'")
					if certException[1]=="self signed certificate":
						
						store.add_cert(verCert)
					elif certException[1] == "certificate is not yet valid":
						print("CERTIFICATE NOT YET VALID")
						store.add_cert(verCert)
					else:
						print(certException[1])
						return False
				
				cert = x509.load_pem_x509_certificate(pemCert,default_backend())
				hexDump=base64.b64decode(certificate).hex()
				extStartIndex=hexDump.find("060a2b06010401d679020111")
				if(extStartIndex != -1):
					certDict[uid]=cert
					octetStringRem=hexDump[extStartIndex+24:]
					if octetStringRem[:2] == "04":
						(rem,octetStringLength)=lengthParser(octetStringRem[2:])
						octetString=octetStringRem[:octetStringRem.find(rem)+octetStringLength*2]		
					else:
						print("OCTET STRING NOT FOUND")
					parse(octetString,uid)
		return True

	def getInitialConfirmationParameters(self,uid,messageToConfirm):
		global nonceDict
		nonce = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
		nonceDict[uid] = nonce
		return nonce+"PLEASE CONFIRM: "+messageToConfirm

	def verifyAuthSignature(self,uid,messageWithSignature):
		datathatwasconfirmed=bytes(messageWithSignature.split('<==>')[0],'latin_1')
		prompt=datathatwasconfirmed.split(b'PLEASE CONFIRM: ')[1].split(b'extra')[0].decode('utf-8')[:-1]
		recnonce=datathatwasconfirmed.split(b'PLEASE CONFIRM: ')[2].decode('utf-8')[-5:]
		signature=bytes(messageWithSignature.split('<==>')[1],'latin_1')
		pubkey=certDict[uid].public_key()
		der = pubkey.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
		key = RSA.import_key(der)
		h = SHA256.new(datathatwasconfirmed)
		verifier = pss.new(key)
		try:
			verifier.verify(h, signature)
			if recnonce==nonceDict[uid]:
				returnval  = True
			else:
				returnval = False
		except (ValueError, TypeError):
			returnval  = False
		return returnval


	def getKeyProperties(self,uid):
		global keypropertiesDict
		return keypropertiesDict[uid]

