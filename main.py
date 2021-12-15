import string
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA1
from Crypto.Signature import pss

# OPERACIONES BASICAS
def txtToBytes(rutaArchivoTxt):
    file = open(rutaArchivoTxt, "rb")
    bytes = file.read()
    file.close()
    return bytes

def leerLlave(rutaLlavePublica):
    llavePublica = RSA.import_key(open(rutaLlavePublica).read())
    return llavePublica


def generarLlave():
    caracteres = list(string.ascii_letters + string.digits)
    random.shuffle(caracteres)
    llave_x = []
    for i in range(16):
        llave_x.append(random.choice(caracteres))
    llave = "".join(llave_x)
    print(llave)
    return llave

def generarArchivo (rutaArchivoFA, bytes):
    file = open(rutaArchivoFA, "wb")
    file.write(bytes)
    file.close()
    print("Archivo nuevo generado")

##SOLO FIRMA
def firmar(rutaLlavePrivada, rutaMensajeClaro, rutaNuevoMensajeFirmado):
    mensaje = txtToBytes(rutaMensajeClaro)
    key = leerLlave(rutaLlavePrivada)
    hash = SHA1.new(mensaje)
    firmado = pss.new(key).sign(hash)
    contenido = firmado + hash
    generarArchivo(rutaNuevoMensajeFirmado, contenido)

def verificarFirma(rutaLlavePublica, rutaMensajeFirmado):
    mensaje = txtToBytes(rutaMensajeFirmado)
    key = leerLlave(rutaLlavePublica)
    h = SHA1.new(mensaje[128:])
    verificar = pss.new(key)
    try:
        verificar.verify(h, mensaje[0:128])
        print("Firma autentica")
    except():
        print("Firma no valida")

###SOLO AES
def cifradoAES (rutaMensajeClaro, rutaNuevoMensajeCifrado):
    byteog = txtToBytes(rutaMensajeClaro)
    llave_crudo = generarLlave()
    llave_b = bytes(llave_crudo, 'utf-8')
    iv_b = llave_b[::-1]
    cifradoCBC = AES.new(llave_b, AES.MODE_CBC, iv_b)
    bytesCifrado = cifradoCBC.encrypt(pad(byteog, AES.block_size))
    generarArchivo(rutaNuevoMensajeCifrado, bytesCifrado)

def descifradoAES (rutaMensajeCifrado, llave, rutaNuevoMensajeCifrado):
    bytesorigen = txtToBytes(rutaMensajeCifrado)
    llave_b = bytes(llave, 'utf8')
    iv_b = llave_b[::-1]
    cifradoCBC = AES.new(llave, AES.MODE_CBC, iv_b)
    bytesdescifrado = unpad(cifradoCBC.decrypt(bytesorigen), AES.block_size)
    generarArchivo(rutaNuevoMensajeCifrado, bytesdescifrado)

##AMBOS FIRMA + AES
'''FUNCIONES AUXILIARES'''
def cifradoAESFIRMA(rutaMensajeClaro, rutaLlavePublica, rutaLlavePrivada, rutaNuevoMensajeCifrado):
    #Leer bytes del txt original
    bytesoriginales = txtToBytes(rutaMensajeClaro)
    #GENERAR PARAMETROS
    llave_str = generarLlave()
    llave_b = bytes(llave_str, 'utf8')
    iv_b = llave_b[::-1]
    ##Ciframos los parametros con la llave Publica.
    llavePublica = leerLlave(rutaLlavePublica)
    cifradorParametros = PKCS1_OAEP.new(llavePublica)
    cifradoParametrosBytes = cifradorParametros.encrypt(llave_b)
    print(len(cifradoParametrosBytes))

    ##Firmamos el texto y guardamos
    llavePrivada = leerLlave(rutaLlavePrivada)
    hash_contenido = SHA1.new(bytesoriginales)
    firmado = pss.new(llavePrivada).sign(hash_contenido)
    firmatotal = firmado + bytesoriginales
    print (len(firmado))
    print(len(firmatotal))
    ##Ciframos el guardado
    cifradoCBC = AES.new(llave_b, AES.MODE_CBC, iv_b)
    bytesCifrados = cifradoCBC.encrypt(pad(firmatotal, AES.block_size))

    bytesTotales = cifradoParametrosBytes + bytesCifrados

    generarArchivo(rutaNuevoMensajeCifrado, bytesTotales)


def descifrarAESFIRMA(rutaMensajeCifrado, rutaLlavePublica, rutaLlavePrivada, rutaNuevoMensajeDescifrado):
    contenido = txtToBytes(rutaMensajeCifrado)
    llavePrivada = leerLlave(rutaLlavePrivada)
    cipherRSA = PKCS1_OAEP.new(llavePrivada)
    llave_RSAb = cipherRSA.decrypt(contenido[0:128])
    iv_b = llave_RSAb[::-1]
    ##Desciframos lo firmado con AES:

    descifradoAESRSA = AES.new(llave_RSAb, AES.MODE_CBC, iv_b)
    bytesFIRMACIF = unpad(descifradoAESRSA.decrypt(contenido[128:]), AES.block_size)

    #Leemos primero las credenciales
    key = leerLlave(rutaLlavePublica)
    h = SHA1.new(bytesFIRMACIF[128:])
    verificar = pss.new(key)
    try:
        verificar.verify(h,bytesFIRMACIF[0:128])
        generarArchivo(rutaNuevoMensajeDescifrado, bytesFIRMACIF[128:])
        print("CONTENIDO DEL MENSAJE..............................................................")
        print(bytesFIRMACIF[128:].decode('utf-8'))
        print("FIN DEL CONTENIDO")
        print("VERIFICADO")
    except:
        print("NO VERIDICO")




cifradoAESFIRMA('mensajeAlicia.txt', 'llavepublicaAlicia.der', 'llaveprivadaBetito.der', 'cifradoAliciaBetito.txt')
descifrarAESFIRMA('cifradoAliciaBetito.txt', 'llavepublicaBetito.der', 'llaveprivadaAlicia.der', 'nuevonuevomensaje.txt')
