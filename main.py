import string
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


# OPERACIONES BASICAS
def txtToBytes(rutaArchivoTxt):
    file = open(rutaArchivoTxt, "rb")
    bytes = file.read()
    file.close()
    return bytes

def leerLlavePublica(rutaLlavePublica):
    llavePublica = RSA.import_key(open(rutaLlavePublica).read())
    return llavePublica

def leerLlavePrivada(rutaLlavePrivada):
    llavePrivada = RSA.import_key(open(rutaLlavePrivada).read())
    return llavePrivada

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

#CIFRADO y FIRMA
def cifrarTXT (rutaArchivoTxt, rutaLlavePublica, rutaArchivoNuevoFA):
    bytesOG = txtToBytes(rutaArchivoTxt)
    llave_str = generarLlave()
    llave_b = bytes(llave_str, 'utf-8')
    iv_b = bytes(llave_str[::-1], 'utf-8')
    cifradoCBC = AES.new(llave_b, AES.MODE_CBC, iv_b)
    bytesCifrado = cifradoCBC.encrypt(pad(bytesOG, AES.block_size))
    bytesParametros = cifradoRSA1(rutaLlavePublica, llave_b)
    print(len(bytesParametros))
    print(len(bytesCifrado))
    bytesTotales = bytesParametros + bytesCifrado
    print(len(bytesTotales))
    generarArchivo(rutaArchivoNuevoFA, bytesTotales)


def cifradoRSA1(rutaLlavePublica, parametros):
    llavePublica = leerLlavePublica(rutaLlavePublica)
    cipher = PKCS1_OAEP.new(llavePublica)
    mensajecifrado = cipher.encrypt(parametros)
    return mensajecifrado

#DESCIFRADO Y FIRMA
def descifrarTXT (rutaMensajeCifrado, rutaLlavePrivada):
    bytesCF = txtToBytes(rutaMensajeCifrado)
    parametrosBytes = descifradoRSA1(rutaLlavePrivada, bytesCF[0:128])
    contenido = bytesCF[128:]
    llave = parametrosBytes
    iv = parametrosBytes[::-1]
    descifradoCBC = AES.new(llave, AES.MODE_CBC, iv)
    bytesDescifrados = unpad(descifradoCBC.decrypt(contenido), AES.block_size)
    print(bytesDescifrados.decode('utf8'))

def descifradoRSA1(rutaLlavePrivada, parametros):
    llavePrivada = leerLlavePrivada(rutaLlavePrivada)
    cipher = PKCS1_OAEP.new(llavePrivada)
    parametros_bytes = cipher.decrypt(parametros)
    print(parametros_bytes.decode('utf-8'))
    return parametros_bytes


##SOLO AES CIFRADO
def cifradoAES(rutaArchivoTXT, rutaArchivoCifrado):
    bytesOG = txtToBytes(rutaArchivoTXT)
    llave_str = generarLlave()
    llave_b = bytes(llave_str, 'utf-8')
    iv_b = llave_b[::-1]
    cifradoAES = AES.new(llave_b, AES.MODE_CBC, iv_b)
    bytesCifrado = cifradoAES.encrypt(pad(bytesOG, AES.block_size))
    generarArchivo(rutaArchivoCifrado, bytesCifrado)

#SOLO AES DESCIFRADO
def descifradoAES(rutaMnesajeCifrado, llave, rutaMensajeClaro):
    bytesOG = txtToBytes(rutaMnesajeCifrado)
    llave_b = bytes(llave, 'utf-8')
    iv_b = llave_b[::-1]
    decifrado  = AES.new(llave_b, AES.MODE_CBC, iv_b)
    bytesDES = unpad(decifrado.decrypt(bytesOG), AES.block_size)
    print(bytesDES.decode("utf-8"))
    generarArchivo(rutaMensajeClaro, bytesDES)

#CIFRADO CON RSA
def cifradoRSA(rutaMensajeClaro, rutaLlavePublica, rutaNuevoMensajeCifrado):
    llavep = leerLlavePublica(rutaLlavePublica)
    bytesOG = txtToBytes(rutaMensajeClaro)
    cipher = PKCS1_OAEP.new(llavep)
    bytesCIF = cipher.encrypt(bytesOG)
    generarArchivo(rutaNuevoMensajeCifrado, bytesCIF)

def descifradoRSA (rutaMensajeCifrado, rutaLlavePrivada, rutaNuevoMensajeClaro):
    llavepriv = leerLlavePrivada(rutaLlavePrivada)
    bytesCIF = txtToBytes(rutaMensajeCifrado)
    descifrado = PKCS1_OAEP.new(llavepriv)
    mensaje = descifrado.decrypt(bytesCIF)
    generarArchivo(rutaNuevoMensajeClaro, mensaje)

'''Todo tiene que ir dentro de un try'''
