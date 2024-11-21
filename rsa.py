# ==============================================================================
# Universidad del Valle de Guatemala
# Departamento de Ciencia y Tecnología
# Curso: Matemática Discreta
# Proyecto: Implementación del algoritmo RSA en Python
# Fecha: [20 de Noviembre de 2024]
# Autores:
# - Ángel Mérida
# - José Auyón
# - André Pivaral
# Descripción:
# Este programa implementa el algoritmo RSA en Python.
# Permite al usuario ingresar un mensaje de texto, encriptarlo y desencriptarlo
# utilizando el algoritmo RSA. Incluye generación de claves, encriptación y
# desencriptación de mensajes basados en caracteres.
# ==============================================================================

import random

# Funciones auxiliares
def es_primo(num):
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def primos_en_rango(lim_inferior, lim_superior):
    return [num for num in range(lim_inferior, lim_superior + 1) if es_primo(num)]

def primo_aleatorio_en_rango(inicio, fin):
    primos = primos_en_rango(inicio, fin)
    if not primos:
        raise ValueError(f"No hay números primos en el rango {inicio} a {fin}")
    return random.choice(primos)

def mcd(a, b):
    while b:
        a, b = b, a % b
    return a

def inverso_modular(e, n):
    t, nuevo_t = 0, 1
    r, nuevo_r = n, e
    while nuevo_r != 0:
        cociente = r // nuevo_r
        t, nuevo_t = nuevo_t, t - cociente * nuevo_t
        r, nuevo_r = nuevo_r, r - cociente * nuevo_r
    if r > 1:
        return None
    if t < 0:
        t += n
    return t

# Generación de claves RSA
def generar_llaves(rango_inferior, rango_superior):
    p = primo_aleatorio_en_rango(rango_inferior, rango_superior)
    q = primo_aleatorio_en_rango(rango_inferior, rango_superior)
    while p == q:
        q = primo_aleatorio_en_rango(rango_inferior, rango_superior)

    n = p * q
    phi = (p - 1) * (q - 1)

    for e in range(2, phi):
        if mcd(e, phi) == 1:
            break

    d = inverso_modular(e, phi)
    return (e, n), (d, n)

# Conversión de texto a números y viceversa
def texto_a_numeros_validado(texto, n):
    numeros = [ord(c) for c in texto]
    for num in numeros:
        if num >= n:
            raise ValueError(f"El carácter '{chr(num)}' (ASCII {num}) no es válido porque excede n = {n}.")
    return numeros

def numeros_a_texto(numeros):
    return ''.join(chr(num) for num in numeros)

# Encriptación y desencriptación
def encriptar_mensaje_validado(mensaje, llave_publica):
    e, n = llave_publica
    mensaje_numeros = texto_a_numeros_validado(mensaje, n)
    return [pow(num, e, n) for num in mensaje_numeros]

def desencriptar_mensaje(mensaje_encriptado, llave_privada):
    d, n = llave_privada
    mensaje_desencriptado = [pow(num, d, n) for num in mensaje_encriptado]
    return numeros_a_texto(mensaje_desencriptado)

# Programa principal
if __name__ == "__main__":
    print("Generando claves RSA...")
    llave_publica, llave_privada = generar_llaves(100, 500)
    print(f"Clave pública: {llave_publica}")
    print(f"Clave privada: {llave_privada}")

    # Solicitar al usuario un mensaje
    while True:
        mensaje_original = input("Introduce el mensaje a encriptar: ")
        try:
            mensaje_encriptado = encriptar_mensaje_validado(mensaje_original, llave_publica)
            break
        except ValueError as e:
            print(f"Error: {e}. Por favor, introduce un mensaje válido.")

    print(f"Mensaje original: {mensaje_original}")
    print(f"Mensaje encriptado (números): {mensaje_encriptado}")

    # Desencriptar el mensaje
    mensaje_desencriptado = desencriptar_mensaje(mensaje_encriptado, llave_privada)
    print(f"Mensaje desencriptado: {mensaje_desencriptado}")

    # Verificar si el mensaje original y el desencriptado coinciden
    if mensaje_original == mensaje_desencriptado:
        print("¡La desencriptación fue exitosa!")
    else:
        print("Hubo un error en la desencriptación.")
