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
# Este programa implementa el algoritmo de encriptación RSA en Python. 
# RSA es un sistema de cifrado de clave pública que permite encriptar y 
# desencriptar mensajes de forma segura. La implementación incluye funciones 
# para generar claves públicas y privadas, encriptar un mensaje y desencriptarlo 
# utilizando estas claves. Se divide en varias funciones clave, que incluyen:
# generación de números primos, cálculo del máximo común divisor, inverso modular, 
# y funciones de encriptación y desencriptación.
# ==============================================================================


def inverso_modular(e, n):
    """
    Calcula el inverso modular de 'e' módulo 'n' utilizando el algoritmo extendido de Euclides.
    
    Parámetros:
    e (int): Número entero cuyo inverso modular se busca.
    n (int): Módulo de la operación.

    Retorna:
    int: El inverso modular de 'e' módulo 'n', o None si no existe.
    """
    t, nuevo_t = 0, 1   # Inicializamos t y nuevo_t para realizar la conversión al módulo
    r, nuevo_r = n, e   # Inicializamos r y nuevo_r con los valores de n y e

    # Algoritmo de Euclides Extendido
    while nuevo_r != 0:  # Mientras el residuo actual sea distinto de 0
        cociente = r // nuevo_r  # Calculamos el cociente de r / nuevo_r
        t, nuevo_t = nuevo_t, t - cociente * nuevo_t  # Actualizamos t y nuevo_t
        r, nuevo_r = nuevo_r, r - cociente * nuevo_r  # Actualizamos r y nuevo_r

    # Si el último residuo es mayor que 1, no hay inverso modular (r y n no son coprimos)
    if r > 1:
        return None  # Retornamos None si no existe el inverso

    # Asegurarse de que el resultado es positivo
    if t < 0:
        t += n  # Aseguramos que t sea positivo añadiendo n si es necesario
    
    return t  # Retornamos el inverso modular de e módulo n



def desencriptar(caracter_encriptado, llave_privada):
    """
    Desencripta un caracter encriptado usando la llave privada de RSA.
    
    Parámetros:
    caracter_encriptado (int): El caracter encriptado que se desea desencriptar.
    llave_privada (tuple): La llave privada en forma de tupla (d, n).
    
    Retorna:
    int: El caracter original M.
    """
    d, n = llave_privada  # Extraemos el exponente privado d y el valor n de la clave privada
    
    # Validamos que el carácter encriptado sea positivo y menor que n
    if caracter_encriptado < 0 or caracter_encriptado >= n:
        raise ValueError("El caracter encriptado debe ser un número positivo y menor que n.")

    # Desencriptar el carácter usando la fórmula: M = C^d % n
    caracter_original = pow(caracter_encriptado, d, n)  # Desencriptación rápida usando pow
    return caracter_original  # Retornamos el caracter original desencriptado

