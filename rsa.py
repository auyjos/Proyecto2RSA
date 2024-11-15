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
import random


def mcd(a,b):
    if b > a:
        a,b = b,a
    if b == 0:  
        return a
    res = a % b
    while res > 0:
        a,b = b,res
        res = a % b
    return b


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


def mcd(a, b):
    """
    Calcula el máximo común divisor (MCD) de dos números enteros utilizando el algoritmo de Euclides.

    Parámetros:
    a (int): El primer número entero.
    b (int): El segundo número entero.

    Retorna:
    int: El máximo común divisor de 'a' y 'b'.
    """
    if b > a:
        a, b = b, a  # Aseguramos que 'a' sea mayor o igual que 'b'
    if b == 0:
        return a  # Si 'b' es cero, el MCD es 'a'
    res = a % b  # Calculamos el residuo de 'a' dividido entre 'b'
    while res > 0:
        a, b = b, res  # Actualizamos 'a' y 'b' para la siguiente iteración
        res = a % b  # Calculamos el nuevo residuo
    return b  # Retornamos el MCD cuando el residuo es cero


def primo_aleatorio_en_rango(inicio, fin):
    """
    Selecciona un número primo aleatorio dentro de un rango especificado.

    Parámetros:
    inicio (int): El límite inferior del rango.
    fin (int): El límite superior del rango.

    Retorna:
    int: Un número primo seleccionado aleatoriamente dentro del rango.

    Lanza:
    ValueError: Si no hay números primos en el rango especificado.
    """
    primos = primos_en_rango(inicio, fin)  # Obtenemos una lista de números primos en el rango
    if not primos:
        raise ValueError(f"No hay números primos en el rango {inicio} a {fin}")
    return random.choice(primos)  # Seleccionamos y retornamos un primo al azar


def generar_keys(rango_inferior, rango_superior):
    """
    Genera un par de claves pública y privada para el cifrado RSA.

    Parámetros:
    rango_inferior (int): Límite inferior para la generación de números primos.
    rango_superior (int): Límite superior para la generación de números primos.

    Retorna:
    tuple: Una tupla que contiene la clave pública (e, n) y la clave privada (d, n).

    Lanza:
    ValueError: Si no es posible encontrar dos números primos diferentes en el rango especificado.
    """
    p = primo_aleatorio_en_rango(rango_inferior, rango_superior)  # Seleccionamos el primer número primo 'p'
    q = primo_aleatorio_en_rango(rango_inferior, rango_superior)  # Seleccionamos el segundo número primo 'q'
    count = 0
    while q == p:  # Aseguramos que 'p' y 'q' sean diferentes
        if count > 100:
            raise ValueError("No se puede encontrar dos números primos diferentes")
        q = primo_aleatorio_en_rango(rango_inferior, rango_superior)
        count += 1
    n = p * q  # Calculamos 'n' como el producto de 'p' y 'q'
    phi = (p - 1) * (q - 1)  # Calculamos la función totiente de Euler 'phi'

    e = 0
    # Buscamos un 'e' tal que el MCD de 'e' y 'phi' sea 1
    for i in range(6, phi - 1):
        maximo = mcd(i, phi)
        if maximo == 1:
            e = i  # Encontramos un 'e' que cumple con la condición
            break
    d = inverso_modular(e, phi)  # Calculamos el inverso modular de 'e' módulo 'phi'
    return (e, n), (d, n)  # Retornamos la clave pública y la clave privada
