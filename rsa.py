
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


def mcd(a, b):
    """
    Calcula el máximo común divisor (MCD) de dos números enteros utilizando el algoritmo de Euclides.

    Parámetros:
    a (int): El primer número entero.
    b (int): El segundo número entero.

    Regresa:
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


def inverso_modular(e, n):
    """
    Calcula el inverso modular de 'e' módulo 'n' utilizando el algoritmo extendido de Euclides.

    Parámetros:
    e (int): Número entero cuyo inverso modular se busca.
    n (int): Módulo de la operación.

    Regresa:
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


def primo_aleatorio_en_rango(inicio, fin):
    """
    Selecciona un número primo aleatorio dentro de un rango especificado.

    Parámetros:
    inicio (int): El límite inferior del rango.
    fin (int): El límite superior del rango.

    Regresa:
    int: Un número primo seleccionado aleatoriamente dentro del rango.

    Lanza:
    ValueError: Si no hay números primos en el rango especificado.
    """
    primos = primos_en_rango(
        inicio, fin)  # Obtenemos una lista de números primos en el rango
    if not primos:
        raise ValueError(f"No hay números primos en el rango {inicio} a {fin}")
    return random.choice(primos)  # Seleccionamos y retornamos un primo al azar


def primos_en_rango(lim_inferior, lim_superior):
    """
    Genera una lista de números primos dentro de un rango dado.

    Parámetros:
    inicio (int): Límite inferior del rango.
    fin (int): Límite superior del rango.

    Retorna:
    list: Lista de números primos dentro del rango [inicio, fin].
    """
    primos = []
    for num in range(lim_inferior, lim_superior + 1):
        if es_primo(num):
            primos.append(num)
    return primos


def es_primo(num):
    """
    Determina si un número es primo.

    Parámetros:
    num (int): El número a verificar.

    Retorna:
    bool: True si el número es primo, False de lo contrario.
    """
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True


def generar_llaves(rango_inferior, rango_superior):
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
    p = primo_aleatorio_en_rango(
        rango_inferior, rango_superior)  # Seleccionamos el primer número primo 'p'
    # Seleccionamos el segundo número primo 'q'
    q = primo_aleatorio_en_rango(rango_inferior, rango_superior)
    count = 0
    while q == p:  # Aseguramos que 'p' y 'q' sean diferentes
        if count > 100:
            raise ValueError(
                "No se puede encontrar dos números primos diferentes")
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
    # Calculamos el inverso modular de 'e' módulo 'phi'
    d = inverso_modular(e, phi)
    return (e, n), (d, n)  # Retornamos la clave pública y la clave privada


def encriptar(caracter, llave_publica):
    """
    Encripta un caracter usando la llave pública de RSA.

    Parámetros:
    caracter (int): El número entero que representa el carácter a encriptar.
    llave_publica (tuple): La llave pública (e, n).

    Retorna:
    int: El caracter encriptado.
    """
    e, n = llave_publica  # Extraemos la clave pública (e, n)

    # Validamos que el carácter sea menor que 'n'
    if caracter < 0 or caracter >= n:
        raise ValueError(f"El caracter debe ser un número menor que {n}.")

    # Encriptar el carácter usando la fórmula: C = M^e % n
    caracter_encriptado = pow(caracter, e, n)  # Encriptación rápida usando pow
    return caracter_encriptado  # Retornamos el carácter encriptado


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
        raise ValueError(
            "El caracter encriptado debe ser un número positivo y menor que n.")

    # Desencriptar el carácter usando la fórmula: M = C^d % n
    # Desencriptación rápida usando pow
    caracter_original = pow(caracter_encriptado, d, n)
    return caracter_original  # Retornamos el caracter original desencriptado


if __name__ == "__main__":
    # Generamos las claves pública y privada para el rango de 10 a 100
    try:
        print("Generando claves RSA...")
        llave_publica, llave_privada = generar_llaves(10, 100)
        print(f"Clave pública: {llave_publica}")
        print(f"Clave privada: {llave_privada}")

        # Obtener el valor n de la clave pública para establecer el rango
        n = llave_publica[1]

        # Solicitar al usuario que ingrese el mensaje original
        while True:
            mensaje_original_str = input(
                f"Introduce el mensaje original (un número entero entre 0 y {n-1}): ")

            try:
                # Convertir el mensaje a entero
                mensaje_original = int(mensaje_original_str)
                print(f"Mensaje original: {mensaje_original}")

                # Comprobar si el mensaje está dentro del rango válido
                if 0 <= mensaje_original < n:
                    break  # Salir del bucle si el mensaje es válido
                else:
                    print(f"Error: El mensaje debe ser un número entre 0 y {
                          n-1}. Intenta de nuevo.")
            except ValueError:
                print("Error: El mensaje debe ser un número entero válido.")

        # Encriptamos el mensaje
        mensaje_encriptado = encriptar(mensaje_original, llave_publica)
        print(f"Mensaje encriptado: {mensaje_encriptado}")

        # Desencriptamos el mensaje
        mensaje_desencriptado = desencriptar(mensaje_encriptado, llave_privada)
        print(f"Mensaje desencriptado: {mensaje_desencriptado}")

        # Verificar si el mensaje original y el desencriptado coinciden
        if mensaje_original == mensaje_desencriptado:
            print("¡La desencriptación fue exitosa!")
        else:
            print("Hubo un error en la desencriptación.")

    except ValueError as e:
        print(f"Error: {e}")
