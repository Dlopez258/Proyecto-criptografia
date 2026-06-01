# Eje 4 - Criptografia | Fundación Universitaria del Area Andina

## Integrantes

| Nombre | Rol |
|--------|-----|
| Diego Andrés Lopez Rodriguez | Desarrollador |

---

## Descripcion

Aplicación Java con interfaz gráfica moderna en Swing que implementa cuatro módulos de criptografía y análisis:

- **AES-256-GCM (Simétrico):** cifrado autenticado con clave de 256 bits e IV aleatorio de 12 bytes.
- **RSA (Asimétrico):** generación de par de claves de 2048 bits con padding PKCS#1, más descifrado con clave externa (PKCS#8 DER).
- **Cifrados Clásicos:** implementación de César (desplazamiento 1-25) y Vigenère (clave alfabética).
- **Funciones HASH:** cálculo de MD5, SHA-1, SHA-256 y SHA-512 con salida hexadecimal y copia al portapapeles.

Toda la entrada/salida de claves y textos cifrados se representa en **Base64** (módulos AES y RSA) o **hexadecimal** (módulo Hash).

---

## Requisitos

- JDK 8 o superior
- No requiere dependencias externas; usa únicamente la biblioteca estándar de Java (`javax.crypto`, `java.security`, `javax.swing`, `java.awt`)

---

## Estructura del proyecto

```
proyecto-criptografia/
├── src/
│   ├── FormularioCriptografia.java   # Clase principal: UI + lógica criptográfica
│   ├── Main.java                     # Plantilla generada por el IDE (no utilizada)
│   └── resources/
├── out/
│   └── FormularioCriptografia.class  # Clase compilada
└── README.md
```

---

## Compilacion y ejecucion

```powershell
javac -encoding UTF-8 -d out src\FormularioCriptografia.java
java -cp out FormularioCriptografia
```

---

## Modulo AES-256-GCM (Simetrico)

### Parametros técnicos

| Parámetro | Valor |
|-----------|-------|
| Algoritmo | AES |
| Modo | GCM (Galois/Counter Mode) |
| Padding | NoPadding |
| Tamaño de clave | **256 bits** |
| Longitud IV | 12 bytes |
| Tag GCM | 128 bits |

### Flujo de operacion

```
Mensaje en texto plano
        │
        ▼
  Generar clave AES (256 bits, SecureRandom)
  Generar IV aleatorio (12 bytes)
        │
        ▼
  AES/GCM/NoPadding → texto cifrado
        │
        ▼
  Concatenar [IV (12 bytes)] + [cifrado]
        │
        ▼
  Codificar en Base64 → salida en pantalla
```

**Descifrado:** se decodifica el Base64, se extraen los primeros 12 bytes como IV y el resto como texto cifrado; luego se descifra con la clave almacenada.

---

## Modulo RSA (Asimetrico)

### Parametros técnicos

| Parámetro | Valor |
|-----------|-------|
| Algoritmo | RSA |
| Modo | ECB |
| Padding | PKCS1Padding |
| Tamaño de clave | 2048 bits |
| Formato clave privada | PKCS#8 DER en Base64 |

### Subseccion: Descifrado con clave externa

Permite descifrar mensajes RSA generados externamente (ej. ejercicios del docente con clave de 512 bits). Se pega el criptograma en Base64 y la clave privada PKCS#8 DER en Base64; la app reconstruye el `PrivateKey` con `PKCS8EncodedKeySpec` y descifra con `RSA/ECB/PKCS1Padding`.

---

## Modulo Cifrados Clasicos

### Cifrado César

| Parámetro | Valor |
|-----------|-------|
| Tipo | Sustitución monoalfabética |
| Desplazamiento | 1 – 25 (configurable por spinner) |
| Case | Preservado (mayúsculas y minúsculas independientes) |
| Caracteres no alfabéticos | Sin modificar |

### Cifrado Vigenère

| Parámetro | Valor |
|-----------|-------|
| Tipo | Sustitución polialfabética |
| Clave | Solo letras (A-Z / a-z); se rechaza si contiene otros caracteres |
| Case | Preservado |
| Avance de clave | Solo al procesar caracteres alfabéticos |
| Caracteres no alfabéticos | Sin modificar |

---

## Modulo Funciones HASH

| Algoritmo | Bits de salida | Uso típico |
|-----------|---------------|------------|
| MD5 | 128 bits | Verificación rápida (no criptográfico) |
| SHA-1 | 160 bits | Legacy, en desuso para seguridad |
| SHA-256 | 256 bits | Estándar moderno |
| SHA-512 | 512 bits | Alta seguridad |

- Salida en hexadecimal (minúsculas).
- Botón **Copiar** copia el hash al portapapeles del sistema (`Toolkit.getDefaultToolkit().getSystemClipboard()`).
- Implementado con `MessageDigest.getInstance(algoritmo)`, sin dependencias externas.

---

## Notas tecnicas

- **AES/GCM** proporciona cifrado autenticado (confidencialidad + integridad) sin necesidad de un MAC separado.
- El IV se genera con `SecureRandom` en cada operación de cifrado para garantizar que nunca se reutilice con la misma clave.
- **RSA/ECB/PKCS1Padding** cifra bloque a bloque; para mensajes largos en producción se recomienda cifrado híbrido (RSA cifra la clave AES).
- **César y Vigenère** son cifrados históricos incluidos con fines académicos; no ofrecen seguridad real.
- La interfaz detecta la fuente **Roboto** si está instalada en el sistema; de lo contrario usa **SansSerif** como alternativa.
- Fecha de entrega: **1 de junio de 2026**
