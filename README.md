# Formulario de Criptografia en Java

Proyecto de ejemplo en Java (JDK 8+) con GUI moderna en Swing y dos modulos: cifrado simetrico AES y cifrado asimetrico RSA.

## Requisitos
- JDK 8 o superior

## Compilacion y ejecucion
```powershell
javac -d out src\FormularioCriptografia.java
java -cp out FormularioCriptografia
```

## Notas
- El modulo AES usa GCM y concatena IV + cifrado en Base64 para descifrado.
- El modulo RSA genera par de claves y usa Base64 para mostrar claves y texto cifrado.


