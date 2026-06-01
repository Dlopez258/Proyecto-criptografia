import java.util.Base64;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class TestRSA {
    static final String CIFRADO =
        "QTU89GxL3ZU/eZvx5poSKIGYd/CZHL9nQSeYgMVXylJtzZ0" +
        "gpoSrfdoPIXHoWZ7Oii8bVUfLtxTDflTvllez0A==";

    static final String PRIVADA =
        "MIIBOgIBAAJBAJ5OX38/dexgwx4H7FPgExLLQR/zE4zfOOR7" +
        "UCvXdRkxluGugX3X8Aqxm3sbnDOJmO8/R6We1ANhJwG2Zl5O" +
        "278CAwEAAQJAepjzeBZres5NDTrRmPtVih6Cpv2WzGgrJTcil" +
        "XFcrE6acDZv7JFYG1s0dbv+ODzR/nXaAwLe+/pSVxGEtZJLU" +
        "QlhANrg4afkPHmb1xikm4mUrOvF5f/97EkvlHS9++uygzdDAi" +
        "EAuSealNiZgyPk30xyB9h1Yq+1vjQTaosraMmdiowWC9UCIQC" +
        "TCj4uJuMFo07WDEc9HvcoETOZTQF+jL1WEAd8aNIDtwlgXJwe" +
        "iYy9XAa8F6SY9KukKzRP508M1yG9GLCfiAkBjfECIGyuMIyaK" +
        "gcWx4AvBld7MsMpNqgHMD+TsmlydQUfxUAB";

    public static void main(String[] args) throws Exception {
        byte[] privBytes = Base64.getDecoder().decode(PRIVADA);
        System.out.println("Longitud clave privada (bytes): " + privBytes.length);
        System.out.printf("Primeros bytes DER: %02X %02X %02X %02X %02X%n",
            privBytes[0], privBytes[1], privBytes[2], privBytes[3], privBytes[4]);

        // Intentar PKCS#8 directo
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
            System.out.println("PKCS#8 OK: " + pk.getAlgorithm());
        } catch (Exception e) {
            System.out.println("PKCS#8 fallo: " + e.getMessage());
        }

        // Intentar conversión PKCS#1 -> PKCS#8
        try {
            byte[] pkcs8 = pkcs1ToPkcs8(privBytes);
            System.out.println("PKCS8 convertido longitud: " + pkcs8.length);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            System.out.println("PKCS#1->PKCS#8 OK: " + pk.getAlgorithm());

            // Descifrar
            byte[] cifrado = Base64.getDecoder().decode(CIFRADO);
            System.out.println("Longitud criptograma (bytes): " + cifrado.length);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, pk);
            byte[] plano = cipher.doFinal(cifrado);
            System.out.println("Mensaje: " + new String(plano, "UTF-8"));
        } catch (Exception e) {
            System.out.println("PKCS#1->PKCS#8 fallo: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        byte[] algId = {
            (byte)0x30,(byte)0x0d,(byte)0x06,(byte)0x09,
            (byte)0x2a,(byte)0x86,(byte)0x48,(byte)0x86,
            (byte)0xf7,(byte)0x0d,(byte)0x01,(byte)0x01,(byte)0x01,
            (byte)0x05,(byte)0x00
        };
        byte[] version = {(byte)0x02,(byte)0x01,(byte)0x00};
        byte[] lenPkcs1 = derLen(pkcs1.length);
        byte[] octetStr = new byte[1 + lenPkcs1.length + pkcs1.length];
        octetStr[0] = (byte)0x04;
        System.arraycopy(lenPkcs1, 0, octetStr, 1, lenPkcs1.length);
        System.arraycopy(pkcs1, 0, octetStr, 1 + lenPkcs1.length, pkcs1.length);
        byte[] inner = new byte[version.length + algId.length + octetStr.length];
        System.arraycopy(version,  0, inner, 0, version.length);
        System.arraycopy(algId,    0, inner, version.length, algId.length);
        System.arraycopy(octetStr, 0, inner, version.length + algId.length, octetStr.length);
        byte[] outerLen = derLen(inner.length);
        byte[] result = new byte[1 + outerLen.length + inner.length];
        result[0] = (byte)0x30;
        System.arraycopy(outerLen, 0, result, 1, outerLen.length);
        System.arraycopy(inner, 0, result, 1 + outerLen.length, inner.length);
        return result;
    }

    static byte[] derLen(int n) {
        if (n < 0x80) return new byte[]{(byte)n};
        if (n < 0x100) return new byte[]{(byte)0x81,(byte)n};
        return new byte[]{(byte)0x82,(byte)(n>>8),(byte)(n&0xff)};
    }
}
