import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.Arrays;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

public class FormularioCriptografia {
    // Paleta de colores (tokens de diseno)
    private static final Color COLOR_PRIMARY = new Color(0x67B31F);
    private static final Color COLOR_PRIMARY_DARK = new Color(0x5A9E1B);
    private static final Color COLOR_PRIMARY_LIGHT = new Color(0x7CC934);
    private static final Color COLOR_WHITE = new Color(0xFFFFFF);
    private static final Color COLOR_GRAY_LIGHT = new Color(0xF8F9FA);
    private static final Color COLOR_GRAY_MID = new Color(0x6C757D);
    private static final Color COLOR_GRAY_BORDER = new Color(0xE2E8F0);
    private static final Color COLOR_SEPARATOR = new Color(0xDDE3EA);
    private static final Color COLOR_TEXT_MAIN = new Color(0x1A1A1A);
    private static final Color COLOR_TEXT_SOFT = new Color(0x444444);

    private static final int AES_KEY_SIZE = 256; // bits
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int GCM_IV_LENGTH = 12; // bytes

    private final Font fontLabel;
    private final Font fontField;
    private final Font fontTitle;

    // Campos del modulo AES
    private JTextArea aesMensajeArea;
    private JTextArea aesClaveArea;
    private JTextArea aesCifradoArea;
    private JTextArea aesDescifradoArea;

    // Campos del modulo RSA (generacion interna)
    private JTextArea rsaMensajeArea;
    private JTextArea rsaPublicaArea;
    private JTextArea rsaPrivadaArea;
    private JTextArea rsaCifradoArea;
    private JTextArea rsaDescifradoArea;

    // Campos del modulo RSA con clave externa
    private JTextArea rsaExtCifradoArea;
    private JTextArea rsaExtPrivadaArea;
    private JTextArea rsaExtDescifradoArea;

    // Campos del modulo Cifrados Clasicos - Cesar
    private JTextArea cesarMensajeArea;
    private JSpinner cesarDesplazamientoSpinner;
    private JTextArea cesarResultadoArea;

    // Campos del modulo Cifrados Clasicos - Vigenere
    private JTextArea vigenereMensajeArea;
    private JTextField vigenereClaveField;
    private JTextArea vigenereResultadoArea;

    // Campos del modulo Hash
    private JTextArea hashMensajeArea;
    private JTextArea hashResultadoArea;

    // Campos del modulo Retos del Eje
    private JTextArea retoRsaCifradoArea;
    private JTextArea retoRsaPrivadaArea;
    private JTextArea retoRsaDescifradoArea;
    private JTextArea retoCesarMensajeArea;
    private JTextArea retoCesarResultadoArea;
    private JTextArea retoVigenereMensajeArea;
    private JTextArea retoVigenereResultadoArea;

    // Datos del reto (limpiados de errores OCR)
    private static final String RETO_RSA_CIFRADO =
        "QTU89GxL3ZU/eZvx5poSKIGYd/CZHL9nQSeYgMVXylJtzZ0" +
        "gpoSrfdoPIXHoWZ7Oii8bVUfLtxTDflTvllez0A==";

    private static final String RETO_RSA_PRIVADA =
        "MIIBOgIBAAJBAJ5OX38/dexgwx4H7FPgExLLQR/zE4zfOOR7" +
        "UCvXdRkxluGugX3X8Aqxm3sbnDOJmO8/R6We1ANhJwG2Zl5O" +
        "278CAwEAAQJAepjzeBZres5NDTrRmPtVih6Cpv2WzGgrJTcil" +
        "XFcrE6acDZv7JFYG1s0dbv+ODzR/nXaAwLe+/pSVxGEtZJLU" +
        "QIhANrg4afkPHmb1xikm4mUrOvF5f/97EkvlHS9++uygzdDAi" +
        "EAuSealNiZgyPk30xyB9h1Yq+1vjQTaosraMmdiowWC9UCIQC" +
        "TCj4uJuMFo07WDEc9HvcoETOZTQF+jL1WEAd8aNIDtwIgXJwe" +
        "iYy9XAa8F6SY9KukKzRP508M1yG9GLCfiAkBjfECIGyuMIyaK" +
        "gcWx4AvBld7MsMpNqgHMD+TsmlydQUfxUAB";

    private static final String RETO_CESAR_TEXTO =
        "Jxyj jx zs yjcyt ij qf rfyjwnf xjlzwnifi ij qf nsktwrfhnts. " +
        "Qt afrtx f hnkwfw hts itx fqltwnyrtx inxynsytx, d afrtx f ajw " +
        "htrt xj inkjwjshnfs frgtx wjxzqyfitx.";

    private static final String RETO_VIGENERE_TEXTO =
        "Wwzm rx mr zmkyg hk tn rsxkzvf kimcenvej Ir qs mtnbweeiqbs. " +
        "Ds biztk e iqswsv iwa igw gtttjmzubx vmybvslsy, g ifesy i ijj " +
        "guub xw honrwwriqns sqhwf wwwatgfvsy";

    private static final String RETO_VIGENERE_CLAVE = "SEGINF";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new FormularioCriptografia().mostrar());
    }

    public FormularioCriptografia() {
        this.fontLabel = resolverFuente(13, Font.PLAIN);
        this.fontField = resolverFuente(13, Font.PLAIN);
        this.fontTitle = resolverFuente(18, Font.BOLD);
    }

    private void mostrar() {
        JFrame frame = new JFrame(
            "Eje 4 - Criptografía - Fundación Universitaria del Área Andina");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setBackground(COLOR_GRAY_LIGHT);
        frame.setLayout(new BorderLayout());

        JPanel card = new JPanel();
        card.setBackground(COLOR_WHITE);
        card.setBorder(new EmptyBorder(24, 28, 24, 28));
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel titulo = new JLabel(
            "Eje 4 - Criptografía - Fundación Universitaria del Área Andina");
        titulo.setFont(fontTitle);
        titulo.setForeground(COLOR_TEXT_MAIN);
        titulo.setAlignmentX(JLabel.CENTER_ALIGNMENT);

        card.add(titulo);
        card.add(Box.createVerticalStrut(16));
        card.add(crearPestanas());
        card.add(Box.createVerticalStrut(16));
        card.add(crearFooter());

        JPanel contenedor = new JPanel(new BorderLayout());
        contenedor.setBackground(COLOR_GRAY_LIGHT);
        contenedor.setBorder(new EmptyBorder(20, 20, 20, 20));
        contenedor.add(card, BorderLayout.CENTER);

        frame.add(contenedor, BorderLayout.CENTER);
        frame.setMinimumSize(new Dimension(900, 700));
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private JTabbedPane crearPestanas() {
        JTabbedPane pestanas = new JTabbedPane();
        pestanas.setFont(fontLabel);
        pestanas.setBackground(COLOR_GRAY_LIGHT);
        pestanas.setForeground(COLOR_TEXT_MAIN);
        pestanas.addTab("AES-256-GCM", envolverScroll(crearPanelAES()));
        pestanas.addTab("RSA (Asimétrico)", envolverScroll(crearPanelRSA()));
        pestanas.addTab("Cifrados Clásicos", envolverScroll(crearPanelCifradosClasicos()));
        pestanas.addTab("Funciones HASH", envolverScroll(crearPanelHash()));
        pestanas.addTab("Retos del Eje", envolverScroll(crearPanelRetos()));
        return pestanas;
    }

    private JScrollPane envolverScroll(JPanel panel) {
        JScrollPane scroll = new JScrollPane(panel);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    // -------------------------------------------------------------------------
    // Panel AES-256-GCM
    // -------------------------------------------------------------------------

    private JPanel crearPanelAES() {
        JPanel panel = new JPanel();
        panel.setBackground(COLOR_WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel titulo = new JLabel(
            "Módulo de Cifrado Simétrico (AES-256-GCM)");
        titulo.setFont(fontTitle);
        titulo.setForeground(COLOR_TEXT_MAIN);
        titulo.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        aesMensajeArea = crearAreaEditable(3);
        aesClaveArea = crearAreaSoloLectura(2);
        aesCifradoArea = crearAreaSoloLectura(3);
        aesDescifradoArea = crearAreaSoloLectura(2);

        JButton botonCifrar = crearBotonPrincipal("Generar clave y cifrar", e -> cifrarAES());
        JButton botonDescifrar = crearBotonPrincipal("Descifrar", e -> descifrarAES());

        panel.add(titulo);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Mensaje en claro"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(aesMensajeArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonCifrar);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Clave secreta (Base64)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(aesClaveArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Texto cifrado (Base64)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(aesCifradoArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonDescifrar);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Texto descifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(aesDescifradoArea));

        return panel;
    }

    // -------------------------------------------------------------------------
    // Panel RSA
    // -------------------------------------------------------------------------

    private JPanel crearPanelRSA() {
        JPanel panel = new JPanel();
        panel.setBackground(COLOR_WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel titulo = new JLabel(
            "Módulo de Cifrado Asimétrico (RSA-2048)");
        titulo.setFont(fontTitle);
        titulo.setForeground(COLOR_TEXT_MAIN);
        titulo.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        rsaMensajeArea = crearAreaEditable(3);
        rsaPublicaArea = crearAreaSoloLectura(3);
        rsaPrivadaArea = crearAreaSoloLectura(3);
        rsaCifradoArea = crearAreaSoloLectura(3);
        rsaDescifradoArea = crearAreaSoloLectura(2);

        JButton botonCifrar = crearBotonPrincipal(
            "Generar par de claves y cifrar", e -> cifrarRSA());
        JButton botonDescifrar = crearBotonPrincipal("Descifrar", e -> descifrarRSA());

        panel.add(titulo);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Mensaje en claro"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaMensajeArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonCifrar);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Clave pública (Base64)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaPublicaArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Clave privada (Base64)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaPrivadaArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Texto cifrado (Base64)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaCifradoArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonDescifrar);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Texto descifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaDescifradoArea));

        // Seccion: Descifrado con clave externa
        panel.add(Box.createVerticalStrut(24));
        panel.add(crearSeparador());
        panel.add(Box.createVerticalStrut(16));

        JLabel tituloExt = new JLabel("Descifrado con clave externa");
        tituloExt.setFont(resolverFuente(15, Font.BOLD));
        tituloExt.setForeground(COLOR_TEXT_MAIN);
        tituloExt.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        rsaExtCifradoArea = crearAreaEditable(3);
        rsaExtPrivadaArea = crearAreaEditable(3);
        rsaExtDescifradoArea = crearAreaSoloLectura(2);

        JButton botonDescifrarExt = crearBotonPrincipal("Descifrar", e -> descifrarRSAExterno());

        panel.add(tituloExt);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Texto cifrado en Base64"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaExtCifradoArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Clave privada en Base64 (PKCS#8 DER)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaExtPrivadaArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonDescifrarExt);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Mensaje descifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaExtDescifradoArea));

        return panel;
    }

    // -------------------------------------------------------------------------
    // Panel Cifrados Clasicos
    // -------------------------------------------------------------------------

    private JPanel crearPanelCifradosClasicos() {
        JPanel panel = new JPanel();
        panel.setBackground(COLOR_WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel titulo = new JLabel("Cifrados Clásicos");
        titulo.setFont(fontTitle);
        titulo.setForeground(COLOR_TEXT_MAIN);
        titulo.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        panel.add(titulo);
        panel.add(Box.createVerticalStrut(16));

        // ---- Seccion Cesar ----
        JLabel tituloCesar = new JLabel("Cifrado César");
        tituloCesar.setFont(resolverFuente(15, Font.BOLD));
        tituloCesar.setForeground(COLOR_TEXT_MAIN);
        tituloCesar.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        cesarMensajeArea = crearAreaEditable(3);
        cesarResultadoArea = crearAreaSoloLectura(2);
        cesarDesplazamientoSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 25, 1));
        cesarDesplazamientoSpinner.setFont(fontField);
        cesarDesplazamientoSpinner.setMaximumSize(new Dimension(70, 32));

        JLabel spinnerLabel = new JLabel("Desplazamiento (1-25):");
        spinnerLabel.setFont(fontLabel);
        spinnerLabel.setForeground(COLOR_GRAY_MID);

        JPanel spinnerRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        spinnerRow.setBackground(COLOR_WHITE);
        spinnerRow.setAlignmentX(JPanel.LEFT_ALIGNMENT);
        spinnerRow.add(spinnerLabel);
        spinnerRow.add(cesarDesplazamientoSpinner);

        JButton cesarCifrar = crearBotonPrincipal("Cifrar", e -> procesarCesar(true));
        JButton cesarDescifrar = crearBotonPrincipal("Descifrar", e -> procesarCesar(false));

        panel.add(tituloCesar);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Mensaje"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(cesarMensajeArea));
        panel.add(Box.createVerticalStrut(8));
        panel.add(spinnerRow);
        panel.add(Box.createVerticalStrut(8));
        panel.add(crearPanelBotones(cesarCifrar, cesarDescifrar));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Resultado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(cesarResultadoArea));

        // ---- Separador ----
        panel.add(Box.createVerticalStrut(24));
        panel.add(crearSeparador());
        panel.add(Box.createVerticalStrut(16));

        // ---- Seccion Vigenere ----
        JLabel tituloVigenere = new JLabel("Cifrado Vigenère");
        tituloVigenere.setFont(resolverFuente(15, Font.BOLD));
        tituloVigenere.setForeground(COLOR_TEXT_MAIN);
        tituloVigenere.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        vigenereMensajeArea = crearAreaEditable(3);
        vigenereClaveField = crearCampoTexto();
        vigenereResultadoArea = crearAreaSoloLectura(2);

        JButton vigenereCifrar = crearBotonPrincipal("Cifrar", e -> procesarVigenere(true));
        JButton vigenereDescifrar = crearBotonPrincipal("Descifrar", e -> procesarVigenere(false));

        panel.add(tituloVigenere);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Mensaje"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(vigenereMensajeArea));
        panel.add(Box.createVerticalStrut(8));
        panel.add(crearEtiqueta("Clave (solo letras)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(vigenereClaveField);
        panel.add(Box.createVerticalStrut(8));
        panel.add(crearPanelBotones(vigenereCifrar, vigenereDescifrar));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Resultado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(vigenereResultadoArea));

        return panel;
    }

    // -------------------------------------------------------------------------
    // Panel Funciones HASH
    // -------------------------------------------------------------------------

    private JPanel crearPanelHash() {
        JPanel panel = new JPanel();
        panel.setBackground(COLOR_WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel titulo = new JLabel("Funciones HASH");
        titulo.setFont(fontTitle);
        titulo.setForeground(COLOR_TEXT_MAIN);
        titulo.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        hashMensajeArea = crearAreaEditable(3);
        hashResultadoArea = crearAreaSoloLectura(3);

        JLabel infoLabel = new JLabel(
            "MD5: 128 bits  •  SHA-1: 160 bits  •  "
            + "SHA-256: 256 bits  •  SHA-512: 512 bits");
        infoLabel.setFont(resolverFuente(12, Font.PLAIN));
        infoLabel.setForeground(COLOR_GRAY_MID);
        infoLabel.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        JButton botonMD5    = crearBotonPrincipal("MD5",     e -> calcularHash("MD5"));
        JButton botonSHA1   = crearBotonPrincipal("SHA-1",   e -> calcularHash("SHA-1"));
        JButton botonSHA256 = crearBotonPrincipal("SHA-256", e -> calcularHash("SHA-256"));
        JButton botonSHA512 = crearBotonPrincipal("SHA-512", e -> calcularHash("SHA-512"));
        JButton botonCopiar = crearBotonPrincipal("Copiar",  e -> copiarHash());

        panel.add(titulo);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Mensaje de entrada"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(hashMensajeArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(infoLabel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearPanelBotones(botonMD5, botonSHA1, botonSHA256, botonSHA512));
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Hash resultante (hexadecimal)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(hashResultadoArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearPanelBotones(botonCopiar));

        return panel;
    }

    // -------------------------------------------------------------------------
    // Panel Retos del Eje
    // -------------------------------------------------------------------------

    private JPanel crearPanelRetos() {
        JPanel panel = new JPanel();
        panel.setBackground(COLOR_WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel titulo = new JLabel("Retos del Eje — Descifrado de Mensajes");
        titulo.setFont(fontTitle);
        titulo.setForeground(COLOR_TEXT_MAIN);
        titulo.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        panel.add(titulo);
        panel.add(Box.createVerticalStrut(8));

        JLabel descripcion = new JLabel(
            "<html>Esta pestaña contiene los criptogramas del ejercicio " +
            "precargados con sus claves. Pulse el botón para descifrar cada uno.</html>");
        descripcion.setFont(resolverFuente(12, Font.PLAIN));
        descripcion.setForeground(COLOR_GRAY_MID);
        descripcion.setAlignmentX(JLabel.LEFT_ALIGNMENT);
        panel.add(descripcion);
        panel.add(Box.createVerticalStrut(20));

        // ---- Reto 1: RSA ----
        JLabel tituloRSA = new JLabel("Reto 1 — Criptograma RSA (512 bits, PKCS#1)");
        tituloRSA.setFont(resolverFuente(15, Font.BOLD));
        tituloRSA.setForeground(COLOR_TEXT_MAIN);
        tituloRSA.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        retoRsaCifradoArea = crearAreaEditable(2);
        retoRsaCifradoArea.setText(RETO_RSA_CIFRADO);

        retoRsaPrivadaArea = crearAreaEditable(5);
        retoRsaPrivadaArea.setText(RETO_RSA_PRIVADA);

        retoRsaDescifradoArea = crearAreaSoloLectura(2);

        JButton botonDescifrarRSA = crearBotonPrincipal(
            "Descifrar mensaje RSA", e -> descifrarRetoRSA());

        panel.add(tituloRSA);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Texto cifrado (Base64)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(retoRsaCifradoArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Clave privada PKCS#1 o PKCS#8 (Base64)"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(retoRsaPrivadaArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonDescifrarRSA);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Mensaje descifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(retoRsaDescifradoArea));

        // ---- Separador ----
        panel.add(Box.createVerticalStrut(24));
        panel.add(crearSeparador());
        panel.add(Box.createVerticalStrut(16));

        // ---- Reto 2: César ----
        JLabel tituloCesar = new JLabel("Reto 2 — Cifrado César (desplazamiento 5)");
        tituloCesar.setFont(resolverFuente(15, Font.BOLD));
        tituloCesar.setForeground(COLOR_TEXT_MAIN);
        tituloCesar.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        retoCesarMensajeArea = crearAreaEditable(3);
        retoCesarMensajeArea.setText(RETO_CESAR_TEXTO);
        retoCesarResultadoArea = crearAreaSoloLectura(3);

        JButton botonDescifrarCesar = crearBotonPrincipal(
            "Descifrar (shift=5)", e -> descifrarRetoCesar());

        panel.add(tituloCesar);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Texto cifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(retoCesarMensajeArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonDescifrarCesar);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Mensaje descifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(retoCesarResultadoArea));

        // ---- Separador ----
        panel.add(Box.createVerticalStrut(24));
        panel.add(crearSeparador());
        panel.add(Box.createVerticalStrut(16));

        // ---- Reto 3: Vigenère ----
        JLabel tituloVigenere = new JLabel(
            "Reto 3 — Cifrado Vigenère (clave: " + RETO_VIGENERE_CLAVE + ")");
        tituloVigenere.setFont(resolverFuente(15, Font.BOLD));
        tituloVigenere.setForeground(COLOR_TEXT_MAIN);
        tituloVigenere.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        retoVigenereMensajeArea = crearAreaEditable(3);
        retoVigenereMensajeArea.setText(RETO_VIGENERE_TEXTO);
        retoVigenereResultadoArea = crearAreaSoloLectura(3);

        JButton botonDescifrarVigenere = crearBotonPrincipal(
            "Descifrar (clave=" + RETO_VIGENERE_CLAVE + ")",
            e -> descifrarRetoVigenere());

        panel.add(tituloVigenere);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Texto cifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(retoVigenereMensajeArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonDescifrarVigenere);
        panel.add(Box.createVerticalStrut(10));
        panel.add(crearEtiqueta("Mensaje descifrado"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(retoVigenereResultadoArea));

        return panel;
    }

    // -------------------------------------------------------------------------
    // Logica AES
    // -------------------------------------------------------------------------

    private void cifrarAES() {
        String mensaje = aesMensajeArea.getText().trim();
        if (mensaje.isEmpty()) {
            mostrarMensaje("Ingresa un mensaje para cifrar con AES.");
            return;
        }

        try {
            // Genera una clave AES segura y cifra con GCM.
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE, new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();

            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            byte[] cifrado = cipher.doFinal(mensaje.getBytes(StandardCharsets.UTF_8));

            // Se concatena IV + texto cifrado para permitir el descifrado posterior.
            byte[] ivYCifrado = new byte[iv.length + cifrado.length];
            System.arraycopy(iv, 0, ivYCifrado, 0, iv.length);
            System.arraycopy(cifrado, 0, ivYCifrado, iv.length, cifrado.length);

            aesClaveArea.setText(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            aesCifradoArea.setText(Base64.getEncoder().encodeToString(ivYCifrado));
            aesDescifradoArea.setText("");
        } catch (Exception ex) {
            mostrarMensaje("Error criptográfico AES: " + ex.getMessage());
        }
    }

    private void descifrarAES() {
        String claveBase64 = aesClaveArea.getText().trim();
        String cifradoBase64 = aesCifradoArea.getText().trim();

        if (claveBase64.isEmpty() || cifradoBase64.isEmpty()) {
            mostrarMensaje(
                "Se requiere clave y texto cifrado para descifrar AES.");
            return;
        }

        try {
            byte[] claveBytes = Base64.getDecoder().decode(claveBase64);
            byte[] ivYCifrado = Base64.getDecoder().decode(cifradoBase64);

            if (ivYCifrado.length <= GCM_IV_LENGTH) {
                mostrarMensaje(
                    "El texto cifrado AES no contiene un IV válido.");
                return;
            }

            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] cifrado = new byte[ivYCifrado.length - GCM_IV_LENGTH];
            System.arraycopy(ivYCifrado, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(ivYCifrado, GCM_IV_LENGTH, cifrado, 0, cifrado.length);

            SecretKey secretKey = new SecretKeySpec(claveBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] plano = cipher.doFinal(cifrado);
            aesDescifradoArea.setText(new String(plano, StandardCharsets.UTF_8));
        } catch (Exception ex) {
            mostrarMensaje("Error al descifrar AES: " + ex.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Logica RSA
    // -------------------------------------------------------------------------

    private void cifrarRSA() {
        String mensaje = rsaMensajeArea.getText().trim();
        if (mensaje.isEmpty()) {
            mostrarMensaje("Ingresa un mensaje para cifrar con RSA.");
            return;
        }

        try {
            // Genera un par de claves RSA y cifra con la clave publica.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] cifrado = cipher.doFinal(mensaje.getBytes(StandardCharsets.UTF_8));

            rsaPublicaArea.setText(
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            rsaPrivadaArea.setText(
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            rsaCifradoArea.setText(Base64.getEncoder().encodeToString(cifrado));
            rsaDescifradoArea.setText("");
        } catch (Exception ex) {
            mostrarMensaje("Error criptográfico RSA: " + ex.getMessage());
        }
    }

    private void descifrarRSA() {
        String privadaBase64 = rsaPrivadaArea.getText().trim();
        String cifradoBase64 = rsaCifradoArea.getText().trim();

        if (privadaBase64.isEmpty() || cifradoBase64.isEmpty()) {
            mostrarMensaje(
                "Se requiere clave privada y texto cifrado para descifrar RSA.");
            return;
        }

        try {
            byte[] privadaBytes = Base64.getDecoder().decode(privadaBase64);
            byte[] cifradoBytes = Base64.getDecoder().decode(cifradoBase64);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privadaBytes));

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plano = cipher.doFinal(cifradoBytes);
            rsaDescifradoArea.setText(new String(plano, StandardCharsets.UTF_8));
        } catch (Exception ex) {
            mostrarMensaje("Error al descifrar RSA: " + ex.getMessage());
        }
    }

    private void descifrarRSAExterno() {
        String cifradoBase64 = normalizarBase64(rsaExtCifradoArea.getText());
        String privadaBase64 = normalizarBase64(rsaExtPrivadaArea.getText());

        if (cifradoBase64.isEmpty() || privadaBase64.isEmpty()) {
            mostrarMensaje(
                "Se requieren el texto cifrado y la clave privada para descifrar.");
            return;
        }

        try {
            byte[] cifradoBytes = Base64.getDecoder().decode(cifradoBase64);
            byte[] privadaBytes  = Base64.getDecoder().decode(privadaBase64);

            PrivateKey privateKey = cargarClavePrivadaFlexible(privadaBytes);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plano = cipher.doFinal(cifradoBytes);
            rsaExtDescifradoArea.setText(new String(plano, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException ex) {
            mostrarMensaje("Formato Base64 inválido: " + ex.getMessage());
        } catch (java.security.spec.InvalidKeySpecException ex) {
            mostrarMensaje(
                "Clave privada inválida. Se acepta PKCS#1 o PKCS#8 en Base64.");
        } catch (Exception ex) {
            mostrarMensaje("Error al descifrar RSA: " + ex.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Logica Cifrados Clasicos
    // -------------------------------------------------------------------------

    private void procesarCesar(boolean cifrar) {
        String mensaje = cesarMensajeArea.getText();
        if (mensaje.isEmpty()) {
            mostrarMensaje("Ingresa un mensaje para procesar.");
            return;
        }
        int desplazamiento = (Integer) cesarDesplazamientoSpinner.getValue();
        int d = cifrar ? desplazamiento : (26 - desplazamiento) % 26;

        StringBuilder sb = new StringBuilder(mensaje.length());
        for (char c : mensaje.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                sb.append((char) ('A' + (c - 'A' + d) % 26));
            } else if (c >= 'a' && c <= 'z') {
                sb.append((char) ('a' + (c - 'a' + d) % 26));
            } else {
                sb.append(c);
            }
        }
        cesarResultadoArea.setText(sb.toString());
    }

    private void procesarVigenere(boolean cifrar) {
        String mensaje = vigenereMensajeArea.getText();
        String clave   = vigenereClaveField.getText().trim();

        if (mensaje.isEmpty()) {
            mostrarMensaje("Ingresa un mensaje para procesar.");
            return;
        }
        if (clave.isEmpty()) {
            mostrarMensaje("Ingresa una clave para Vigenère.");
            return;
        }
        if (!clave.matches("[a-zA-Z]+")) {
            mostrarMensaje(
                "La clave de Vigenère debe contener solo letras "
                + "(sin espacios ni números).");
            return;
        }

        String claveUpper = clave.toUpperCase();
        StringBuilder sb = new StringBuilder(mensaje.length());
        int j = 0;
        for (char c : mensaje.toCharArray()) {
            if (Character.isLetter(c)) {
                int shift = claveUpper.charAt(j % claveUpper.length()) - 'A';
                if (!cifrar) shift = (26 - shift) % 26;
                if (c >= 'A' && c <= 'Z') {
                    sb.append((char) ('A' + (c - 'A' + shift) % 26));
                } else {
                    sb.append((char) ('a' + (c - 'a' + shift) % 26));
                }
                j++;
            } else {
                sb.append(c);
            }
        }
        vigenereResultadoArea.setText(sb.toString());
    }

    // -------------------------------------------------------------------------
    // Logica Retos del Eje
    // -------------------------------------------------------------------------

    private void descifrarRetoRSA() {
        String cifradoBase64 = normalizarBase64(retoRsaCifradoArea.getText());
        String privadaBase64 = normalizarBase64(retoRsaPrivadaArea.getText());

        if (cifradoBase64.isEmpty() || privadaBase64.isEmpty()) {
            mostrarMensaje("Faltan datos para descifrar el reto RSA.");
            return;
        }

        try {
            byte[] cifradoBytes = Base64.getDecoder().decode(cifradoBase64);
            byte[] privadaBytes  = Base64.getDecoder().decode(privadaBase64);
            PrivateKey privateKey = cargarClavePrivadaFlexible(privadaBytes);

            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] plano = cipher.doFinal(cifradoBytes);
                String resultado = decodificarTextoLegible(plano);
                if (!resultado.isEmpty()) {
                    retoRsaDescifradoArea.setText(resultado);
                    return;
                }
            } catch (Exception ignored) {
                // Intentar un descifrado mas flexible
            }

            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] raw = cipher.doFinal(cifradoBytes);
                byte[] mensaje = extraerPkcs1Mensaje(raw);
                if (mensaje != null) {
                    String resultado = decodificarTextoLegible(mensaje);
                    if (!resultado.isEmpty()) {
                        retoRsaDescifradoArea.setText(resultado);
                        return;
                    }
                }
            } catch (Exception ignored) {
                // Se reporta al final si no hay texto legible
            }

            retoRsaDescifradoArea.setText(
                "No se pudo obtener texto legible. Verifica la clave y el padding.");
        } catch (IllegalArgumentException ex) {
            mostrarMensaje("Base64 inválido: " + ex.getMessage());
        } catch (Exception ex) {
            mostrarMensaje("Error RSA: " + ex.getMessage());
        }
    }

    private void descifrarRetoCesar() {
        String mensaje = retoCesarMensajeArea.getText();
        if (mensaje.isEmpty()) return;
        int d = (26 - 5) % 26; // desplazamiento inverso de 5
        StringBuilder sb = new StringBuilder(mensaje.length());
        for (char c : mensaje.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                sb.append((char) ('A' + (c - 'A' + d) % 26));
            } else if (c >= 'a' && c <= 'z') {
                sb.append((char) ('a' + (c - 'a' + d) % 26));
            } else {
                sb.append(c);
            }
        }
        retoCesarResultadoArea.setText(sb.toString());
    }

    private void descifrarRetoVigenere() {
        String mensaje = retoVigenereMensajeArea.getText();
        if (mensaje.isEmpty()) return;
        String claveUpper = RETO_VIGENERE_CLAVE.toUpperCase();
        StringBuilder sb = new StringBuilder(mensaje.length());
        int j = 0;
        for (char c : mensaje.toCharArray()) {
            if (Character.isLetter(c)) {
                int shift = (26 - (claveUpper.charAt(j % claveUpper.length()) - 'A')) % 26;
                if (c >= 'A' && c <= 'Z') {
                    sb.append((char) ('A' + (c - 'A' + shift) % 26));
                } else {
                    sb.append((char) ('a' + (c - 'a' + shift) % 26));
                }
                j++;
            } else {
                sb.append(c);
            }
        }
        retoVigenereResultadoArea.setText(sb.toString());
    }

    // Carga una clave RSA privada en formato PKCS#1 o PKCS#8.
    private PrivateKey cargarClavePrivadaFlexible(byte[] keyBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        // Intentar PKCS#8 primero
        try {
            return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception ignored) {
            // Asumir PKCS#1 y envolver en PKCS#8
        }
        try {
            byte[] pkcs8 = pkcs1ToPkcs8(keyBytes);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (Exception ignored) {
            // Intentar recuperacion basica con modulo + exponente privado
        }
        return cargarClavePrivadaBasicaPkcs1(keyBytes);
    }

    // Convierte un DER RSAPrivateKey (PKCS#1) a PrivateKeyInfo (PKCS#8).
    private byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        // AlgorithmIdentifier SEQUENCE { OID rsaEncryption, NULL }
        byte[] algId = {
            (byte)0x30, (byte)0x0d,
            (byte)0x06, (byte)0x09,
            (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86,
            (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01,
            (byte)0x05, (byte)0x00
        };
        byte[] version = {(byte)0x02, (byte)0x01, (byte)0x00};

        // OCTET STRING wrapping pkcs1
        byte[] lenPkcs1 = derLength(pkcs1.length);
        byte[] octetStr = new byte[1 + lenPkcs1.length + pkcs1.length];
        octetStr[0] = (byte)0x04;
        System.arraycopy(lenPkcs1, 0, octetStr, 1, lenPkcs1.length);
        System.arraycopy(pkcs1, 0, octetStr, 1 + lenPkcs1.length, pkcs1.length);

        // PrivateKeyInfo inner = version + algId + octetStr
        byte[] inner = new byte[version.length + algId.length + octetStr.length];
        System.arraycopy(version,   0, inner, 0,                        version.length);
        System.arraycopy(algId,     0, inner, version.length,           algId.length);
        System.arraycopy(octetStr,  0, inner, version.length + algId.length, octetStr.length);

        // Outer SEQUENCE
        byte[] outerLen = derLength(inner.length);
        byte[] result = new byte[1 + outerLen.length + inner.length];
        result[0] = (byte)0x30;
        System.arraycopy(outerLen, 0, result, 1,                result.length - 1 - inner.length);
        System.arraycopy(inner,    0, result, 1 + outerLen.length, inner.length);
        return result;
    }

    private byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[]{(byte)length};
        } else if (length < 0x100) {
            return new byte[]{(byte)0x81, (byte)length};
        } else {
            return new byte[]{(byte)0x82, (byte)(length >> 8), (byte)(length & 0xff)};
        }
    }

    private PrivateKey cargarClavePrivadaBasicaPkcs1(byte[] pkcs1) throws Exception {
        int offset = 0;
        if (pkcs1.length < 1 || pkcs1[offset] != 0x30) {
            throw new IllegalArgumentException("Clave PKCS#1 invalida.");
        }
        offset++;
        int[] lenBytes = new int[1];
        int seqLen = leerLongitudDer(pkcs1, offset, lenBytes);
        offset += lenBytes[0];
        int seqEnd = offset + seqLen;

        int[] pos = new int[]{offset};
        leerEnteroDer(pkcs1, pos); // version
        BigInteger modulus = leerEnteroDer(pkcs1, pos);
        leerEnteroDer(pkcs1, pos); // public exponent
        BigInteger privateExponent = leerEnteroDer(pkcs1, pos);
        if (pos[0] > seqEnd) {
            throw new IllegalArgumentException("Clave PKCS#1 truncada.");
        }

        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
        return kf.generatePrivate(spec);
    }

    private BigInteger leerEnteroDer(byte[] data, int[] offsetRef) {
        int offset = offsetRef[0];
        if (offset >= data.length || data[offset] != 0x02) {
            throw new IllegalArgumentException("DER invalido. Se esperaba INTEGER.");
        }
        offset++;
        int[] lenBytes = new int[1];
        int len = leerLongitudDer(data, offset, lenBytes);
        offset += lenBytes[0];
        if (offset + len > data.length) {
            throw new IllegalArgumentException("DER invalido. Longitud fuera de rango.");
        }
        byte[] value = Arrays.copyOfRange(data, offset, offset + len);
        offset += len;
        offsetRef[0] = offset;
        return new BigInteger(1, value);
    }

    private int leerLongitudDer(byte[] data, int offset, int[] bytesLeidos) {
        if (offset >= data.length) {
            throw new IllegalArgumentException("DER invalido. Longitud incompleta.");
        }
        int first = data[offset] & 0xFF;
        if ((first & 0x80) == 0) {
            bytesLeidos[0] = 1;
            return first;
        }
        int numBytes = first & 0x7F;
        if (numBytes == 0 || numBytes > 4 || offset + numBytes >= data.length) {
            throw new IllegalArgumentException("DER invalido. Longitud mal formada.");
        }
        int len = 0;
        for (int i = 0; i < numBytes; i++) {
            len = (len << 8) | (data[offset + 1 + i] & 0xFF);
        }
        bytesLeidos[0] = 1 + numBytes;
        return len;
    }

    // -------------------------------------------------------------------------
    // Logica Hash
    // -------------------------------------------------------------------------

    private void calcularHash(String algoritmo) {
        String mensaje = hashMensajeArea.getText();
        if (mensaje.isEmpty()) {
            mostrarMensaje("Ingresa un mensaje para calcular su hash.");
            return;
        }
        try {
            MessageDigest md = MessageDigest.getInstance(algoritmo);
            byte[] hash = md.digest(mensaje.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            hashResultadoArea.setText(algoritmo + ": " + hex);
        } catch (Exception ex) {
            mostrarMensaje("Error al calcular hash: " + ex.getMessage());
        }
    }

    private void copiarHash() {
        String texto = hashResultadoArea.getText().trim();
        if (texto.isEmpty()) {
            mostrarMensaje("No hay hash para copiar.");
            return;
        }
        StringSelection sel = new StringSelection(texto);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
        mostrarMensaje("Hash copiado al portapapeles.");
    }

    // -------------------------------------------------------------------------
    // Helpers de UI
    // -------------------------------------------------------------------------

    private JLabel crearEtiqueta(String texto) {
        JLabel label = new JLabel(texto);
        label.setFont(fontLabel);
        label.setForeground(COLOR_GRAY_MID);
        label.setAlignmentX(JLabel.LEFT_ALIGNMENT);
        return label;
    }

    private JTextArea crearAreaEditable(int filas) {
        JTextArea area = new JTextArea(filas, 40);
        area.setFont(fontField);
        area.setForeground(COLOR_TEXT_SOFT);
        area.setBackground(COLOR_WHITE);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(new EmptyBorder(8, 10, 8, 10));
        return area;
    }

    private JTextArea crearAreaSoloLectura(int filas) {
        JTextArea area = new JTextArea(filas, 40);
        area.setFont(fontField);
        area.setForeground(COLOR_TEXT_SOFT);
        area.setBackground(COLOR_GRAY_LIGHT);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(new EmptyBorder(8, 10, 8, 10));
        return area;
    }

    private JTextField crearCampoTexto() {
        JTextField field = new JTextField();
        field.setFont(fontField);
        field.setForeground(COLOR_TEXT_SOFT);
        field.setBackground(COLOR_WHITE);
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(COLOR_GRAY_BORDER, 1),
            new EmptyBorder(6, 10, 6, 10)
        ));
        field.setAlignmentX(JTextField.LEFT_ALIGNMENT);
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        return field;
    }

    private JScrollPane wrapScroll(JTextArea area) {
        JScrollPane scroll = new JScrollPane(area);
        scroll.setBorder(BorderFactory.createLineBorder(COLOR_GRAY_BORDER, 1));
        scroll.setAlignmentX(JScrollPane.LEFT_ALIGNMENT);
        return scroll;
    }

    private JButton crearBotonPrincipal(String texto, java.awt.event.ActionListener listener) {
        JButton boton = new JButton(texto);
        boton.setFont(fontField);
        boton.setForeground(COLOR_WHITE);
        boton.setBackground(COLOR_PRIMARY);
        boton.setBorder(BorderFactory.createEmptyBorder(10, 16, 10, 16));
        boton.setFocusPainted(false);
        boton.setBorderPainted(false);
        boton.setOpaque(true);
        boton.setAlignmentX(JButton.LEFT_ALIGNMENT);
        boton.addActionListener(listener);
        boton.addChangeListener(e -> {
            if (boton.getModel().isPressed()) {
                boton.setBackground(COLOR_PRIMARY_DARK);
            } else if (boton.getModel().isRollover()) {
                boton.setBackground(COLOR_PRIMARY_LIGHT);
            } else {
                boton.setBackground(COLOR_PRIMARY);
            }
        });
        return boton;
    }

    private JPanel crearPanelBotones(JButton... botones) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        panel.setBackground(COLOR_WHITE);
        panel.setAlignmentX(JPanel.LEFT_ALIGNMENT);
        for (JButton b : botones) {
            panel.add(b);
        }
        return panel;
    }

    private JPanel crearSeparador() {
        JPanel sep = new JPanel();
        sep.setBackground(COLOR_SEPARATOR);
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep.setPreferredSize(new Dimension(0, 1));
        sep.setAlignmentX(JPanel.LEFT_ALIGNMENT);
        return sep;
    }

    private void mostrarMensaje(String mensaje) {
        JOptionPane.showMessageDialog(null, mensaje, "Aviso", JOptionPane.INFORMATION_MESSAGE);
    }

    private String normalizarBase64(String texto) {
        if (texto == null) {
            return "";
        }
        String limpio = texto.replace('-', '+').replace('_', '/');
        return limpio.replaceAll("[^A-Za-z0-9+/=]", "").trim();
    }

    private String decodificarTextoLegible(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        String utf8 = new String(data, StandardCharsets.UTF_8).trim();
        if (esTextoLegible(utf8)) {
            return utf8;
        }
        String latin1 = new String(data, StandardCharsets.ISO_8859_1).trim();
        if (esTextoLegible(latin1)) {
            return latin1;
        }
        return "";
    }

    private boolean esTextoLegible(String texto) {
        if (texto == null || texto.isEmpty()) {
            return false;
        }
        int malos = 0;
        int total = texto.length();
        for (int i = 0; i < total; i++) {
            char c = texto.charAt(i);
            if (c == '\uFFFD' || (Character.isISOControl(c) && !Character.isWhitespace(c))) {
                malos++;
            }
        }
        return malos * 10 <= total;
    }

    private byte[] extraerPkcs1Mensaje(byte[] raw) {
        if (raw == null || raw.length < 11) {
            return null;
        }
        int offset = 0;
        if (raw[0] == 0x00) {
            offset = 1;
        }
        if (raw[offset] != 0x02) {
            return null;
        }
        int idx = offset + 1;
        while (idx < raw.length && raw[idx] != 0x00) {
            idx++;
        }
        int paddingLen = idx - (offset + 1);
        if (idx >= raw.length || paddingLen < 8) {
            return null;
        }
        int msgStart = idx + 1;
        if (msgStart >= raw.length) {
            return new byte[0];
        }
        return Arrays.copyOfRange(raw, msgStart, raw.length);
    }

    private JPanel crearFooter() {
        JPanel footer = new JPanel();
        footer.setBackground(COLOR_WHITE);
        footer.setLayout(new BoxLayout(footer, BoxLayout.Y_AXIS));
        footer.setAlignmentX(JPanel.LEFT_ALIGNMENT);
        footer.setBorder(new EmptyBorder(8, 0, 0, 0));

        JLabel universidad = new JLabel(
            "Fundación Universitaria del Área Andina");
        universidad.setFont(fontLabel);
        universidad.setForeground(COLOR_GRAY_MID);

        JLabel integrantes = new JLabel(
            "Integrante: Diego Andrés Lopez Rodriguez");
        integrantes.setFont(fontLabel);
        integrantes.setForeground(COLOR_GRAY_MID);

        JLabel fecha = new JLabel("Fecha de entrega: 1 de junio de 2026");
        fecha.setFont(fontLabel);
        fecha.setForeground(COLOR_GRAY_MID);

        footer.add(universidad);
        footer.add(Box.createVerticalStrut(4));
        footer.add(integrantes);
        footer.add(Box.createVerticalStrut(4));
        footer.add(fecha);
        return footer;
    }

    private Font resolverFuente(int size, int style) {
        String familia = Font.SANS_SERIF;
        try {
            String[] familias = GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getAvailableFontFamilyNames();
            for (String nombre : familias) {
                if ("Roboto".equalsIgnoreCase(nombre)) {
                    familia = nombre;
                    break;
                }
            }
        } catch (Exception ignored) {
            // Si falla la deteccion de fuentes, se usa SansSerif como respaldo seguro.
        }
        return new Font(familia, style, size);
    }
}
