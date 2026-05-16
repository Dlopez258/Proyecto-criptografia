import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

public class FormularioCriptografia {
    // Paleta de colores (tokens de diseño)
    private static final Color COLOR_PRIMARY = new Color(0x67B31F);
    private static final Color COLOR_PRIMARY_DARK = new Color(0x5A9E1B);
    private static final Color COLOR_PRIMARY_LIGHT = new Color(0x7CC934);
    private static final Color COLOR_WHITE = new Color(0xFFFFFF);
    private static final Color COLOR_GRAY_LIGHT = new Color(0xF8F9FA);
    private static final Color COLOR_GRAY_MID = new Color(0x6C757D);
    private static final Color COLOR_GRAY_BORDER = new Color(0xE2E8F0);
    private static final Color COLOR_TEXT_MAIN = new Color(0x1A1A1A);
    private static final Color COLOR_TEXT_SOFT = new Color(0x444444);

    private static final int AES_KEY_SIZE = 128; // bits
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

    // Campos del modulo RSA
    private JTextArea rsaMensajeArea;
    private JTextArea rsaPublicaArea;
    private JTextArea rsaPrivadaArea;
    private JTextArea rsaCifradoArea;
    private JTextArea rsaDescifradoArea;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new FormularioCriptografia().mostrar());
    }

    public FormularioCriptografia() {
        this.fontLabel = resolverFuente(13, Font.PLAIN);
        this.fontField = resolverFuente(13, Font.PLAIN);
        this.fontTitle = resolverFuente(18, Font.BOLD);
    }

    private void mostrar() {
        JFrame frame = new JFrame("Eje 3 - Criptograf\u00eda - Fundaci\u00f3n Universitaria del \u00c1rea Andina");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setBackground(COLOR_GRAY_LIGHT);
        frame.setLayout(new BorderLayout());

        JPanel card = new JPanel();
        card.setBackground(COLOR_WHITE);
        card.setBorder(new EmptyBorder(24, 28, 24, 28));
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel titulo = new JLabel("Eje 3 - Criptograf\u00eda - Fundaci\u00f3n Universitaria del \u00c1rea Andina");
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
        frame.setMinimumSize(new Dimension(900, 600));
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private JTabbedPane crearPestanas() {
        JTabbedPane pestanas = new JTabbedPane();
        pestanas.setFont(fontLabel);
        pestanas.setBackground(COLOR_GRAY_LIGHT);
        pestanas.setForeground(COLOR_TEXT_MAIN);
        pestanas.addTab("AES (Sim\u00e9trico)", crearPanelAES());
        pestanas.addTab("RSA (Asim\u00e9trico)", crearPanelRSA());
        return pestanas;
    }

    private JPanel crearPanelAES() {
        JPanel panel = new JPanel();
        panel.setBackground(COLOR_WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel titulo = new JLabel("M\u00f3dulo de Cifrado Sim\u00e9trico (AES)");
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

    private JPanel crearPanelRSA() {
        JPanel panel = new JPanel();
        panel.setBackground(COLOR_WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel titulo = new JLabel("M\u00f3dulo de Cifrado Asim\u00e9trico (RSA)");
        titulo.setFont(fontTitle);
        titulo.setForeground(COLOR_TEXT_MAIN);
        titulo.setAlignmentX(JLabel.LEFT_ALIGNMENT);

        rsaMensajeArea = crearAreaEditable(3);
        rsaPublicaArea = crearAreaSoloLectura(3);
        rsaPrivadaArea = crearAreaSoloLectura(3);
        rsaCifradoArea = crearAreaSoloLectura(3);
        rsaDescifradoArea = crearAreaSoloLectura(2);

        JButton botonCifrar = crearBotonPrincipal("Generar par de claves y cifrar", e -> cifrarRSA());
        JButton botonDescifrar = crearBotonPrincipal("Descifrar", e -> descifrarRSA());

        panel.add(titulo);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Mensaje en claro"));
        panel.add(Box.createVerticalStrut(6));
        panel.add(wrapScroll(rsaMensajeArea));
        panel.add(Box.createVerticalStrut(10));
        panel.add(botonCifrar);
        panel.add(Box.createVerticalStrut(12));
        panel.add(crearEtiqueta("Clave p\u00fablica (Base64)"));
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

        return panel;
    }

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
            mostrarMensaje("Error criptogr\u00e1fico AES: " + ex.getMessage());
        }
    }

    private void descifrarAES() {
        String claveBase64 = aesClaveArea.getText().trim();
        String cifradoBase64 = aesCifradoArea.getText().trim();

        if (claveBase64.isEmpty() || cifradoBase64.isEmpty()) {
            mostrarMensaje("Se requiere clave y texto cifrado para descifrar AES.");
            return;
        }

        try {
            byte[] claveBytes = Base64.getDecoder().decode(claveBase64);
            byte[] ivYCifrado = Base64.getDecoder().decode(cifradoBase64);

            if (ivYCifrado.length <= GCM_IV_LENGTH) {
                mostrarMensaje("El texto cifrado AES no contiene un IV v\u00e1lido.");
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

    private void cifrarRSA() {
        String mensaje = rsaMensajeArea.getText().trim();
        if (mensaje.isEmpty()) {
            mostrarMensaje("Ingresa un mensaje para cifrar con RSA.");
            return;
        }

        try {
            // Genera un par de claves RSA y cifra con la clave pública.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] cifrado = cipher.doFinal(mensaje.getBytes(StandardCharsets.UTF_8));

            rsaPublicaArea.setText(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            rsaPrivadaArea.setText(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            rsaCifradoArea.setText(Base64.getEncoder().encodeToString(cifrado));
            rsaDescifradoArea.setText("");
        } catch (Exception ex) {
            mostrarMensaje("Error criptogr\u00e1fico RSA: " + ex.getMessage());
        }
    }

    private void descifrarRSA() {
        String privadaBase64 = rsaPrivadaArea.getText().trim();
        String cifradoBase64 = rsaCifradoArea.getText().trim();

        if (privadaBase64.isEmpty() || cifradoBase64.isEmpty()) {
            mostrarMensaje("Se requiere clave privada y texto cifrado para descifrar RSA.");
            return;
        }

        try {
            byte[] privadaBytes = Base64.getDecoder().decode(privadaBase64);
            byte[] cifradoBytes = Base64.getDecoder().decode(cifradoBase64);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privadaBytes));

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plano = cipher.doFinal(cifradoBytes);
            rsaDescifradoArea.setText(new String(plano, StandardCharsets.UTF_8));
        } catch (Exception ex) {
            mostrarMensaje("Error al descifrar RSA: " + ex.getMessage());
        }
    }

    private void mostrarMensaje(String mensaje) {
        JOptionPane.showMessageDialog(null, mensaje, "Aviso", JOptionPane.INFORMATION_MESSAGE);
    }


    private JPanel crearFooter() {
        JPanel footer = new JPanel();
        footer.setBackground(COLOR_WHITE);
        footer.setLayout(new BoxLayout(footer, BoxLayout.Y_AXIS));
        footer.setAlignmentX(JPanel.LEFT_ALIGNMENT);
        footer.setBorder(new EmptyBorder(8, 0, 0, 0));

        JLabel universidad = new JLabel("Fundaci\u00f3n Universitaria del \u00c1rea Andina");
        universidad.setFont(fontLabel);
        universidad.setForeground(COLOR_GRAY_MID);

        JLabel integrantes = new JLabel("Integrantes: Diego Andr\u00e9s L\u00f3pez Rodr\u00edguez, Sandrith Natalia Barreto Alfonso");
        integrantes.setFont(fontLabel);
        integrantes.setForeground(COLOR_GRAY_MID);

        JLabel fecha = new JLabel("Fecha de entrega: 18 de mayo de 2026");
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
