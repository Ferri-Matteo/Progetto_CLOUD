
// quando setta la whitelist iniziale? faccio leggere e scrivere bootstrap zero Acl read e write. lancio i container, avvio la defense console. La prima cosa che fa, anche se ci sono black list me ne fotto e tengo solo white list,
//  solo produttore e consumatore originali. Dice a kafka che devoe comunicare solo con loro due


package org.example.Sicurezza;

import org.apache.kafka.clients.admin.*;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.acl.*;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourcePatternFilter;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.example.OrderDispatcherConsumer;
import org.example.OrderDispatcherProducer;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicProgressBarUI;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.Duration;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * EnterpriseDefenseConsole - Console di monitoraggio e risposta agli incidenti.
 *
 * <p>Applicazione grafica (Swing) che sorveglia il topic {@code secure-orders} e
 * reagisce alle minacce applicando regole ACL dinamiche sul cluster Kafka.
 * Il programma ha due parti indipendenti:
 * <ul>
 *   <li><b>motore di rilevamento</b>: un thread in background legge il topic,
 *       analizza ogni messaggio e decide se applicare una revoca;</li>
 *   <li><b>interfaccia grafica</b>: mostra il registro degli eventi, il throughput
 *       e i pulsanti di controllo manuale.</li>
 * </ul>
 *
 * <p><b>Modello di fiducia:</b> il cluster parte in modalità zero trust
 * ({@code ALLOW_EVERYONE_IF_NO_ACL_FOUND=false}). Al bootstrap la console crea solo
 * due regole ALLOW: scrittura per {@code OrderProducer} e lettura per
 * {@code OrderConsumer}, entrambe sul topic {@code secure-orders}. Ogni altra
 * identità è respinta.
 *
 * <p><b>Identità usata:</b> la console si connette con {@code SecurityAdmin}, che è
 * super user e può modificare le ACL. Senza questa identità il bootstrap fallisce.
 *
 * <p><b>Regole di rilevamento</b>, applicate a ogni messaggio nell'ordine seguente:
 * <table border="1">
 *   <caption>Controlli sul flusso del topic</caption>
 *   <tr><th>Controllo</th><th>Condizione</th><th>Esito</th></tr>
 *   <tr><td>Struttura</td><td>manca {@code ordine_id} oppure {@code status}/{@code stato}</td><td>DENY su {@code OrderProducer}</td></tr>
 *   <tr><td>Sequenza assente</td><td>manca {@code seq} o {@code counter}</td><td>DENY su {@code OrderProducer}</td></tr>
 *   <tr><td>Salto di sequenza</td><td>differenza dal massimo visto &gt; 50000</td><td>DENY su {@code OrderProducer}</td></tr>
 *   <tr><td>Replay</td><td>sequenza già vista nella sessione</td><td>DENY su {@code OrderProducer}</td></tr>
 *   <tr><td>Volume</td><td>throughput &gt; {@value #MAX_TRAFFIC_LIMIT_SEC} msg/sec</td><td>DENY su {@code OrderProducer} e {@code OrderConsumer}</td></tr>
 * </table>
 *
 * <p><b>Limiti noti:</b>
 * <ul>
 *   <li>la revoca colpisce l'identità del certificato, non il processo: il producer
 *       legittimo viene bloccato insieme a un eventuale attaccante che usa lo stesso certificato;</li>
 *   <li>la revoca blocca solo le scritture: i messaggi già accettati continuano a
 *       essere letti dal consumer;</li>
 *   <li>lo storico dei numeri di sequenza è in memoria: si azzera con RESTORE PERMISSIONS
 *       o con il riavvio della console.</li>
 * </ul>
 *
 * <p><b>Prerequisiti:</b>
 * <ul>
 *   <li>cluster Kafka attivo, con i tre broker in stato {@code Up};</li>
 *   <li>topic {@code secure-orders} creato con {@code admin.properties};</li>
 *   <li>avvio dalla radice del progetto, perché i percorsi dei certificati sono relativi
 *       a {@code sicurezza/certs/}.</li>
 * </ul>
 *
 * @see OrderDispatcherProducer
 * @see OrderDispatcherConsumer
 */
public class EnterpriseDefenseConsole extends JFrame {

    // --- CONFIGURAZIONE CLUSTER KAFKA ---
    /** Broker raggiungibili dal PC tramite le porte esposte da Docker. */
    private static final String CLUSTER_ENDPOINTS = "localhost:9093,localhost:9095,localhost:9096";
    /** Topic protetto monitorato dalla console. */
    private static final String TARGET_TOPIC = "secure-orders";
    /** Soglia di throughput, in messaggi al secondo, oltre la quale scatta il lockdown globale. */
    private static final int MAX_TRAFFIC_LIMIT_SEC = 2000;

    // --- IDENTITÀ DI SICUREZZA ---
    private static final String PRODUCER_ID = "User:CN=OrderProducer,OU=IT,O=Cloud,L=Milano,C=IT";
    private static final String CONSUMER_ID = "User:CN=OrderConsumer,OU=IT,O=Cloud,L=Milano,C=IT";

    // --- PALETTE UI (tema chiaro) ---
    private static final Color UI_BACKGROUND = new Color(244, 246, 250);
    private static final Color UI_PANEL = Color.WHITE;
    private static final Color UI_PANEL_BORDER = new Color(218, 223, 232);
    private static final Color UI_TEXT_PRIMARY = new Color(30, 41, 59);
    private static final Color UI_TEXT_MUTED = new Color(100, 116, 139);
    private static final Color UI_LOG_BACKGROUND = new Color(250, 251, 253);
    private static final Color UI_LOG_TEXT = new Color(51, 65, 85);
    private static final Color UI_STATUS_OK = new Color(22, 163, 74);
    private static final Color UI_STATUS_ALERT = new Color(220, 38, 38);
    private static final Color UI_PRIMARY_ACCENT = new Color(37, 99, 235);
    private static final Color UI_BUTTON_NEUTRAL = new Color(71, 85, 105);

    /** Valore massimo della barra del throughput: scala di visualizzazione, non una soglia di sicurezza. */
    private static final int THROUGHPUT_BAR_MAX = 2500;

    // --- STATO DEL MOTORE PRINCIPALE ---
    private final AtomicBoolean isAccessBlocked = new AtomicBoolean(false);
    private AdminClient kafkaAdmin;
    private KafkaConsumer<String, String> auditConsumer;
    private boolean engineActive = true;

    // --- METRICA DEL FLUSSO ---
    private long currentWindowSec = 0;
    private int packetCountCurrentSec = 0;
    private int peakThroughputRate = 0;

    // --- STATO DEL RILEVAMENTO ANOMALIE ---
    private final Set<String> historicalIdsTracker = new HashSet<>();
    private long highestObservedSeq = -1;

    // --- COMPONENTI GRAFICI ---
    private JTextArea consoleLogArea;
    private JProgressBar throughputBar;
    private JLabel operationalStateLabel;
    private JLabel throughputTextLabel;
    private JPanel statusDot;
    private Color currentStatusColor = UI_STATUS_OK;
    private JButton actionBlockButton, actionPurgeButton, actionRestoreButton;

    /**
     * Costruttore: crea l'interfaccia grafica e avvia il motore di monitoraggio in background.
     */
    public EnterpriseDefenseConsole() {
        buildUserInterface();
        launchKafkaMonitoringEngine();
    }

    /**
     * Costruisce la finestra: intestazione con lo stato, registro eventi
     * al centro, metriche e pulsanti in basso.
     */
    private void buildUserInterface() {
        setTitle("ENTERPRISE DEFENSE CONSOLE - NETWORK MONITORING UNIT");
        setSize(1100, 760);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        getContentPane().setBackground(UI_BACKGROUND);

        add(buildHeader(), BorderLayout.NORTH);
        add(buildLogSection(), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        setLocationRelativeTo(null);
    }

    /**
     * Intestazione: titolo, sottotitolo con topic e modalità e indicatore di stato.
     * 
     * @return il pannello di intestazione
     */
    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        header.setBorder(new EmptyBorder(22, 28, 14, 28));

        JPanel titleBlock = new JPanel();
        titleBlock.setOpaque(false);
        titleBlock.setLayout(new BoxLayout(titleBlock, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Enterprise Defense Console");
        title.setForeground(UI_TEXT_PRIMARY);
        title.setFont(new Font("Segoe UI", Font.BOLD, 22));

        JLabel subtitle = new JLabel("Secure Stream Analyzer  \u00B7  topic " + TARGET_TOPIC + "  \u00B7  mTLS");
        subtitle.setForeground(UI_TEXT_MUTED);
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 13));

        titleBlock.add(title);
        titleBlock.add(Box.createVerticalStrut(4));
        titleBlock.add(subtitle);

        statusDot = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(currentStatusColor);
                g2.fillOval(0, 0, getWidth(), getHeight());
                g2.dispose();
            }
        };
        statusDot.setOpaque(false);
        statusDot.setPreferredSize(new Dimension(10, 10));

        operationalStateLabel = new JLabel("STATUS: SYSTEM OPERATIONAL");
        operationalStateLabel.setForeground(UI_STATUS_OK);
        operationalStateLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));

        JPanel statusPill = new RoundedPanel(24, UI_PANEL, UI_PANEL_BORDER,
                new FlowLayout(FlowLayout.LEFT, 10, 0));
        statusPill.setBorder(new EmptyBorder(8, 16, 8, 18));
        statusPill.add(statusDot);
        statusPill.add(operationalStateLabel);

        header.add(titleBlock, BorderLayout.WEST);
        header.add(statusPill, BorderLayout.EAST);
        return header;
    }

    /**
     * Costruisce la sezione centrale con il registro degli eventi.
     * Il registro è in sola lettura e scorre automaticamente sull'ultima riga.
     *
     * @return il pannello della sezione log
     */
    private JPanel buildLogSection() {
        JPanel section = new JPanel(new BorderLayout());
        section.setOpaque(false);
        section.setBorder(new EmptyBorder(0, 28, 0, 28));

        RoundedPanel logCard = new RoundedPanel(16, UI_PANEL, UI_PANEL_BORDER, new BorderLayout(0, 10));
        logCard.setBorder(new EmptyBorder(14, 16, 14, 16));

        JLabel logTitle = new JLabel("Registro eventi");
        logTitle.setForeground(UI_TEXT_MUTED);
        logTitle.setFont(new Font("Segoe UI", Font.BOLD, 12));

        consoleLogArea = new JTextArea();
        consoleLogArea.setEditable(false);
        consoleLogArea.setBackground(UI_LOG_BACKGROUND);
        consoleLogArea.setForeground(UI_LOG_TEXT);
        consoleLogArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        consoleLogArea.setMargin(new Insets(12, 14, 12, 14));

        DefaultCaret textCaret = (DefaultCaret) consoleLogArea.getCaret();
        textCaret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

        JScrollPane scrollPane = new JScrollPane(consoleLogArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(UI_PANEL_BORDER, 1));
        scrollPane.getViewport().setBackground(UI_LOG_BACKGROUND);

        logCard.add(logTitle, BorderLayout.NORTH);
        logCard.add(scrollPane, BorderLayout.CENTER);

        section.add(logCard, BorderLayout.CENTER);
        return section;
    }

    /**
     * Costruisce il pannello inferiore: la barra del throughput con il valore numerico
     * e i tre pulsanti di controllo manuale.
     *
     * <p>I pulsanti eseguono in ordine: svuotamento del topic, revoca dell'accesso del
     * producer, ripristino delle autorizzazioni.
     *
     * @return il pannello inferiore
     */
    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout(0, 14));
        footer.setOpaque(false);
        footer.setBorder(new EmptyBorder(14, 28, 24, 28));

        RoundedPanel metricsCard = new RoundedPanel(16, UI_PANEL, UI_PANEL_BORDER, new BorderLayout(0, 10));
        metricsCard.setBorder(new EmptyBorder(16, 20, 16, 20));

        throughputTextLabel = new JLabel("LIVE THROUGHPUT: 0 msg/sec");
        throughputTextLabel.setForeground(UI_TEXT_PRIMARY);
        throughputTextLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));

        throughputBar = new JProgressBar(0, THROUGHPUT_BAR_MAX);
        throughputBar.setUI(new BasicProgressBarUI());
        throughputBar.setPreferredSize(new Dimension(0, 10));
        throughputBar.setForeground(UI_PRIMARY_ACCENT);
        throughputBar.setBackground(UI_PANEL_BORDER);
        throughputBar.setBorderPainted(false);
        throughputBar.setStringPainted(false);

        metricsCard.add(throughputTextLabel, BorderLayout.NORTH);
        metricsCard.add(throughputBar, BorderLayout.CENTER);

        RoundedPanel actionCard = new RoundedPanel(16, UI_PANEL, UI_PANEL_BORDER,
                new FlowLayout(FlowLayout.RIGHT, 12, 0));
        actionCard.setBorder(new EmptyBorder(12, 16, 12, 16));

        actionPurgeButton = createCustomButton("SVUOTA TOPIC", UI_BUTTON_NEUTRAL);
        actionBlockButton = createCustomButton("REVOKE ACCESS", UI_STATUS_ALERT);
        actionRestoreButton = createCustomButton("RESTORE PERMISSIONS", UI_STATUS_OK);

        actionBlockButton.addActionListener(e -> applyAccessRevocation(Collections.singletonList(PRODUCER_ID), "ADMIN_MANUAL_OVERRIDE"));
        actionPurgeButton.addActionListener(e -> executeDataSanitization());
        actionRestoreButton.addActionListener(e -> restoreDefaultSecurityState());

        actionCard.add(actionPurgeButton);
        actionCard.add(actionBlockButton);
        actionCard.add(actionRestoreButton);

        footer.add(metricsCard, BorderLayout.NORTH);
        footer.add(actionCard, BorderLayout.SOUTH);
        return footer;
    }

    /**
     * Crea un pulsante con angoli arrotondati e scurimento al passaggio del mouse.
     * 
     * @param labelText testo del pulsante
     * @param buttonBg  colore di sfondo
     * @return il pulsante configurato
     */
    private JButton createCustomButton(String labelText, Color buttonBg) {
        JButton customBtn = new JButton(labelText) {
            private boolean hovered = false;

            {
                addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseEntered(MouseEvent e) {
                        hovered = true;
                        repaint();
                    }

                    @Override
                    public void mouseExited(MouseEvent e) {
                        hovered = false;
                        repaint();
                    }
                });
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(hovered ? buttonBg.darker() : buttonBg);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        customBtn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        customBtn.setForeground(Color.WHITE);
        customBtn.setOpaque(false);
        customBtn.setContentAreaFilled(false);
        customBtn.setBorderPainted(false);
        customBtn.setFocusPainted(false);
        customBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        customBtn.setPreferredSize(new Dimension(200, 42));
        return customBtn;
    }

    /**
     * Avvia il motore di monitoraggio su un thread separato.
     *
     * <p>Sequenza di avvio: creazione dell'{@code AdminClient}, bootstrap delle ACL,
     * creazione del consumer e sottoscrizione al topic. Solo dopo questi passaggi
     * il motore è dichiarato attivo. Poi entra nel ciclo di polling, che esegue i
     * controlli su ogni messaggio e il calcolo del throughput.
     *
     * <p>Il consumer usa {@code auto.offset.reset=latest} e un gruppo nuovo a ogni avvio:
     * legge solo i messaggi arrivati dopo l'assegnazione delle partizioni.
    */
    private void launchKafkaMonitoringEngine() {
        new Thread(() -> {
            Properties securityProps = buildSecureConfig();
            Properties listenerProps = new Properties();
            listenerProps.putAll(securityProps);
            listenerProps.put(ConsumerConfig.GROUP_ID_CONFIG, "security-audit-" + System.currentTimeMillis());
            listenerProps.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
            listenerProps.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
            listenerProps.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "latest");
            listenerProps.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, "15000");

            try {
                kafkaAdmin = AdminClient.create(securityProps);
                initializeZeroTrustRules();
                auditConsumer = new KafkaConsumer<>(listenerProps);
                auditConsumer.subscribe(Collections.singletonList(TARGET_TOPIC));
                appendLog("[SYSTEM] Security Engine initialized. Protocol and State verification active.");
            } catch (Exception ex) {
                appendLog("[CRITICAL] Engine Startup Failure: " + ex.getMessage());
                return;
            }

            while (engineActive) {
                try {
                    ConsumerRecords<String, String> recordsStream = auditConsumer.poll(Duration.ofMillis(100));

                    long currentSecEpoch = System.currentTimeMillis() / 1000;
                    if (currentSecEpoch > currentWindowSec) {
                        peakThroughputRate = packetCountCurrentSec;
                        packetCountCurrentSec = 0;
                        currentWindowSec = currentSecEpoch;
                    }
                    packetCountCurrentSec += recordsStream.count();
                    if (!recordsStream.isEmpty()) appendLog("[AUDIT] Ricevuto " + recordsStream.count() + " messaggio");
                    int activeRateDisplay = Math.max(peakThroughputRate, packetCountCurrentSec);

                    SwingUtilities.invokeLater(() -> {
                        throughputBar.setValue(activeRateDisplay);
                        throughputTextLabel.setText("LIVE THROUGHPUT: " + activeRateDisplay + " msg/sec");
                    });

                    // BLOCCO DOS - LOCKDOWN GLOBALE (Banda bloccata se superata la soglia)
                    if (!isAccessBlocked.get() && activeRateDisplay > MAX_TRAFFIC_LIMIT_SEC) {
                        appendLog("[ALERT] Volumetric flood detected (" + activeRateDisplay + " msg/sec). Executing GLOBAL LOCKDOWN.");
                        applyAccessRevocation(Arrays.asList(PRODUCER_ID, CONSUMER_ID), "GLOBAL_DOS_LOCKDOWN");
                        continue;
                    }

                    for (ConsumerRecord<String, String> recordItem : recordsStream) {
                        if (isAccessBlocked.get()) break;

                        String jsonPayload = recordItem.value();
                        if (jsonPayload == null) continue;

                        // Controllo strutturale: campi obbligatori presenti
                        if (!jsonPayload.contains("ordine_id") || (!jsonPayload.contains("status") && !jsonPayload.contains("stato"))) {
                            appendLog("[SECURITY] Structural integrity violation. Missing mandatory fields.");
                            applyAccessRevocation(Collections.singletonList(PRODUCER_ID), "STRUCTURAL_INTEGRITY_VIOLATION");
                            continue;
                        }

                        // Controllo di presenza del numero di sequenza
                        Long sequenceVal = parsePayloadSequence(jsonPayload);
                        if (sequenceVal == null) {
                            appendLog("[SECURITY] PROTOCOL VIOLATION: Missing Sequence ID. Counterfeit payload detected.");
                            applyAccessRevocation(Collections.singletonList(PRODUCER_ID), "MISSING_SEQUENCE_COUNTER");
                            continue;
                        }

                        // Controllo sui salti di sequenza
                        if (highestObservedSeq != -1) {
                            long sequenceDelta = Math.abs(sequenceVal - highestObservedSeq);
                            if (sequenceDelta > 50000) {
                                appendLog("[SECURITY] DUAL-USAGE DETECTED! Massive sequence jump (" + sequenceDelta + "). Two actors are using the Producer certificate.");
                                applyAccessRevocation(Collections.singletonList(PRODUCER_ID), "DUAL_USAGE_IDENTITY_CLONING");
                                continue;
                            }
                        }
                        if (sequenceVal > highestObservedSeq) {
                            highestObservedSeq = sequenceVal;
                        }

                        // Controllo anti-replay: la sequenza non deve essere già stata vista
                        if (!historicalIdsTracker.add(sequenceVal.toString())) {
                            appendLog("[SECURITY] REPLAY ATTACK DETECTED! Duplicated sequence: " + sequenceVal);
                            applyAccessRevocation(Collections.singletonList(PRODUCER_ID), "REPLAY_ATTACK_DETECTED");
                        }
                        // Limite di memoria dello storico: svuotato oltre 50000 voci
                        if (historicalIdsTracker.size() > 50000) historicalIdsTracker.clear();
                    }
                } catch (Exception ex) {
                    appendLog("[WARNING] Network overload. Engine self-healing...");
                    try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                }
            }
        }).start();
    }

    /**
     * Crea le due regole ALLOW di base sul topic: scrittura per il producer e lettura per il consumer.
     *
     * <p>Se le regole esistono già, il broker può restituire un errore: il metodo lo
     * registra come avviso e il motore prosegue.
     */
    private void initializeZeroTrustRules() {
        appendLog("[SYSTEM] Bootstrapping Zero-Trust ACLs...");
        ResourcePattern resourcePattern = new ResourcePattern(ResourceType.TOPIC, TARGET_TOPIC, PatternType.LITERAL);

        AccessControlEntry producerAllowEntry = new AccessControlEntry(PRODUCER_ID, "*", AclOperation.WRITE, AclPermissionType.ALLOW);
        AccessControlEntry consumerAllowEntry = new AccessControlEntry(CONSUMER_ID, "*", AclOperation.READ, AclPermissionType.ALLOW);

        try {
            kafkaAdmin.createAcls(Arrays.asList(
                    new AclBinding(resourcePattern, producerAllowEntry),
                    new AclBinding(resourcePattern, consumerAllowEntry)
            )).all().get();
            appendLog("[SYSTEM] Baseline ALLOW rules applied successfully.");
        } catch (Exception ex) {
            appendLog("[WARNING] Error during ACL bootstrap (rules might already exist).");
        }
    }

    /**
     * Estrae il numero di sequenza dal payload JSON, con parsing manuale della stringa.
     *
     * <p>Cerca prima la chiave {@code seq} e poi {@code counter}. Restituisce {@code null}
     * se nessuna delle due contiene un numero valido.
     *
     * @param rawJson payload del messaggio
     * @return il numero di sequenza, oppure {@code null}
     */
    private Long parsePayloadSequence(String rawJson) {
        String[] targetKeys = {"\"seq\":", "\"counter\":"};
        for (String keyToken : targetKeys) {
            int tokenStartIndex = rawJson.indexOf(keyToken);
            if (tokenStartIndex != -1) {
                tokenStartIndex += keyToken.length();
                int tokenEndIndex = rawJson.indexOf(",", tokenStartIndex);
                if (tokenEndIndex == -1) tokenEndIndex = rawJson.indexOf("}", tokenStartIndex);
                if (tokenEndIndex != -1) {
                    try {
                        String extractedValue = rawJson.substring(tokenStartIndex, tokenEndIndex).replaceAll("\"", "").trim();
                        String numericCleaned = extractedValue.replaceAll("[^0-9]", "");
                        if (!numericCleaned.isEmpty()) return Long.parseLong(numericCleaned);
                    } catch (Exception ignored) {}
                }
            }
        }
        return null;
    }

    /**
     * Applica una regola DENY in scrittura sul topic per le identità indicate.
     *
     * <p>La regola è associata al certificato, quindi colpisce chiunque lo usi.
     * In caso di successo imposta lo stato di blocco e aggiorna l'indicatore a
     * {@code ACCESS REVOKED}.
     *
     * @param bannedPrincipals identità da bloccare, nel formato {@code User:CN=...}
     * @param breachReason     motivo registrato nel log
     */
    private void applyAccessRevocation(List<String> bannedPrincipals, String breachReason) {
        appendLog("[ACTION] Applying DENY rules to compromised identities...");
        ResourcePattern resourcePattern = new ResourcePattern(ResourceType.TOPIC, TARGET_TOPIC, PatternType.LITERAL);

        List<AclBinding> aclBindingsList = new ArrayList<>();
        for (String principalTarget : bannedPrincipals) {
            AccessControlEntry denyRuleEntry = new AccessControlEntry(principalTarget, "*", AclOperation.WRITE, AclPermissionType.DENY);
            aclBindingsList.add(new AclBinding(resourcePattern, denyRuleEntry));
            appendLog(" -> Revoking WRITE access for: " + principalTarget);
        }

        try {
            kafkaAdmin.createAcls(aclBindingsList).all().get();
            isAccessBlocked.set(true);
            refreshStatusDisplay("ACCESS REVOKED", UI_STATUS_ALERT);
            appendLog("[SUCCESS] Threat Neutralized. [Reason: " + breachReason + "]");
        } catch (Exception ex) {
            appendLog("[FAILURE] Unable to enforce ACL: " + ex.getMessage());
        }
    }

    /**
     * Rimuove le regole DENY di producer e consumer e azzera lo stato di rilevamento.
     *
     * <p>Azzera lo storico dei numeri di sequenza e i contatori del throughput, così
     * il producer può ripartire da seq 1 senza generare replay. Non ferma i processi
     * eventualmente ancora attivi: se continuano a inviare, la revoca può scattare di nuovo.
     */
    private void restoreDefaultSecurityState() {
        appendLog("[ACTION] Restoring default authorization state...");
        try {
            ResourcePatternFilter resourceFilter = new ResourcePatternFilter(ResourceType.TOPIC, TARGET_TOPIC, PatternType.LITERAL);

            AccessControlEntryFilter denyFilterProducer = new AccessControlEntryFilter(PRODUCER_ID, "*", AclOperation.WRITE, AclPermissionType.DENY);
            AccessControlEntryFilter denyFilterConsumer = new AccessControlEntryFilter(CONSUMER_ID, "*", AclOperation.WRITE, AclPermissionType.DENY);

            kafkaAdmin.deleteAcls(Arrays.asList(
                    new AclBindingFilter(resourceFilter, denyFilterProducer),
                    new AclBindingFilter(resourceFilter, denyFilterConsumer)
            )).all().get();

            isAccessBlocked.set(false);
            highestObservedSeq = -1;
            historicalIdsTracker.clear();
            packetCountCurrentSec = 0;
            peakThroughputRate = 0;

            refreshStatusDisplay("SYSTEM OPERATIONAL", UI_STATUS_OK);
            appendLog("[SUCCESS] All BANs removed. Baseline Authorized state restored.");
        } catch (Exception ex) {
            appendLog("[FAILURE] Restoration failed: " + ex.getMessage());
        }
    }

    /**
     * Svuota il topic eliminando tutti i messaggi presenti fino all'offset più recente.
     *
     * <p>Opera sulle partizioni 0, 1 e 2, che sono quelle del topic creato dalla procedura
     * del progetto. Non modifica ACL, storico dei numeri di sequenza né stato di blocco.
     */
    private void executeDataSanitization() {
        appendLog("[ACTION] Executing data plane sanitization...");
        try {
            Map<TopicPartition, ListOffsetsResult.ListOffsetsResultInfo> offsetMetadataMap =
                    kafkaAdmin.listOffsets(Map.of(
                            new TopicPartition(TARGET_TOPIC, 0), OffsetSpec.latest(),
                            new TopicPartition(TARGET_TOPIC, 1), OffsetSpec.latest(),
                            new TopicPartition(TARGET_TOPIC, 2), OffsetSpec.latest()
                    )).all().get();

            Map<TopicPartition, RecordsToDelete> deletionMap = new HashMap<>();
            offsetMetadataMap.forEach((partitionInfo, offsetInfo) -> {
                deletionMap.put(partitionInfo, RecordsToDelete.beforeOffset(offsetInfo.offset()));
            });

            kafkaAdmin.deleteRecords(deletionMap).all().get();
            appendLog("[SUCCESS] Topic infrastructure successfully sanitized.");

        } catch (Exception ex) {
            appendLog("[FAILURE] Sanitization failed: " + ex.getMessage());
        }
    }

    /**
     * Aggiunge una riga al registro eventi. Può essere chiamato da qualsiasi thread:
     * l'aggiornamento della finestra avviene sull'Event Dispatch Thread.
     *
     * @param logMessage testo da registrare, senza data (la data viene aggiunta qui)
     */
    private void appendLog(String logMessage) {
        SwingUtilities.invokeLater(() -> consoleLogArea.append("[" + new java.util.Date() + "] " + logMessage + "\n"));
    }

    /**
     * Aggiorna il testo dello stato e il colore dell'indicatore nell'intestazione.
     *
     * @param statusText  testo dello stato, ad esempio {@code ACCESS REVOKED}
     * @param statusColor colore associato allo stato
     */
    private void refreshStatusDisplay(String statusText, Color statusColor) {
        SwingUtilities.invokeLater(() -> {
            operationalStateLabel.setText("STATUS: " + statusText);
            operationalStateLabel.setForeground(statusColor);
            currentStatusColor = statusColor;
            statusDot.repaint();
        });
    }

    /**
     * Costruisce la configurazione di connessione per l'{@code AdminClient}.
     *
     * <p>Usa il keystore di {@code SecurityAdmin}, super user del cluster, e il truststore
     * comune. Il controllo del nome host è disattivato perché il cluster è raggiunto
     * tramite {@code localhost}.
     *
     * @return proprietà SSL/mTLS per l'{@code AdminClient}
     */
    private static Properties buildSecureConfig() {
        Properties connectionProps = new Properties();
        connectionProps.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, CLUSTER_ENDPOINTS);
        connectionProps.put("security.protocol", "SSL");
        connectionProps.put("ssl.truststore.location", "sicurezza/certs/kafka.truststore.jks");
        connectionProps.put("ssl.truststore.password", "KafkaSecurePass123");

        connectionProps.put("ssl.keystore.location", "sicurezza/certs/SecurityAdmin.keystore.jks");
        connectionProps.put("ssl.keystore.password", "KafkaSecurePass123");
        connectionProps.put("ssl.key.password", "KafkaSecurePass123");
        connectionProps.put("ssl.endpoint.identification.algorithm", "");
        return connectionProps;
    }

    /**
     * Pannello con angoli arrotondati, usato per le schede dell'interfaccia.
     */
    private static class RoundedPanel extends JPanel {
        private final int arc;
        private final Color fill;
        private final Color stroke;

        /**
         * @param arc    raggio degli angoli, in pixel
         * @param fill   colore di riempimento
         * @param stroke colore del bordo
         * @param layout layout del pannello
         */
        RoundedPanel(int arc, Color fill, Color stroke, LayoutManager layout) {
            super(layout);
            this.arc = arc;
            this.fill = fill;
            this.stroke = stroke;
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(fill);
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            g2.setColor(stroke);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            g2.dispose();
        }
    }

    /**
     * Punto di ingresso dell'applicazione. Crea la finestra sull'Event Dispatch Thread.
     *
     * @param args non utilizzato
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new EnterpriseDefenseConsole().setVisible(true));
    }
}
