package org.example;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.serialization.StringSerializer;

import java.time.Duration;
import java.util.Properties;

/**
 * OrderDispatcherProducer - Microservizio di invio ordini.
 *
 * <p>Invia ordini sintetici al topic {@code secure-orders}, uno ogni
 * {@link #MESSAGE_INTERVAL_MS} millisecondi, usando il keystore del producer
 * ({@code OrderProducer.keystore.jks}) per l'autenticazione mTLS.
 *
 * <p><b>Garanzie:</b>
 * <ul>
 *   <li>{@code acks=all}: ogni invio è confermato solo dopo la replica su almeno
 *       {@code min.insync.replicas} broker;</li>
 *   <li>{@code enable.idempotence=true}: il broker scarta i duplicati generati da
 *       ritrasmissioni di rete;</li>
 *   <li>autenticazione mTLS: il broker accetta la connessione solo con un
 *       certificato firmato dalla CA del cluster.</li>
 * </ul>
 *
 * <p><b>Formato del messaggio:</b> ogni payload contiene {@code ordine_id},
 * {@code seq}, {@code articolo} e {@code stato}. La dashboard si aspetta esattamente
 * questi campi: {@code ordine_id} e {@code stato} per il controllo strutturale,
 * {@code seq} per il controllo di sequenza. La chiave del messaggio è {@code key-N}.
 *
 * <p><b>Sequenza:</b> il numero {@code seq} parte da 1 a ogni avvio. Se la dashboard
 * ha già visto quei valori nella stessa sessione, scatta {@code REPLAY ATTACK DETECTED}.
 * Per evitarlo, riavviare la dashboard o eseguire RESTORE PERMISSIONS prima di
 * riavviare il producer.
 *
 * <p><b>Permessi richiesti:</b> l'identità {@code OrderProducer} deve avere WRITE sul
 * topic {@code secure-orders}. Il permesso è creato dalla dashboard all'avvio. Se la
 * dashboard ha applicato un DENY, ogni invio fallisce con
 * {@code TopicAuthorizationException}.
 *
 * <p><b>Arresto:</b> l'invio è infinito se {@link #MAX_MESSAGES_TO_SEND} vale {@code -1}.
 * Il programma si ferma con CTRL+C: un hook di shutdown chiude il producer e invia
 * i messaggi ancora in coda, entro 5 secondi.
 *
 * <p><b>Prerequisiti:</b>
 * <ul>
 *   <li>cluster Kafka attivo con i tre broker in stato {@code Up};</li>
 *   <li>eseguire il programma dalla radice del progetto, perché i percorsi dei
 *       certificati sono relativi a {@code sicurezza/certs/}.</li>
 * </ul>
 *
 * @see OrderDispatcherConsumer
 */
public class OrderDispatcherProducer {

    /** Broker raggiungibili dal PC tramite le porte esposte da Docker. */
    private static final String BOOTSTRAP_SERVERS = "localhost:9093,localhost:9095,localhost:9096";

    /** Topic protetto su cui vengono inviati gli ordini. */
    private static final String TOPIC = "secure-orders";

    /** Intervallo in millisecondi tra un ordine e l'altro. */
    private static final long MESSAGE_INTERVAL_MS = 1200;

    /** Numero massimo di messaggi da inviare. Il valore {@code -1} significa invio infinito. */
    private static final int MAX_MESSAGES_TO_SEND = -1;

    /**
     * Avvia il producer e invia gli ordini secondo {@link #MESSAGE_INTERVAL_MS}.
     *
     * <p>Ogni esito è stampato dalla callback di {@code send}: {@code [SPEDITO]} con
     * partizione e offset in caso di successo, {@code [ERRORE]} in caso di rifiuto.
     *
     * @param args non utilizzato
     */
    public static void main(String[] args) {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");

        Properties props = getConfiguration();

        try (KafkaProducer<String, String> producer = new KafkaProducer<>(props)) {

            // Hook di arresto: con l'invio infinito il programma termina solo con CTRL+C.
            // Il hook fa il flush dei messaggi in coda e chiude il producer.
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n[SHUTDOWN] CTRL+C ricevuto. Flush e chiusura del producer...");
                producer.close(Duration.ofSeconds(5));
            }));

            System.out.println("\n========================================================");
            System.out.println("   ECOMMERCE DISPATCH SERVICE - PRODUCER NODE ACTIVE    ");
            System.out.println("========================================================");
            System.out.println("CLUSTER TARGET : " + BOOTSTRAP_SERVERS);
            System.out.println("SECURITY       : mTLS (SSL) - Canale cifrato protetto");
            System.out.println("TOPIC DEST     : " + TOPIC);
            System.out.println("INTERVALLO     : " + MESSAGE_INTERVAL_MS + " ms");
            System.out.println("STATO          : Generazione e invio ordini in corso (CTRL+C per fermare)...");
            System.out.println("--------------------------------------------------------\n");

            long messageCount = 0;

            // Ciclo di invio: infinito se MAX_MESSAGES_TO_SEND == -1
            while (MAX_MESSAGES_TO_SEND == -1 || messageCount < MAX_MESSAGES_TO_SEND) {
                final long currentId = messageCount + 1;
                String payload = "{\"ordine_id\": " + currentId + ", \"seq\": " + currentId
                        + ", \"articolo\": \"Prodotto-Cloud-" + currentId + "\", \"stato\": \"COMPLETED\"}";
                ProducerRecord<String, String> record = new ProducerRecord<>(TOPIC, "key-" + currentId, payload);

                // Invio asincrono: l'esito arriva nella callback, non nel thread principale
                producer.send(record, (metadata, exception) -> {
                    if (exception == null) {
                        System.out.printf("[SPEDITO] OrdineID: %d | Partizione: %d | Offset: %d%n",
                                currentId, metadata.partition(), metadata.offset());
                    } else {
                        System.err.println("[ERRORE] Impossibile inviare l'ordine " + currentId + ": " + exception.getMessage());
                    }
                });

                messageCount++;

                if (MAX_MESSAGES_TO_SEND == -1 || messageCount < MAX_MESSAGES_TO_SEND) {
                    Thread.sleep(MESSAGE_INTERVAL_MS);
                }
            }

            System.out.println("\n[COMPLETATO] Ciclo di trasmissione ordini terminato con successo.");
        } catch (Exception e) {
            System.err.println("\n[ERRORE CRITICO] Errore imprevisto nel Producer.");
            System.err.println("Dettaglio: " + e.getMessage());
        }
    }

    /**
     * Costruisce la configurazione del producer: serializzazione, affidabilità,
     * timeout di consegna e credenziali mTLS del keystore {@code OrderProducer}.
     *
     * <p>{@code request.timeout.ms} e {@code delivery.timeout.ms} sono ridotti
     * (10 e 20 secondi) per rendere visibile in tempi brevi il fallimento di un invio
     * durante una prova di guasto. Il valore predefinito di {@code delivery.timeout.ms}
     * è di 2 minuti.
     *
     * <p>{@code ssl.endpoint.identification.algorithm} è vuoto perché il cluster è
     * raggiunto tramite {@code localhost}, mentre i certificati sono emessi per i nomi
     * dei container. La verifica della catena della CA resta attiva.
     *
     * @return proprietà pronte per {@link KafkaProducer}
     */
    private static Properties getConfiguration() {
        Properties props = new Properties();

        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, BOOTSTRAP_SERVERS);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, "10000");
        props.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, "20000");

        // Affidabilità: conferma dopo la replica completa, niente duplicati
        props.put(ProducerConfig.ACKS_CONFIG, "all");
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");

        props.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL");
        props.put(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, "sicurezza/certs/kafka.truststore.jks");
        props.put(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, "KafkaSecurePass123");
        props.put(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, "sicurezza/certs/OrderProducer.keystore.jks");
        props.put(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, "KafkaSecurePass123");
        props.put(SslConfigs.SSL_KEY_PASSWORD_CONFIG, "KafkaSecurePass123");

        props.put("ssl.endpoint.identification.algorithm", "");

        return props;
    }
}