package org.example;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;

import java.time.Duration;
import java.util.Collections;
import java.util.Properties;

/**
 * OrderDispatcherConsumer - Microservizio di smistamento ordini.
 *
 * <p>Legge il topic {@code secure-orders} come membro del gruppo
 * {@code ecommerce-dispatch-group} e stampa ogni ordine ricevuto. Usa il keystore
 * del consumer ({@code OrderConsumer.keystore.jks}) per l'autenticazione mTLS.
 *
 * <p><b>Garanzie:</b>
 * <ul>
 *   <li>{@code isolation.level=read_committed}: vengono letti solo i messaggi di
 *       transazioni completate con successo;</li>
 *   <li>{@code auto.offset.reset=earliest}: se il gruppo non ha un offset salvato,
 *       il consumer parte dal primo messaggio del topic;</li>
 *   <li>autenticazione mTLS: il broker accetta la connessione solo se il client
 *       presenta un certificato firmato dalla CA del cluster.</li>
 * </ul>
 *
 * <p><b>Permessi richiesti:</b> l'identità {@code OrderConsumer} deve avere READ
 * sul topic {@code secure-orders} e READ sul gruppo {@code ecommerce-dispatch-group}.
 * Il primo è creato dalla dashboard all'avvio; il secondo va verificato con
 * {@code kafka-acls.sh --list}.
 *
 * <p><b>Comportamento in caso di revoca:</b> se la dashboard applica un DENY in
 * scrittura, il consumer continua a leggere. Il DENY riguarda solo {@code WRITE}.
 *
 * <p><b>Prerequisiti:</b>
 * <ul>
 *   <li>cluster Kafka attivo con i tre broker in stato {@code Up};</li>
 *   <li>eseguire il programma dalla radice del progetto, perché i percorsi dei
 *       certificati sono relativi a {@code sicurezza/certs/}.</li>
 * </ul>
 *
 * @see OrderDispatcherProducer
 */
public class OrderDispatcherConsumer {

    /** Broker raggiungibili dal PC tramite le porte esposte da Docker. */
    private static final String BOOTSTRAP_SERVERS = "localhost:9093,localhost:9095,localhost:9096";

    /** Topic protetto da cui leggere gli ordini. */
    private static final String TOPIC = "secure-orders";

    /** Gruppo di consumer: con lo stesso gruppo, gli offset sono mantenuti tra un avvio e l'altro. */
    private static final String GROUP_ID = "ecommerce-dispatch-group";

    /** Intervallo minimo, in millisecondi, tra due messaggi di stato quando non arrivano ordini. */
    private static final long HEARTBEAT_INTERVAL_MS = 6000;

    /**
     * Avvia il consumer: si sottoscrive al topic e stampa ogni ordine ricevuto.
     * Il ciclo di lettura non termina, a meno di un'eccezione o di un'interruzione
     * del processo.
     *
     * @param args non utilizzato
     */
    public static void main(String[] args) {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");

        Properties props = getConfiguration();
        long lastHeartbeat = System.currentTimeMillis();

        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props)) {
            consumer.subscribe(Collections.singletonList(TOPIC));

            System.out.println("\n========================================================");
            System.out.println("   ECOMMERCE DISPATCH SERVICE - CONSUMER NODES ACTIVE   ");
            System.out.println("========================================================");
            System.out.println("CLUSTER TARGET : " + BOOTSTRAP_SERVERS);
            System.out.println("SECURITY       : mTLS (SSL) - Protocollo Protetto");
            System.out.println("CONSUMER GROUP : " + GROUP_ID);
            System.out.println("ISOLATION      : read_committed (Transazioni Atomiche)");
            System.out.println("STATO          : In ascolto di ordini in tempo reale...");
            System.out.println("--------------------------------------------------------\n");

            while (true) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(150));

                if (records.isEmpty()) {
                    // Nessun messaggio: stampa uno stato di servizio al massimo ogni HEARTBEAT_INTERVAL_MS
                    long currentTime = System.currentTimeMillis();
                    if (currentTime - lastHeartbeat > HEARTBEAT_INTERVAL_MS) {
                        System.out.println("[IDLE] Nessun nuovo ordine in coda. Sistema operativo e in ascolto...");
                        lastHeartbeat = currentTime;
                    }
                } else {
                    for (ConsumerRecord<String, String> record : records) {
                        String payload = record.value();
                        String orderId = extractOrderId(payload);

                        System.out.printf("[ELABORATO] OrdineID: %s | Partizione: %d | Offset: %d | Contenuto: %s%n",
                                orderId, record.partition(), record.offset(), payload);
                    }
                    lastHeartbeat = System.currentTimeMillis();
                }
            }
        } catch (Exception e) {
            System.err.println("\n[ERRORE CRITICO] Connessione al broker interrotta o credenziali revocate.");
            System.err.println("Dettaglio: " + e.getMessage());
        }
    }

    /**
     * Estrae il valore di {@code ordine_id} dal payload JSON, per la stampa a terminale.
     *
     * <p>Il parsing è manuale e tollera solo il formato prodotto da
     * {@link OrderDispatcherProducer}. Se la chiave manca, restituisce {@code N/A}.
     *
     * @param json payload del messaggio, può essere {@code null}
     * @return l'identificativo dell'ordine, oppure {@code N/A}
     */
    private static String extractOrderId(String json) {
        if (json == null) return "N/A";
        String key = "\"ordine_id\":";
        int start = json.indexOf(key);
        if (start != -1) {
            start += key.length();
            int end = json.indexOf(",", start);
            if (end == -1) end = json.indexOf("}", start);
            if (end != -1) {
                return json.substring(start, end).trim();
            }
        }
        return "N/A";
    }

    /**
     * Costruisce la configurazione del consumer: deserializzazione, gruppo, isolamento
     * delle transazioni e credenziali mTLS del keystore {@code OrderConsumer}.
     *
     * <p>{@code ssl.endpoint.identification.algorithm} è vuoto perché il cluster è
     * raggiunto tramite {@code localhost}, mentre i certificati sono emessi per i nomi
     * dei container. Disattivando il controllo del nome host, la verifica della catena
     * della CA resta attiva.
     *
     * @return proprietà pronte per {@link KafkaConsumer}
     */
    private static Properties getConfiguration() {
        Properties props = new Properties();

        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, BOOTSTRAP_SERVERS);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, GROUP_ID);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        // Garanzia di leggere solo transazioni completate con successo
        props.put(ConsumerConfig.ISOLATION_LEVEL_CONFIG, "read_committed");

        props.put("security.protocol", "SSL");
        props.put("ssl.truststore.location", "sicurezza/certs/kafka.truststore.jks");
        props.put("ssl.truststore.password", "KafkaSecurePass123");
        props.put("ssl.keystore.location", "sicurezza/certs/OrderConsumer.keystore.jks");
        props.put("ssl.keystore.password", "KafkaSecurePass123");
        props.put("ssl.key.password", "KafkaSecurePass123");

        props.put("ssl.endpoint.identification.algorithm", "");

        return props;
    }
}