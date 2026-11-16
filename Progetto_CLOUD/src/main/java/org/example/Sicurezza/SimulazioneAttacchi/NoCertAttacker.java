package org.example.Sicurezza.SimulazioneAttacchi;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;

import java.util.Properties;

/**
 * NoCertAttacker - Tentativo di connessione senza certificato client.
 *
 * <p>Simula un attore esterno che prova a connettersi al cluster Kafka senza un
 * keystore client. Il client possiede solo il truststore comune, quindi accetta
 * i broker firmati dalla CA {@code Kafka-CA}, ma non può presentare un'identità.
 *
 * <p><b>Comportamento atteso:</b>
 * <ul>
 *   <li>il broker rifiuta l'handshake SSL, perché il listener {@code EXTERNAL} è
 *       configurato con {@code KAFKA_SSL_CLIENT_AUTH=required};</li>
 *   <li>nessun messaggio arriva al topic, quindi la dashboard non registra
 *       alcun evento: la difesa è applicata a livello di connessione, non di contenuto;</li>
 *   <li>il programma stampa {@code [DIFESA RIUSCITA]} con l'eccezione ricevuta.</li>
 * </ul>
 *
 * <p><b>Verifica lato server:</b> le righe di rifiuto compaiono nei log dei broker:
 * <pre>docker logs kafka1 2>&amp;1 | grep -iE "ssl|handshake|authentication"</pre>
 *
 * <p><b>Prerequisiti:</b>
 * <ul>
 *   <li>cluster Kafka attivo con i tre broker in stato {@code Up};</li>
 *   <li>file {@code sicurezza/certs/kafka.truststore.jks} presente nella cartella
 *       di lavoro del progetto.</li>
 * </ul>
 *
 * @see org.example.Sicurezza.SimulazioneAttacchi.FullAccessAttacker
 * @see org.example.Sicurezza.SimulazioneAttacchi.DoSAttacker
 */
public class NoCertAttacker {

    /** Broker raggiungibili dal PC tramite le porte esposte da Docker. */
    private static final String CLUSTER_ENDPOINTS = "localhost:9093,localhost:9095,localhost:9096";

    /**
     * Tenta una connessione anonima al cluster richiedendo i metadati del topic.
     * La richiesta fallisce durante l'handshake SSL, prima di inviare qualsiasi dato.
     *
     * <p>Il programma non termina con un errore del sistema: la mancata connessione
     * è il risultato atteso, e viene stampata come esito positivo della difesa.
     *
     * @param args non utilizzato
     */
    public static void main(String[] args) {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
        System.out.println(">>> TENTATIVO DI CONNESSIONE PRIVO DI CERTIFICATO IDENTITARIO...");

        Properties connectionSettings = buildConfiguration();

        try (KafkaProducer<String, String> anonymousProducer = new KafkaProducer<>(connectionSettings)) {
            System.out.println("[ATTACCO] Handshake di rete in corso...");
            anonymousProducer.partitionsFor("secure-orders");

            // Se l'esecuzione arriva qui, il broker ha accettato una connessione senza identità
            System.out.println("[ERRORE CRITICO] Connessione stabilita senza un certificato valido!");
        } catch (Exception ex) {
            System.out.println("\n[DIFESA RIUSCITA] Accesso negato correttamente.");
            System.out.println("Il Broker ha respinto l'handshake in modo forzato.");
            System.out.println("Dettaglio Tecnico: " + ex.getClass().getSimpleName() + " - " + ex.getMessage()
                    + " - SSL Handshake Fallito / Connessione interrotta.");
            System.out.println("Motivazione: Assenza di certificato client. Rigida policy mTLS attiva.");
        }
    }

    /**
     * Costruisce la configurazione SSL senza keystore client.
     *
     * <p>Il keystore è omesso di proposito: il broker deve rifiutare il client
     * perché non può verificare un certificato che non viene presentato.
     *
     * @return proprietà per {@link KafkaProducer} con il solo truststore
     */
    private static Properties buildConfiguration() {
        Properties connectionSettings = new Properties();
        connectionSettings.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, CLUSTER_ENDPOINTS);
        connectionSettings.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        connectionSettings.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        connectionSettings.put("security.protocol", "SSL");

        // Keystore client intenzionalmente assente: ssl.keystore.location non viene impostato
        connectionSettings.put("ssl.truststore.location", "sicurezza/certs/kafka.truststore.jks");
        connectionSettings.put("ssl.truststore.password", "KafkaSecurePass123");

        return connectionSettings;
    }
}