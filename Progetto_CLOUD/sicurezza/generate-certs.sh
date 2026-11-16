#!/bin/bash
# ==============================================================================
# generate-certs.sh
#
# Genera la PKI di prova del progetto Progetto_CLOUD: una Certificate Authority
# interna, il truststore comune del cluster e tutti i keystore delle identità
# mTLS (nodi Kafka, client di test e applicazioni del progetto).
#
# SCOPO
#   Il cluster Kafka richiede certificati firmati dalla stessa CA per tutti i
#   listener SSL (KAFKA_SSL_CLIENT_AUTH=required). Questo script crea tutto
#   ciò che serve in un unico passaggio, così i certificati sono coerenti tra
#   loro.
#
# FILE PRODOTTI (in sicurezza/certs/)
#   ca-key                       Chiave privata della CA (NON condividere)
#   ca-cert                      Certificato pubblico della CA
#   ca-cert.srl                  Contatore seriale creato da openssl
#   kafka.truststore.jks         Truststore comune: contiene la CA
#   kafka1/2/3.keystore.jks      Identità dei tre broker/controller
#   client.keystore.jks          Identità generica "client" (CN=ClientApp)
#   OrderProducer.keystore.jks   Identità del producer (CN=OrderProducer)
#   OrderConsumer.keystore.jks   Identità del consumer (CN=OrderConsumer)
#   SecurityAdmin.keystore.jks   Identità amministrativa della dashboard
#   *.csr, *-cert-signed         File intermedi di firma, non usati da Kafka
#
# DN (SUBJECT) DELLE IDENTITÀ
#   Kafka usa il Subject del certificato come principal. I valori di
#   KAFKA_SUPER_USERS nel docker-compose.yml devono coincidere con questi DN:
#     kafka1/2/3       CN=kafka1,OU=CloudComputing,O=Unimi,L=Milan,C=IT
#     client           CN=ClientApp,OU=CloudComputing,O=Unimi,L=Milan,C=IT
#     OrderProducer    CN=OrderProducer,OU=IT,O=Cloud,L=Milano,C=IT
#     OrderConsumer    CN=OrderConsumer,OU=IT,O=Cloud,L=Milano,C=IT
#     SecurityAdmin    CN=SecurityAdmin,OU=IT,O=Cloud,L=Milano,C=IT
#
# PREREQUISITI
#   - openssl e keytool nel PATH (keytool è incluso in un JDK 17+)
#   - Esecuzione dalla radice del progetto: lo script crea e usa
#     il percorso relativo sicurezza/certs
#
# ESECUZIONE
#   Lo script NON va rilanciato sulla stessa cartella: keytool rifiuta gli
#   alias già esistenti. Per rigenerare tutto:
#     rm -f sicurezza/certs/*
#     bash sicurezza/generate-certs.sh
#   Dopo una rigenerazione la CA cambia, quindi il cluster va ricreato:
#     docker compose down -v && docker compose up -d
#
# NOTE DI SICUREZZA
#   - Password, CA e chiavi sono di prova. In un uso reale vanno cambiate e
#     gestite con un vault, non nel repository.
#   - ca-key non è cifrata (-nodes): chiunque la legga può firmare certificati
#     accettati dal cluster.
#   - I certificati non contengono estensioni (KeyUsage, SAN): va bene perché
#     ssl.endpoint.identification.algorithm è vuoto nel cluster.
#   - Validità: CA 10 anni, identità 365 giorni. Alla scadenza va rigenerato
#     tutto.
#   - Il client "client" non è super user: per usarlo serve un'ACL esplicita.
#
# ==============================================================================

# Interrompe lo script al primo comando che fallisce
set -e

# Disabilita la conversione automatica dei percorsi di MSYS2/Git Bash per OpenSSL
export MSYS_NO_PATHCONV=1

# Crea la cartella di destinazione e vi entra: tutti i file vengono prodotti qui
mkdir -p sicurezza/certs
cd sicurezza/certs

# Password unica per keystore, chiavi e truststore del progetto
PASS="KafkaSecurePass123"

# ------------------------------------------------------------------------------
# 1. CA interna: chiave privata (ca-key) e certificato pubblico (ca-cert),
#    validi 3650 giorni, senza cifratura della chiave (-nodes).
# ------------------------------------------------------------------------------
echo "1. Generazione della Certificate Authority (CA) interna..."
openssl req -new -x509 -keyout ca-key -out ca-cert -days 3650 \
  -subj "/C=IT/ST=Italy/L=Milan/O=Unimi/OU=CloudComputing/CN=KafkaCA" \
  -nodes

# ------------------------------------------------------------------------------
# 2. Truststore comune: contiene solo il certificato della CA.
#    Tutti i client e i broker si fidano dei certificati firmati da questa CA.
# ------------------------------------------------------------------------------
echo "2. Creazione del Truststore unico..."
keytool -keystore kafka.truststore.jks -alias CARoot -import -noprompt \
  -file ca-cert -storepass $PASS

# ------------------------------------------------------------------------------
# 3. Identità dei tre nodi Kafka (kafka1, kafka2, kafka3).
#    Per ogni nodo: chiave generata nel keystore, richiesta di firma (CSR),
#    firma con la CA, import della CA e del certificato firmato nel keystore.
# ------------------------------------------------------------------------------
for i in 1 2 3
do
  echo "3. Generazione Keystore per kafka$i..."
  keytool -keystore kafka$i.keystore.jks -alias kafka$i -validity 365 -genkey \
    -keyalg RSA -dname "CN=kafka$i,OU=CloudComputing,O=Unimi,L=Milan,C=IT" \
    -storepass $PASS -keypass $PASS

  # Richiesta di firma (CSR) estratta dal keystore
  keytool -keystore kafka$i.keystore.jks -alias kafka$i -certreq \
    -file kafka$i.csr -storepass $PASS

  # Firma del CSR con la CA
  openssl x509 -req -CA ca-cert -CAkey ca-key -in kafka$i.csr \
    -out kafka$i-cert-signed -days 365 -CAcreateserial -passin pass:$PASS

  # Import della CA nel keystore, così la catena di certificati è completa
  keytool -keystore kafka$i.keystore.jks -alias CARoot -import -noprompt \
    -file ca-cert -storepass $PASS

  # Import del certificato firmato nel keystore, sull'alias del nodo
  keytool -keystore kafka$i.keystore.jks -alias kafka$i -import -noprompt \
    -file kafka$i-cert-signed -storepass $PASS
done

# ------------------------------------------------------------------------------
# 4. Identità generica "client" (CN=ClientApp), usata dai comandi kafka-*.sh
#    e dai test iniziali. Stesso procedimento dei nodi.
# ------------------------------------------------------------------------------
echo "4. Generazione Keystore per il Client..."
keytool -keystore client.keystore.jks -alias client -validity 365 -genkey \
  -keyalg RSA -dname "CN=ClientApp,OU=CloudComputing,O=Unimi,L=Milan,C=IT" \
  -storepass $PASS -keypass $PASS

keytool -keystore client.keystore.jks -alias client -certreq \
  -file client.csr -storepass $PASS

openssl x509 -req -CA ca-cert -CAkey ca-key -in client.csr \
  -out client-cert-signed -days 365 -passin pass:$PASS

keytool -keystore client.keystore.jks -alias CARoot -import -noprompt \
  -file ca-cert -storepass $PASS

keytool -keystore client.keystore.jks -alias client -import -noprompt \
  -file client-cert-signed -storepass $PASS

# ------------------------------------------------------------------------------
# 5. Identità delle applicazioni del progetto: OrderProducer, OrderConsumer e
#    SecurityAdmin. Il DN di ciascuna deve coincidere con quello atteso dalla
#    dashboard (ACL automatiche) e con KAFKA_SUPER_USERS nel compose.
# ------------------------------------------------------------------------------
echo "5. Generazione Keystore per OrderProducer, OrderConsumer, SecurityAdmin..."
for ENTRY in \
  "OrderProducer:CN=OrderProducer,OU=IT,O=Cloud,L=Milano,C=IT" \
  "OrderConsumer:CN=OrderConsumer,OU=IT,O=Cloud,L=Milano,C=IT" \
  "SecurityAdmin:CN=SecurityAdmin,OU=IT,O=Cloud,L=Milano,C=IT"
do
  # Separa il nome dell'alias (prima dei due punti) dal DN (dopo i due punti)
  N="${ENTRY%%:*}"
  DN="${ENTRY#*:}"

  keytool -keystore $N.keystore.jks -alias $N -validity 365 -genkey \
    -keyalg RSA -dname "$DN" \
    -storepass $PASS -keypass $PASS

  keytool -keystore $N.keystore.jks -alias $N -certreq \
    -file $N.csr -storepass $PASS

  openssl x509 -req -CA ca-cert -CAkey ca-key -in $N.csr \
    -out $N-cert-signed -days 365 -CAcreateserial -passin pass:$PASS

  keytool -keystore $N.keystore.jks -alias CARoot -import -noprompt \
    -file ca-cert -storepass $PASS

  keytool -keystore $N.keystore.jks -alias $N -import -noprompt \
    -file $N-cert-signed -storepass $PASS
done

echo "✅ Generazione certificati completata con successo!"