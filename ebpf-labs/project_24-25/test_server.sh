# Scegli una porta su cui ascoltare, es. 8080
export TARGET_IP_ADDR="10.0.0.1"
export TEST_PORT=8080

# Questo comando mette socat in ascolto sulla porta $TEST_PORT.
# 'fork' permette di gestire più connessioni senza terminare.
# 'reuseaddr' permette di riavviare subito il listener.
# 'bind=' forza socat a legarsi a un IP specifico
echo "Avvio listener socat su $TARGET_IP_ADDR:$TEST_PORT..."
socat TCP4-LISTEN:$TEST_PORT,bind=$TARGET_IP_ADDR,fork,reuseaddr -