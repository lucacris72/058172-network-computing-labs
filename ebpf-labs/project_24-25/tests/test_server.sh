export TARGET_IP_ADDR="10.0.0.1"
export TEST_PORT=54321

echo "Start listener socat on $TARGET_IP_ADDR:$TEST_PORT..."
socat TCP4-LISTEN:$TEST_PORT,bind=$TARGET_IP_ADDR,fork,reuseaddr -