"""One-shot subscriber: connects, waits briefly for one message, records
whether it arrived, and writes results to a shared file the runner reads
via docker exec cat. This is a receiver's own /state-equivalent, since
mosquitto itself has no query API for 'did receiver X get message Y'."""
import json, os, time
import paho.mqtt.client as mqtt

BROKER = os.environ.get("BROKER_HOST", "broker")
received = {"got_message": False, "payload": None}

def on_message(client, userdata, msg):
    received["got_message"] = True
    received["payload"] = msg.payload.decode()

c = mqtt.Client(client_id="receiver", protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
c.username_pw_set("receiver", "receiver-pw")
c.on_message = on_message
c.connect(BROKER, 1883, 10)
c.subscribe("test/topic", qos=1)
c.loop_start()
time.sleep(3)
c.loop_stop()
c.disconnect()

with open("/tmp/result.json", "w") as f:
    json.dump(received, f)
print(json.dumps(received))
