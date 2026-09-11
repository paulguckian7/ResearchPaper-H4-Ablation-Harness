import json, os, sys, time
import paho.mqtt.client as mqtt

USER = os.environ.get("MQTT_USER", "source-t")
PASS = os.environ.get("MQTT_PASS", "sourcet-pw")
BROKER = os.environ.get("BROKER_HOST", "broker")

result = {"connected": False, "publish_rc": None, "puback_reason": None}

def on_connect(client, userdata, flags, rc, properties=None):
    result["connected"] = (rc == 0)

def on_publish(client, userdata, mid, reason_code=None, properties=None):
    result["puback_reason"] = str(reason_code) if reason_code is not None else "ok"

c = mqtt.Client(client_id=USER, protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
c.username_pw_set(USER, PASS)
c.on_connect = on_connect
c.on_publish = on_publish
c.connect(BROKER, 1883, 10)
c.loop_start()
time.sleep(1)
mode = sys.argv[1] if len(sys.argv) > 1 else "publish"
if mode == "clear":
    info = c.publish("test/topic", payload=None, qos=1, retain=True)
else:
    info = c.publish("test/topic", json.dumps({"test_value": 42}), qos=1, retain=True)
info.wait_for_publish(timeout=5)
result["publish_rc"] = info.rc
time.sleep(1)
c.loop_stop()
c.disconnect()
print(json.dumps(result))
