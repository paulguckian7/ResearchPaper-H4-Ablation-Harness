import json, os, sys, time
import paho.mqtt.client as mqtt

USER = os.environ.get("MQTT_USER", "source-t")
PASS = os.environ.get("MQTT_PASS", "sourcet-pw")
BROKER = os.environ.get("BROKER_HOST", "broker")

result = {"connected": False, "publish_rc": None, "puback_reason_value": None, "puback_reason_str": None}

def on_connect(client, userdata, flags, rc, properties=None):
    result["connected"] = (rc == 0)

def on_publish(client, userdata, mid, reason_code=None, properties=None):
    # An earlier version stored only str(reason_code) and the caller
    # (run_i2.py) matched that string against ("0","ok",None) -- fragile,
    # and never verified against a real paho-mqtt ReasonCode object
    # (this repo has no network access to install paho-mqtt and check).
    # Fixed to use the ReasonCode's documented .value integer instead of
    # its string form: 0 is always Success for PUBACK across paho-mqtt's
    # MQTTv5 reason codes, whatever the __str__ output happens to be.
    # No reason_code at all (MQTTv3-style, or QoS 0) is treated as
    # success, matching paho-mqtt's semantics for those cases. Both the
    # numeric value AND the raw string are recorded, specifically so a
    # human can see what actually came back rather than trust this
    # parsing blindly -- see the "PUBACK RAW" print below.
    if reason_code is None:
        result["puback_reason_value"] = 0
        result["puback_reason_str"] = "ok (no reason code)"
    else:
        result["puback_reason_value"] = getattr(reason_code, "value", reason_code)
        result["puback_reason_str"] = str(reason_code)

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
print("PUBACK RAW:", json.dumps({
    "puback_reason_value": result["puback_reason_value"],
    "puback_reason_str": result["puback_reason_str"]
}), file=sys.stderr)
print(json.dumps(result))
