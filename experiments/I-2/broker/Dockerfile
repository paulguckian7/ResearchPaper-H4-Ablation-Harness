FROM eclipse-mosquitto:2.0
RUN mosquitto_passwd -b -c /mosquitto/config/passwd source-t sourcet-pw \
 && mosquitto_passwd -b   /mosquitto/config/passwd source-c sourcec-pw \
 && mosquitto_passwd -b   /mosquitto/config/passwd receiver receiver-pw
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY acl.baseline.conf /mosquitto/config/acl.conf
COPY acl.ablated.conf /mosquitto/config/acl.ablated.conf
