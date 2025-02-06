import paho.mqtt.client as mqtt
import json
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import random
import os

CONFIG = {
    'device_id': 'jcz_001',
    'secret_key': 'your_secret_key_here',  # Must match the web client
    'topic_prefix': 'secure_jacuzzi/jcz_001/',
    'broker': 'test.mosquitto.org',
    'port': 1883
}

TOPICS = {
    'temperature': CONFIG['topic_prefix'] + 'temperature',
    'status': CONFIG['topic_prefix'] + 'status',
    'target_temp': CONFIG['topic_prefix'] + 'target_temperature',
    'initial_request': CONFIG['topic_prefix'] + 'initial_request'
}

def encrypt_message(message):
    """Encrypt message using AES"""
    # Ensure key is 32 bytes
    key = CONFIG['secret_key'].encode('utf-8').ljust(32, b'\0')
    
    # Generate IV
    iv = os.urandom(16)
    
    message_str = json.dumps(message)
    
    # Create cipher and encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message_str.encode('utf-8'), AES.block_size))
    
    # Create result object matching JavaScript format
    result = {
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ct_bytes).decode('utf-8')
    }
    
    return json.dumps(result)

def decrypt_message(encrypted_data):
    """Decrypt message using AES"""
    try:
        # Parse the encrypted data
        data = json.loads(encrypted_data)
        
        # Ensure key is 32 bytes
        key = CONFIG['secret_key'].encode('utf-8').ljust(32, b'\0')
        
        # Get IV and ciphertext
        iv = base64.b64decode(data['iv'])
        ciphertext = base64.b64decode(data['ciphertext'])
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        
        # Remove padding
        padding_length = padded_data[-1]
        unpadded_data = padded_data[:-padding_length]
        
        return json.loads(unpadded_data.decode('utf-8'))
    except Exception as e:
        print(f"Decryption error: {e}")
        print(f"Received data: {encrypted_data}")
        return None

def on_publish(client, userdata, mid):
    """Callback when a message is published"""
    print(f"Message {mid} published successfully")

class JacuzziSimulator:
    def __init__(self):
        self.current_temp = 38.0
        self.target_temp = 38.0
        self.heating_rate = 0.1  # °C per second
        self.cooling_rate = 0.05  # °C per second
        self.last_update = time.time()
        self.last_target_update_timestamp = 0 

    def update_temperature(self):
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now

        noise = random.uniform(-0.1, 0.1)

        if self.current_temp < self.target_temp:
            change = self.heating_rate * elapsed
            self.current_temp = min(self.target_temp, self.current_temp + change + noise)
        else:
            change = self.cooling_rate * elapsed
            self.current_temp = max(self.target_temp, self.current_temp - change + noise)

        return round(self.current_temp, 1)

def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")
    client.subscribe(TOPICS['target_temp'])
    client.subscribe(TOPICS['initial_request'])

def on_message(client, userdata, msg):
    try:
        simulator = userdata['simulator']
        decrypted = decrypt_message(msg.payload)
        print("Received message: ", decrypted)
        
        if msg.topic == TOPICS['initial_request']:
            current_temp = simulator.update_temperature()
            message = {
                'deviceId': CONFIG['device_id'],
                'value': current_temp,
                'target': simulator.target_temp,
                'timestamp': int(time.time() * 1000)
            }
            encrypted_message = encrypt_message(message)
            client.publish(TOPICS['temperature'], encrypted_message)
            return
            
        if msg.topic == TOPICS['target_temp']:
            message_timestamp = decrypted.get('timestamp', 0)
            if message_timestamp < simulator.last_target_update_timestamp:
                print(f"Ignoring outdated target temperature request (timestamp: {message_timestamp})")
                return

            new_target = float(decrypted['value'])
            if 35 <= new_target <= 40:
                simulator.target_temp = new_target
                simulator.last_target_update_timestamp = message_timestamp
                status_message = {
                    'deviceId': CONFIG['device_id'],
                    'type': 'target_temp_update',
                    'status': 'ok',
                    'message': new_target,
                    'timestamp': int(time.time() * 1000)
                }
            else:
                status_message = {
                    'deviceId': CONFIG['device_id'],
                    'type': 'target_temp_update',
                    'status': 'error',
                    'message': 'Temperature out of valid range (35-40°C)',
                    'timestamp': int(time.time() * 1000)
                }
            
            client.publish(TOPICS['status'], encrypt_message(status_message))
    except Exception as e:
        print(f"Error processing message: {e}")

def simulate_temperature(client, simulator):
    """Simulate temperature fluctuations"""
    while True:
        current_temp = simulator.update_temperature()
        
        message = {
            'deviceId': CONFIG['device_id'],
            'value': current_temp,
            'target': simulator.target_temp,
            'timestamp': int(time.time() * 1000)
        }
        
        encrypted_message = encrypt_message(message)
        client.publish(TOPICS['temperature'], encrypted_message)
        
        status_message = {
            'deviceId': CONFIG['device_id'],
            'status': 'heating' if current_temp < simulator.target_temp else 'idle',
            'timestamp': int(time.time() * 1000)
        }
        encrypted_status = encrypt_message(status_message)
        client.publish(TOPICS['status'], encrypted_status)
        
        print(f"Current: {current_temp}°C, Target: {simulator.target_temp}°C")
        time.sleep(2)

client = mqtt.Client(userdata={'simulator': JacuzziSimulator()})
client.on_connect = on_connect
client.on_message = on_message
client.on_publish = on_publish

print(f"Connecting to {CONFIG['broker']}...")
client.connect(CONFIG['broker'], CONFIG['port'], 60)

client.loop_start()

try:
    simulate_temperature(client, client._userdata['simulator'])
except KeyboardInterrupt:
    print("\nStopping simulation...")
    client.loop_stop()
    client.disconnect()
