import requests
import time
import json
import os
from dotenv import load_dotenv

# .env dosyası yüklenir
load_dotenv()

# API anahtarını ortam değişkeninden alınır
API_KEY = os.getenv('VT_API_KEY')
API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
HEADERS = {'x-apikey': API_KEY}

# responses klasörü oluşturulur
os.makedirs('responses', exist_ok=True)

# IP’ler okunur
with open('ips.txt', 'r') as file:
    ips = [line.strip() for line in file if line.strip()]

# Her IP için sorgu gönderilir
for ip in ips:
    try:
        response = requests.get(API_URL + ip, headers=HEADERS)

        if response.status_code == 200:
            data = response.json()

            # Yanıtı responses klasörüne yazılır
            with open(f'responses/{ip}.json', 'w') as f:
                json.dump(data, f, indent=2)

            # zararlı mı diye kontrol edilir
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0 or suspicious > 0:
                with open('malicious_ips.txt', 'a') as m:
                    m.write(ip + '\n')

        elif response.status_code == 404:
            with open('not_found_ips.txt', 'a') as nf:
                nf.write(ip + '\n')

        # Rate limit: max 4 sorgu/dk → 16 saniye bekliyoruz 
        time.sleep(16)

    except Exception as e:
        print(f"Hata oluştu: {e}")
