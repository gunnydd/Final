import requests
import subprocess
import logging
import re
import asyncio
import aiohttp
import config
from requests.exceptions import ConnectTimeout, ConnectionError

import subprocess
import re
import logging




def ping(ip, attempts=4, timeout=1):
    logging.debug(f"Attempting to ping {ip} {attempts} times with {timeout} second(s) timeout each")
    success_count = 0
    
    for _ in range(attempts):
        try:
            response = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout * 1000), ip], 
                capture_output=True, 
                text=True
            )

            if response.returncode == 0:
                stdout = response.stdout
                logging.debug(f"Ping output for {ip}: {stdout}")
                
                if not re.search(r'Destination host unreachable|Request timed out|General failure', stdout):
                    success_count += 1
            else:
                logging.error(f"Ping command failed with return code {response.returncode} for {ip}")

        except UnicodeDecodeError:
            logging.error(f"Unicode decode error for ping response from {ip}")
        except Exception as e:
            logging.error(f"Failed to ping {ip}: {e}")

    logging.debug(f"Ping results for {ip}: {success_count}/{attempts} successes")
    return success_count > 0
    

async def upload_to_raspberry_pi(ip, file_stream, file_name):
    upload_url = f'http://{ip}:5001/upload'
    async with aiohttp.ClientSession() as session:
        data = aiohttp.FormData()
        data.add_field('file', file_stream, filename=file_name)
        try:
            async with session.post(upload_url, data=data, timeout=60) as response:
                response.raise_for_status()
                return response.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"Could not connect to {ip}: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Failed to upload file to {ip}: {str(e)}")
            return False

def display_on_raspberry_pi(tv_ip, file_name):
    url = f"http://{tv_ip}:5001/display"
    data = {'file_name': file_name}
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to display file on TV {tv_ip}: {e}")
        return False

async def control_tv(tv_ip, action):
    url = f"http://{tv_ip}:5001/tv_{action}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers={'Content-Type': 'application/json'}) as response:
                response.raise_for_status()
                return await response.json()
    except aiohttp.ClientError as e:
        logging.error(f"Failed to control TV {tv_ip}: {e}")
        return {'error': f"Failed to control TV {tv_ip}: {e}"}

def display_emergency_message(tv_ip, message):
    url = f"http://{tv_ip}:5001/emergency"
    payload = {'message': message}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send emergency message to {tv_ip}: {e}")
        return False

def update_pi_status(tv_rpi_mapping, raspberry_pi_status):
    for tv_key, ip in tv_rpi_mapping.items():
        if ip is None:
            logging.error(f"IP for {tv_key} is None.")
            continue
        if ping(ip):
            raspberry_pi_status[ip] = 'online'
        else:
            raspberry_pi_status[ip] = 'offline'
    logging.info(f"Updated Raspberry Pi status: {raspberry_pi_status}")
