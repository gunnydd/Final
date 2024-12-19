import os
import sys
from dotenv import load_dotenv
from pathlib import Path


# 실행 파일 경로 설정
base_path = Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else Path(__file__).parent
# env 파일 경로 설정
env_path = base_path / "IP.env"
load_dotenv(dotenv_path=env_path)


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
    TV_RPI_MAPPING = {
        'TV1': os.getenv('TV1_IP'),
        'TV2': os.getenv('TV2_IP'),
        'TV3': os.getenv('TV3_IP'),
        'TV4': os.getenv('TV4_IP'),
        'TV5': os.getenv('TV5_IP')
    }
    TV_LOCATIONS = {
        'TV1': 'Lobby',
        'TV2': 'Electrode Room',
        'TV3': 'any room',
        'TV4': 'your room',
        'TV5': 'ks room'
    }

# For Debugging 
print(f"SECRET_KEY: {Config.SECRET_KEY}")
print(f"UPLOAD_FOLDER: {Config.UPLOAD_FOLDER}")
print(f"TV_RPI_MAPPING: {Config.TV_RPI_MAPPING}")
print(f"TV_LOCATIONS: {Config.TV_LOCATIONS}")
