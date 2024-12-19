import os
import logging
import asyncio
import aiohttp
import requests
import sys
import ssl
import io

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from apscheduler.triggers.interval import IntervalTrigger
from pytz import utc
from io import BytesIO
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from pathlib import Path  
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, flash, send_file, make_response
from concurrent.futures import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.base import JobLookupError
from apscheduler.triggers.date import DateTrigger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import db, User, ActivityLog, UploadLog, ScheduleLog  
import utils  

base_path = Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else Path(__file__).parent

app = Flask(__name__, template_folder=os.path.join(base_path, 'templates'))
app.secret_key = Config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_COOKIE_SECURE'] = False  # 실제 서버에서는 True로 설정
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # 실제 서버에서는 True로 설정

jwt = JWTManager(app)
db.init_app(app)

with app.app_context():
    db.create_all()

    # 관리자 계정이 없다면 생성
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', is_admin=True, is_approved=True)
        admin.set_password('admin_password')  # 관리자 비밀번호 설정
        db.session.add(admin)
        db.session.commit()

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

raspberry_pi_status = {ip: 'unknown' for ip in Config.TV_RPI_MAPPING.values()}

async def async_post_request(url):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, headers={'Content-Type': 'application/json'}) as response:
                response.raise_for_status()
                return await response.json()
        except aiohttp.ClientError as e:
            logging.error(f"Failed to make POST request to {url}: {e}")
            return {'error': f"Failed to make POST request to {url}: {e}"}


def run_async(func):
    async def wrapper(*args, **kwargs):
        await func(*args, **kwargs)
    def wrapped(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(wrapper(*args, **kwargs))
        finally:
            loop.close()
    return wrapped

def update_pi_status():
    global raspberry_pi_status
    for tv_key, ip in Config.TV_RPI_MAPPING.items():
        if ip is None:
            logging.error(f"IP for {tv_key} is None.")
            continue
        if utils.ping(ip):
            raspberry_pi_status[ip] = 'online'
        else:
            raspberry_pi_status[ip] = 'offline'
    logging.info(f"Updated Raspberry Pi status: {raspberry_pi_status}")


scheduler = BackgroundScheduler()
scheduler.add_job(update_pi_status, 'interval', minutes=1)
scheduler.start()

async def fetch_tv_status(session, tv_ip):
    url = f"http://{tv_ip}:5001/tv_status"
    try:
        async with session.get(url, timeout=10) as response:
            response.raise_for_status()
            return await response.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.error(f"Failed to get status from TV {tv_ip}: {e}")
        return {'status': 'unknown'}

async def fetch_current_file(session, tv_ip):
    url = f"http://{tv_ip}:5001/current_file"
    try:
        async with session.get(url, timeout=5) as response:
            response.raise_for_status()
            return await response.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.error(f"Failed to get current file from TV {tv_ip}: {e}")
        return {'current_file': 'unknown'}

async def get_all_tv_stats():
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_tv_status(session, ip) for ip in Config.TV_RPI_MAPPING.values()]
        status_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        tasks = [fetch_current_file(session, ip) for ip in Config.TV_RPI_MAPPING.values()]
        file_results = await asyncio.gather(*tasks, return_exceptions=True)

        stats = {}
        for i, tv in enumerate(Config.TV_RPI_MAPPING.keys()):
            status = status_results[i].get('status', 'unknown') if not isinstance(status_results[i], Exception) else 'unknown'
            current_file = file_results[i].get('current_file', 'unknown') if not isinstance(file_results[i], Exception) else 'unknown'
            stats[tv] = {
                'location': Config.TV_LOCATIONS.get(tv, 'Unknown'),
                'status': status,
                'current_file': current_file
            }

        return stats

def log_activity(user_id, activity):
    log = ActivityLog(user_id=user_id, activity=activity)
    db.session.add(log)
    db.session.commit()

MAX_LOGIN_ATTEMPTS = 5

@app.before_request
def check_login():
    if request.endpoint not in ['login', 'register', 'static'] and not request.path.startswith('/static'):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user.is_approved:
                return redirect(url_for('login'))
        except:
            return redirect(url_for('login'))

@app.route('/')
def home():
    try:
        verify_jwt_in_request()
        return redirect(url_for('index'))
    except:
        return redirect(url_for('login'))

@app.route('/index')
@jwt_required()
def index():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()

        if user:
            if user.is_locked:
                flash('Your account is locked due to too many failed login attempts.', 'danger')
                return redirect(url_for('login'))

            if user.check_password(password):
                if not user.is_approved:
                    flash('Your account is not approved yet.', 'danger')
                    return redirect(url_for('login'))

                access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))
                response = make_response(redirect(url_for('index')))
                set_access_cookies(response, access_token)
                flash('Logged in successfully', 'success')
                # 로그인 성공 시 로그인 시도 횟수 초기화 및 활동 로그 기록
                user.login_attempts = 0
                db.session.commit()
                log_activity(user.id, 'Logged in')
                return response
            else:
                # 관리자 계정인 경우 로그인 시도 횟수와 계정 잠금을 무시
                if not user.is_admin:
                    user.login_attempts += 1
                    if user.login_attempts >= MAX_LOGIN_ATTEMPTS:
                        user.is_locked = True
                        log_activity(user.id, 'Account locked due to too many failed login attempts')
                        flash('Your account has been locked due to too many failed login attempts.', 'danger')
                    db.session.commit()
                flash('Invalid username or password', 'danger')
        else:
            flash('Invalid username or password', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    user_id = get_jwt_identity()
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    flash('Logged out successfully', 'success')
    # 활동 로그 기록
    log_activity(user_id, 'Logged out')
    return response

@app.route('/approve_users', methods=['GET'])
@jwt_required()
def approve_users():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.filter_by(is_approved=False).all()
    return render_template('approve_users.html', users=users)

@app.route('/admin_dashboard')
@jwt_required()
def admin_dashboard():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html')

@app.route('/approve_user/<int:user_id>', methods=['POST'])
@jwt_required()
def approve_user(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    
    user_to_approve = User.query.get(user_id)
    if user_to_approve:
        user_to_approve.is_approved = True
        db.session.commit()
    return redirect(url_for('approve_users'))

@app.route('/unlock_user/<int:user_id>', methods=['POST'])
@jwt_required()
def unlock_user(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    user_to_unlock = User.query.get(user_id)
    if user_to_unlock:
        user_to_unlock.is_locked = False
        user_to_unlock.login_attempts = 0  # 로그인 시도 횟수 초기화
        db.session.commit()
        flash(f"User {user_to_unlock.username} unlocked", 'success')
    else:
        flash('User not found', 'danger')
    
    return redirect(url_for('unlock_users'))



@app.route('/unlock_users')
@jwt_required()
def unlock_users():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    locked_users = User.query.filter_by(is_locked=True).all()
    return render_template('unlock_users.html', locked_users=locked_users)


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify(logged_in_as=user.username), 200




@app.route('/upload', methods=['GET'])
def upload():
    return render_template('upload.html', available_tvs=Config.TV_RPI_MAPPING, TV_LOCATIONS=Config.TV_LOCATIONS)

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']
    selected_tvs = request.form.getlist('tvs')
    if file.filename == '' or not selected_tvs:
        flash('No selected file or TVs', 'danger')
        return redirect(request.url)

    valid_extensions = {'.pptx', '.jpg', '.jpeg', '.mp4', '.avi'}
    if not any(file.filename.endswith(ext) for ext in valid_extensions):
        flash('Only .pptx, .jpg, .jpeg, .mp4, and .avi files are allowed', 'danger')
        return redirect(request.url)

    messages = []
    errors = []

    # 파일을 메모리에 저장
    file_content = file.read()

    async def upload_to_all_tvs():
        for tv_key in selected_tvs:
            tv_ip = Config.TV_RPI_MAPPING.get(tv_key)
            success = await utils.upload_to_raspberry_pi(tv_ip, BytesIO(file_content), file.filename)
            if success:
                logging.info(f"Uploaded file to TV {tv_ip}")
                messages.append(f"File uploaded to TV {tv_ip}")
            else:
                logging.error(f"Failed to upload file to TV {tv_ip}")
                errors.append(f"Failed to upload file to TV {tv_ip}")

    asyncio.run(upload_to_all_tvs())

    logging.info(f"User '{request.remote_addr}' uploaded file '{file.filename}'")  # 업로드 기록
    # 데이터베이스에 업로드 기록 저장
    user_id = get_jwt_identity()
    status = 'success' if not errors else 'failure'
    upload_log = UploadLog(user_ip=request.remote_addr, filename=file.filename, user_id=user_id, status=status)
    db.session.add(upload_log)
    db.session.commit()

    for message in messages:
        flash(message, 'success')
    for error in errors:
        flash(error, 'danger')

    return redirect(url_for('upload'))
 

@app.route('/display', methods=['POST'])
def display_file():
    data = request.get_json()
    tv_ip = data.get('ip')
    file_name = data.get('file_name')
    response = utils.display_on_raspberry_pi(tv_ip, file_name)
    if response:
        return jsonify({'message': f"File '{file_name}' is being displayed on TV {tv_ip}"}), 200
    else:
        return jsonify({'error': f"Failed to display file '{file_name}' on TV {tv_ip}"}), 500

@app.route('/tv_on', methods=['POST'])
def tv_on():
    data = request.get_json()
    ip = data.get('ip')

    if not ip:
        return jsonify({'error': 'No IP provided'}), 400

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    response = loop.run_until_complete(utils.control_tv(ip, 'on'))
    loop.close()

    if 'error' in response:
        return jsonify(response), 500

    return jsonify({'message': 'TV turned on and HDMI input switched'}), 200

@app.route('/tv_off', methods=['POST'])
def tv_off():
    data = request.get_json()
    ip = data.get('ip')

    if not ip:
        return jsonify({'error': 'No IP provided'}), 400

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    response = loop.run_until_complete(utils.control_tv(ip, 'off'))
    loop.close()

    if 'error' in response:
        return jsonify(response), 500

    return jsonify({'message': 'TV turned off'}), 200

@app.route('/tv_controls', methods=['GET'])
def tv_controls():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    statuses = loop.run_until_complete(get_all_tv_stats())

    return render_template('tv_controls.html', available_tvs=Config.TV_RPI_MAPPING, statuses=statuses, TV_LOCATIONS=Config.TV_LOCATIONS)

@app.route('/stats', methods=['GET'])
def stats():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tv_stats = loop.run_until_complete(get_all_tv_stats())

    return render_template('stats.html', tv_stats=tv_stats.items(), TV_LOCATIONS=Config.TV_LOCATIONS)

@app.route('/delete', methods=['POST'])
def delete_file():
    data = request.get_json()
    file_name = data.get('file_name')
    tv_ip = data.get('ip')

    if not file_name or not tv_ip:
        return jsonify({'error': 'No file name or IP provided'}), 400

    response = utils.delete_from_raspberry_pi(tv_ip, file_name)
    if response:
        logging.info(f"File '{file_name}' successfully deleted from {tv_ip}")
        return jsonify({'message': f'File {file_name} successfully deleted from {tv_ip}'}), 200
    else:
        return jsonify({'error': f'Failed to delete file {file_name} from {tv_ip}'}), 500

@app.route('/list_files', methods=['GET'])
def list_files():
    tv_ip = request.args.get('ip')
    if not tv_ip:
        return jsonify({'error': 'No IP provided'}), 400

    files = utils.list_files_on_raspberry_pi(tv_ip)
    return jsonify(files), 200

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    tv_ip = request.args.get('ip')
    if not tv_ip:
        return jsonify({'error': 'No IP provided'}), 400

    file_content = utils.download_from_raspberry_pi(tv_ip, filename)
    if file_content:
        return send_file(
            io.BytesIO(file_content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename  # `attachment_filename`은 Flask >= 2.0에서는 `download_name`으로 변경되었습니다.
        )
    else:
        return jsonify({'error': f'Failed to download file {filename} from {tv_ip}'}), 500

@app.route('/schedule', methods=['GET'])
def schedule():
    available_tvs = list(Config.TV_RPI_MAPPING.keys())
    return render_template('schedule.html', available_tvs=available_tvs, TV_LOCATIONS=Config.TV_LOCATIONS)

@app.route('/schedule', methods=['POST'])
def schedule_file():
    file = request.files.get('file')
    display_date = request.form.get('display_date')
    display_time = request.form.get('display_time')
    selected_tvs = request.form.getlist('tvs')

    if not file or file.filename == '' or not selected_tvs:
        flash('No selected file or TVs or invalid date/time', 'danger')
        return redirect(request.url)

    valid_extensions = {'.pptx', '.jpg', '.jpeg', '.mp4', '.avi'}
    if not any(file.filename.endswith(ext) for ext in valid_extensions):
        flash('Only .pptx, .jpg, .jpeg, .mp4, and .avi files are allowed', 'danger')
        return redirect(request.url)

    logging.info(f"User '{request.remote_addr}' scheduled file '{file.filename}' for {display_date} {display_time} on TVs: {', '.join(selected_tvs)}")  # 스케줄 기록

    # 문자열을 datetime 객체로 변환
    schedule_datetime = datetime.strptime(f'{display_date} {display_time}', '%Y-%m-%d %H:%M')

    # 파일을 메모리에 저장
    file_content = file.read()

    async def scheduled_replace_and_update(tv_ip, file_content, file_name):
        file_stream = BytesIO(file_content)
        file_stream.seek(0)
        success = await utils.upload_to_raspberry_pi(tv_ip, file_stream, file_name)
        if success:
            logging.info(f"Scheduled replacement for TV {tv_ip}")
        else:
            logging.error(f"Failed scheduled replacement for TV {tv_ip}")

    user_id = get_jwt_identity()  # JWT에서 사용자 ID 가져오기

    for tv_key in selected_tvs:
        tv_ip = Config.TV_RPI_MAPPING.get(tv_key)
        job = scheduler.add_job(
            run_async(scheduled_replace_and_update),  # 비동기 함수 래핑
            trigger=DateTrigger(run_date=schedule_datetime),  # datetime 객체 사용
            args=[tv_ip, file_content, file.filename]
        )

        # 데이터베이스에 스케줄 기록 저장
        schedule_log = ScheduleLog(
            job_id=job.id,  # job ID 저장
            user_ip=request.remote_addr,
            filename=file.filename,
            schedule_time=schedule_datetime,
            tvs=', '.join(selected_tvs),
            user_id=user_id
        )
        db.session.add(schedule_log)

    db.session.commit()
    flash('File scheduled successfully', 'success')
    return redirect(url_for('schedule'))


@app.route('/jobs', methods=['GET'])
def jobs():
    scheduled_jobs = []
    for job in scheduler.get_jobs():
        job_id = job.id
        next_run_time = job.next_run_time
        if job.args:
            tv_ip = job.args[0]
            file_content = job.args[1]
            file_name = job.args[2]
            scheduled_jobs.append({
                'id': job_id,
                'next_run_time': next_run_time,
                'tv': tv_ip,
                'file_name': file_name
            })
    return render_template('jobs.html', scheduled_jobs=scheduled_jobs, available_tvs=Config.TV_RPI_MAPPING, TV_LOCATIONS=Config.TV_LOCATIONS)

@app.route('/modify_job', methods=['POST'])
def modify_job():
    job_id = request.form.get('job_id')
    display_date = request.form.get('display_date')
    display_time = request.form.get('display_time')
    selected_tvs = request.form.getlist('tvs')
    file = request.files.get('file')

    if not job_id or not display_date or not display_time or not selected_tvs or not file:
        flash('Missing required fields', 'danger')
        return redirect(url_for('jobs'))

    valid_extensions = {'.pptx', '.jpg', '.jpeg', '.mp4', '.avi'}
    if not any(file.filename.endswith(ext) for ext in valid_extensions):
        flash('Only .pptx, .jpg, .jpeg, .mp4, and .avi files are allowed', 'danger')
        return redirect(request.url)

    # 문자열을 datetime 객체로 변환
    schedule_datetime = datetime.strptime(f'{display_date} {display_time}', '%Y-%m-%d %H:%M')

    # 파일을 메모리에 저장
    file_content = file.read()

    async def scheduled_replace_and_update(tv_ip, file_content, file_name):
        file_stream = BytesIO(file_content)
        file_stream.seek(0)
        success = await utils.upload_to_raspberry_pi(tv_ip, file_stream, file_name)
        if success:
            logging.info(f"Scheduled replacement for TV {tv_ip}")
        else:
            logging.error(f"Failed scheduled replacement for TV {tv_ip}")

    try:
        # 기존 job 삭제
        scheduler.remove_job(job_id)
    except JobLookupError:
        flash(f"No job found with ID: {job_id}", 'danger')
        return redirect(url_for('jobs'))

    new_jobs = []
    for tv_key in selected_tvs:
        tv_ip = Config.TV_RPI_MAPPING.get(tv_key)
        job = scheduler.add_job(
            run_async(scheduled_replace_and_update),  # 비동기 함수 래핑
            trigger=DateTrigger(run_date=schedule_datetime),  # datetime 객체 사용
            args=[tv_ip, file_content, file.filename]
        )
        new_jobs.append(job.id)

    # 데이터베이스에서 기존 스케줄 기록 업데이트
    job_record = ScheduleLog.query.filter_by(job_id=job_id).first()
    if job_record:
        job_record.job_id = new_jobs[0]  # 새로운 job ID로 업데이트
        job_record.schedule_time = schedule_datetime
        job_record.filename = file.filename
        job_record.tvs = ', '.join(selected_tvs)
        db.session.commit()

    flash('Job modified successfully', 'success')
    return redirect(url_for('jobs'))


@app.route('/delete_job', methods=['POST'])
def delete_job():
    job_id = request.form.get('job_id')
    
    try:
        # APScheduler에서 job 삭제
        scheduler.remove_job(job_id)
        flash(f"Deleted Job: {job_id}", 'success')
        
        # 데이터베이스에서 job 기록 삭제
        job_record = ScheduleLog.query.filter_by(job_id=job_id).first()
        if job_record:
            db.session.delete(job_record)
            db.session.commit()
            flash(f"Deleted job record from database: {job_id}", 'success')
        else:
            flash(f"No job record found in database with ID: {job_id}", 'danger')
        
    except JobLookupError:
        flash(f"No job found with ID: {job_id}", 'danger')
    
    return redirect(url_for('jobs'))

@app.route('/display_emergency', methods=['GET', 'POST'])
def display_emergency():
    if request.method == 'POST':
        message = request.form.get('message')
        selected_tvs = request.form.getlist('tvs')

        if not message or not selected_tvs:
            flash('Message and TVs are required', 'danger')
            return redirect(request.url)

        errors = []
        for tv_key in selected_tvs:
            tv_ip = Config.TV_RPI_MAPPING.get(tv_key)
            if not utils.display_emergency_message(tv_ip, message):
                errors.append(f"Failed to display emergency message on {tv_key}")

        if errors:
            for error in errors:
                flash(error, 'danger')
        else:
            flash('Emergency message displayed successfully', 'success')

        return redirect(request.url)

    return render_template('display_emergency.html', available_tvs=Config.TV_RPI_MAPPING, TV_LOCATIONS=Config.TV_LOCATIONS)

@app.route('/reboot', methods=['POST'])
def reboot_raspberry_pi():
    data = request.get_json()
    ip = data.get('ip')
    url = f"http://{ip}:5001/reboot"

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    response = loop.run_until_complete(async_post_request(url))
    loop.close()

    if 'error' in response:
        return jsonify(response), 500
    return jsonify({'message': 'Reboot initiated successfully'}), 200
    
@app.route('/shutdown', methods=['POST'])
def shutdown_raspberry_pi():
    data = request.get_json()
    ip = data.get('ip')
    url = f"http://{ip}:5001/shutdown"

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    response = loop.run_until_complete(async_post_request(url))
    loop.close()

    if 'error' in response:
        return jsonify(response), 500
    return jsonify({'message': 'Shutdown initiated successfully'}), 200

@app.route('/status', methods=['GET'])
def get_status():
    return jsonify(raspberry_pi_status)

@app.route('/admin/logs/upload_logs', methods=['GET'])
@jwt_required()
def view_upload_logs():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    search_query = request.args.get('search', '')
    user_filter = request.args.get('user_filter', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 페이지 당 항목 수

    query = UploadLog.query.filter(
        (UploadLog.filename.contains(search_query)) | 
        (UploadLog.user_id.contains(search_query))
    )

    if user_filter:
        query = query.filter_by(user_id=user_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    upload_logs = pagination.items

    users = User.query.all()  # 모든 사용자 목록을 가져옴

    return render_template('upload_logs.html', upload_logs=upload_logs, pagination=pagination, search_query=search_query, user_filter=user_filter, users=users)


@app.route('/admin/logs/activity_logs', methods=['GET'])
@jwt_required()
def view_activity_logs():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    search_query = request.args.get('search', '')
    user_filter = request.args.get('user_filter', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 페이지 당 항목 수

    query = ActivityLog.query.filter(
        (ActivityLog.activity.contains(search_query)) | 
        (ActivityLog.user_id.contains(search_query))
    )

    if user_filter:
        query = query.filter_by(user_id=user_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    activity_logs = pagination.items

    users = User.query.all()  # 모든 사용자 목록을 가져옴

    return render_template('activity_logs.html', activity_logs=activity_logs, pagination=pagination, search_query=search_query, user_filter=user_filter, users=users)

@app.route('/admin/logs/schedule_logs', methods=['GET'])
@jwt_required()
def view_schedule_logs():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    search_query = request.args.get('search', '')
    user_filter = request.args.get('user_filter', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 페이지 당 항목 수

    query = ScheduleLog.query.filter(
        (ScheduleLog.filename.contains(search_query)) | 
        (ScheduleLog.user_id.contains(search_query))
    )

    if user_filter:
        query = query.filter_by(user_id=user_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    schedule_logs = pagination.items

    users = User.query.all()  # 모든 사용자 목록을 가져옴

    return render_template('schedule_logs.html', schedule_logs=schedule_logs, pagination=pagination, search_query=search_query, user_filter=user_filter, users=users)


@app.route('/admin/logs/users', methods=['GET'])
@jwt_required()
def view_users():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('users.html', users=users)


if __name__ == "__main__":
    from waitress import serve
    serve(app, host='0.0.0.0', port=8080)