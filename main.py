import requests
from flask import Flask, request, render_template, redirect, url_for, session
import hashlib
import uuid
import json
from flask_pymongo import PyMongo
from functools import wraps
import os
import nmap

app = Flask(__name__)
app.config['MONGO_URI'] = ''  # YOUR MONGODB URL
mongo = PyMongo(app)

API_KEY = 'YOUR IPGEOLOCATION.IO API KEY'
api = 'https://api.mojang.com/users/profiles/minecraft/'  # Mojang api
mcservstatus_api = 'https://api.mcsrvstat.us/2/'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # CHECK IF USER IS AUTHENTICATED
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VERIFY THE CREDENTIALS ON MONGODB
        user = mongo.db.users.find_one({'username': username, 'password': password})

        if user:
            # If login successful, define the user session
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            # Invalid credentials, show error message
            return 'Credenciais inválidas.'

    return render_template('login.html')


@app.route('/')
@login_required
def home():
    return render_template('index.html')


@app.route('/search')
@login_required
def search():
    return render_template('search.html')


@app.route('/get_ip', methods=['GET', 'POST'])
def get_ip():
    if request.method == 'POST':
        ip = request.form['ip_address']
        url = f'https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}'

        response = requests.get(url)
        data = response.json()

        if response.status_code == 200:
            ip_details = {
                'IP': data['ip'],
                'País': data['country_name'],
                'Estado/Província': data['state_prov'],
                'Cidade': data['city'],
                'Latitude': data['latitude'],
                'Longitude': data['longitude']
            }
            return redirect(url_for('show_ip_details', **ip_details))
        else:
            return 'An error occurred.'

    return render_template('search.html')


@app.route('/ip_details')
def show_ip_details():
    ip_details = request.args
    return render_template('ip_details.html', ip_details=ip_details)


def player_uuid(username):
    """
    Gets the following data from the minecraft username:
    > Online UUID
    > Offline UUID

    :param username: Username
    :return: UUID's
    """

    try:
        r = requests.get(f'{api}{username}')
        r_json = r.json()

        online_uuid = r_json['id']
        online_uuid = f'{online_uuid[0:8]}-{online_uuid[8:12]}-{online_uuid[12:16]}-{online_uuid[16:20]}-{online_uuid[20:32]}'
        offline_uuid = str(uuid.UUID(bytes=hashlib.md5(bytes(f'OfflinePlayer:{username}', 'utf-8')).digest()[:16], version=3))
        return online_uuid, offline_uuid

    except (json.JSONDecodeError, KeyError):
        offline_uuid = str(uuid.UUID(bytes=hashlib.md5(bytes(f'OfflinePlayer:{username}', 'utf-8')).digest()[:16], version=3))
        return None, offline_uuid


@app.route('/uuid-search')
@login_required
def uuid_search():
    return render_template('uuid_search.html')


@app.route('/uuid-results', methods=['POST'])
def uuid_results():
    username = request.form.get('username')

    if username:
        online_uuid, offline_uuid = player_uuid(username)
        return render_template('uuid_results.html', online_uuid=online_uuid, offline_uuid=offline_uuid)
    else:
        return 'It needs an username to work!.'


@app.route('/hostname')
@login_required
def hostname():
    return render_template('hostname.html')


@app.route('/get_numerical_ip', methods=['POST'])
def get_numerical_ip():
    hostname = request.form.get('hostname')

    if hostname:
        url = f'{mcservstatus_api}{hostname}'
        response = requests.get(url)
        data = response.json()

        if response.status_code == 200 and 'ip' in data:
            numerical_ip = data['ip']
            numerical_port = data['port']
            return redirect(url_for('show_hostname_results', numerical_ip=numerical_ip, numerical_port=numerical_port))
        else:
            return 'Unable to get numeric IP from the given hostname.'

    return 'You must provide a hostname.'


@app.route('/hostname-results')
def show_hostname_results():
    numerical_ip = request.args.get('numerical_ip')
    numerical_port = request.args.get('numerical_port')
    return render_template('hostname_results.html', numerical_ip=numerical_ip, numerical_port=numerical_port)

@app.route('/port_finder')
@login_required
def port_finder_form():
    return render_template('port_finder.html')

@app.route('/finder_result', methods=['POST'])
def port_finder_result():
    ip = request.form['ip']

    nm = nmap.PortScanner()
    nm.scan(ip, '0-65535')

    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)

    return render_template('finder_result.html', open_ports=open_ports)


if __name__ == '__main__':
    app.secret_key = 'Kb3MJu7I5Pq8rXvL9WgA2zYc' # Just type anything here
    app.run(port=5000, host='0.0.0.0', debug=False)
