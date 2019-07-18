from flask import Flask, request, Response
from flask_restful import Api, Resource
from flask import jsonify
from operator import itemgetter
import mysql.connector
from datetime import datetime
# import math
from math import sin, cos, sqrt, atan2, radians
import re
# import os.path
from validate_email import validate_email
import hashlib
import uuid
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pymysql
from flask_sqlalchemy import SQLAlchemy
import geopy.distance
from flask_cors import CORS
from collections import defaultdict


# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# db_path = os.path.join(BASE_DIR, "DoctorApiData.db")


LONG_MILES = 53
LAT_MILES = 69
LONG_KM = 85
LAT_KM = 111
DEG_LONG_PER_MILE = 1 / LONG_MILES
DEG_LAT_MILES_PER = 1 / LAT_MILES
DEG_LONG_PER_KM = 1 / LONG_KM
DEG_LAT_PER_KM = 1 / LAT_KM
# API_ERRORS_PATH = "C:/Users/ronkn/OneDrive - Orasi Software/Orasi_Data Files/DoctorAPI/ApiErrors.txt"
# connections_string_path = "C:/Users/ronkn/OneDrive - Orasi Software/Orasi_Data Files/DoctorAPI/Connections.txt"

ip_addresses = {}

application = app = Flask(__name__)
CORS(app)
api = Api(app)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:TrickyPassword@localhost/DoctorDb'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ronknighton@doctor-api-db-svr:R0na!d1966@doctor-api-db-svr.mysql.database.azure.com/doctordb'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ronknighton:R0na!d1966@doctorapi-db.ceztmqgtoqb1.us-east-2.rds.amazonaws.com/doctordb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)


def send_email(email, message):
    try:
        sender = smtplib.SMTP(host='smtp.gmail.com', port=587)
        sender.starttls()
        sender.login('orasiapi@gmail.com', 'Orasi123')
        # sender.login('WestonPythonTinker@gmail.com', '@Pyth0nRul3z')
        msg = MIMEMultipart()
        msg['From'] = 'orasiapi@gmail.com'
        # msg['From'] = 'WestonPythonTinker@gmail.com'
        msg['To'] = email
        msg['Subject'] = "A message from Orasi API"
        body = message
        msg.attach(MIMEText(body, 'html'))
        sender.send_message(msg)
        del msg
        sender.quit()
        return "Email sent"
    except Exception as e:
        return "Email NOT sent: " + str(e)


def convert_to_radians(value):
    return radians(value)


def get_distance_geopy(long_1, lat_1, long_2, lat_2):
    coords_1 = (lat_1, long_1)
    coords_2 = (lat_2, long_2)
    distance = geopy.distance.distance(coords_1, coords_2).miles
    return distance


# This formula returns bad distances
def get_distance(long_1, lat_1, long_2, lat_2):
    dlong = convert_to_radians(long_2) - convert_to_radians(long_1)
    dlat = convert_to_radians(lat_2) - convert_to_radians(lat_1)
    a = (sin(dlat / 2)) ** 2 + cos(lat_1) * cos(lat_2) * (sin(dlong / 2)) ** 2
    # c = 2 * sin(min(1, sqrt(a)))
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = 3956 * c
    return distance


def get_comments_by_npi(this_npi, con):
    # comments = con.execute("SELECT * FROM Comments where NPI =" + this_npi).fetchall()
    start_time = datetime.now()
    comments = con.execute("SELECT Id, NPI, Comment, Created, User_Id FROM doctordb.comments where NPI = '" + this_npi + "'").fetchall()
    end_time = datetime.now()
    elapsed_time = end_time - start_time
    print("Get " + str(len(comments)) + " comments for NPI: " + str(this_npi) + ", Time: " + str(elapsed_time))
    return make_comment_list(comments)


def get_provider_comments(providers, npi_list, con):
    npi_tuple = tuple(npi_list)
    if len(npi_tuple) == 1:
        comment_query = "SELECT * FROM doctordb.comments where NPI =" + "'" + str(npi_tuple[0]) + "'"
    else:
        comment_query = "SELECT * FROM doctordb.comments where NPI IN {}".format(npi_tuple)
    comments = con.execute(comment_query).fetchall()
    comments = make_comment_list(comments)
    comment_list = []
    for comment in comments:
        comment_list.append([comment['NPI'], comment])

    comment_dict = defaultdict(list)
    for key, comment in comment_list:
        comment_dict[key].append(comment)

    for doc in providers:
        doc.update({'Comments': comment_dict[doc['NPI']]})

    return providers


def send_return_response(message, error):
    response = jsonify({'message': message})
    response.status_code = error
    return response


def is_npi_good(code):
    if code is None:
        return False
    if len(code) != 10 or not code.isdigit():
        return False
    else:
        return True


def is_postal_code_good(code):
    if code is None:
        return False
    if len(code) != 5 or not code.isdigit():
        return False
    else:
        return True


def is_radius_good(radius):
    if radius is None:
        return False
    if not radius.isdigit() or int(radius) > 50:
        return False
    else:
        return True


def is_taxonomy_good(tax):
    if tax is None:
        return False
    if len(tax) != 10:
        return False
    if tax != '':
        first_three = tax[:3]
        last_three = tax[-4:-1]
        # three = int(last_three)
        # print(three)
        if not first_three.isdigit():
            return False
        elif not last_three.isdigit():
            return False
        else:
            return True


def is_string_good(word, length=35):
    if word is None:
        return False
    if len(word) > length:
        return False
    elif not re.match(r'^\w+$', word):
        return False
    else:
        return True


def is_phrase_good(phrase, length=35):
    if phrase is None:
        return False
    if len(phrase) > length:
        return False
    phrase_list = phrase.split(' ')
    for word in phrase_list:
        if not is_string_good(word):
            return False
    return True


def is_comment_good(comment):
    if comment is None:
        return False
    if comment != '':
        length = len(comment)
        if length > 455:
            return False
        words = comment.split(' ')
        for line in words:
            line = line.replace(',', '')
            line = line.replace('.', '')
            line = line.replace('!', '')
            if not re.match(r'^\w+$', line):
                return False
    return True


def filter_message(message, length=50):
    message = message[:length]
    filtered = ""
    for line in message.split('\n'):
        line = re.sub(r"[^a-zA-Z0-9]+", ' ', line)
        filtered += line + '\n'
    return filtered


def build_zip_query(long, lat, dist):
    query = "SELECT * FROM (SELECT *,(((acos(sin((" + str(lat) + "*pi()/180)) * sin((Latitude*pi()/180))" \
            "+cos((" + str(lat) + "*pi()/180)) * cos((Latitude*pi()/180)) * cos(((" + str(long) + " - Longitude)" \
            "*pi()/180))))*180/pi())*60*1.1515*1.609344) as distance FROM doctordb.postalcodes) t WHERE distance <= " + str(dist)
    return query


def check_email(email):
    if email is None:
        return False
    return validate_email(email)


def validate_user_timestamp(email, con):
    if not check_email(email):
        return False
    else:

        str_id = str(id)
        query = "Select * From doctordb.users Where Email = :email"
        user = con.execute(query, {'email': email}).fetchall()

        if len(user) == 0:
            return False
        else:
            now = datetime.now()
            login_time = user[0][6]
            if login_time is None:
                return False
            logged_in = user[0][7]
            verified = user[0][8]
            if not logged_in or not verified:
                return False
            elapsed_time = now - login_time
            # Allows 1 hour for posting/editing/deleting comments
            hours = elapsed_time.seconds / 3600
            if hours > 1:
                return False
            return True


def get_user_id_by_email(email, con):
    if not check_email(email):
        return -1

    query = "Select * From doctordb.users Where Email = :email"
    users = con.execute(query, {'email': email}).fetchall()

    if len(users) == 0:
        return -1
    logged_in = users[0][7]
    verified = users[0][8]
    if not logged_in or not verified:
        return -1
    id = users[0][0]
    return id


def validate_comment_user(email, comment_id, con):
    if not validate_user_timestamp(email, con):
        return -1
    else:
        if not comment_id.isdigit():
            return -1
        user_id = get_user_id_by_email(email, con)

        str_comment_id = str(comment_id)
        query = "Select * From doctordb.comments Where Id = :id"
        comments = con.execute(query, {'id': str_comment_id}).fetchall()

        if len(comments) == 0:
            return -1
        temp_user_id = comments[0][4]
        if temp_user_id != int(user_id):
            return -1
        else:
            return user_id


def validate_password(password, length=15):
    if len(password) > length:
        return False
    spaces = re.findall(' ', password)
    if len(spaces) > 0:
        return False
    else:
        return True


def is_email_available(email, con):
    if not check_email(email):
        return False

    query = "Select * From doctordb.users Where Email = :email"
    users = con.execute(query, {'email': email}).fetchall()
    if len(users) == 0:
        return True
    else:
        return False


def is_api_email_available(email, con):
    if not check_email(email):
        return False
    query = "Select * From doctordb.apiusers Where Email = :email"
    users = con.execute(query, {'email': email}).fetchall()
    if len(users) == 0:
        return True
    else:
        return False


def is_valid_api_user(api_key, api_secret, con):
    if not is_uuid_good(api_key):
        return False
    if not is_uuid_good(api_secret):
        return False
    query = "Select * From doctordb.apiusers Where ApiKey = :key AND ApiSecret = :secret"
    api_user = con.execute(query, {'key': api_key, 'secret': api_secret}).fetchall()
    if len(api_user) == 0:
        return False
    id = api_user[0][0]
    api_calls = api_user[0][6]
    query = "UPDATE doctordb.apiusers SET ApiCalls = :calls WHERE Id = :id"
    api_calls += 1
    con.execute(query, {'calls': api_calls, 'id': id})
    con.commit()
    return True


def hash_password(password):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt


def check_password(hashed_password, user_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()


def is_uuid_good(code):
    if code is None or code == '':
        return False
    code_list = code.split('-')
    if len(code_list) != 5:
        return False
    else:
        return True


def make_provider_list(providers):
    doc_list = []
    for doc in providers:
        provider_dict = {
            'Id': doc[0],
            'NPI': doc[1],
            'Organization': doc[2],
            'Lastname': doc[3],
            'Firstname': doc[4],
            'Address1': doc[5],
            'Address2': doc[6],
            'City': doc[7],
            'State': doc[8],
            'PostalCode': doc[9],
            'Phone': doc[10],
            'Taxonomy1': doc[11],
            'Taxonomy2': doc[12]
        }
        doc_list.append(provider_dict)
    return doc_list


def make_comment_list(comments):
    comment_list = []
    for comm in comments:
        comment_dict = {
            'Id': comm[0],
            'NPI': comm[1],
            'Comment': comm[2],
            'Created': comm[3],
            'User_Id': comm[4]
        }
        comment_list.append(comment_dict)
    return comment_list


def make_user_dict(user):
    user_dict = {
        'Firstname': user[1],
        'Lastname': user[2],
        'Nickname': user[3],
        'Email': user[4],
        'LoginTime': user[6],
        'LoggedIn': user[7],
        'Verified': user[8]
    }


def get_zips_and_distances_old(postal_code, radius_miles, con):
    rows = con.execute("SELECT Latitude, Longitude FROM doctordb.postalcodes where ZipCode = '" + str(postal_code) + "'").fetchall()

    if len(rows) == 0:
        return rows

    starting_lat = float(rows[0][0])
    starting_long = float(rows[0][1])
    change_degree_long = DEG_LONG_PER_MILE * radius_miles
    change_degree_lat = DEG_LAT_MILES_PER * radius_miles

    min_lat = round(starting_lat - change_degree_lat, 5)
    max_lat = round(starting_lat + change_degree_lat, 5)
    min_long = round(starting_long - change_degree_long, 5)
    max_long = round(starting_long + change_degree_long, 5)

    tested_zip_codes = []
    zips_distance = dict()

    temp_zip_codes = con.execute("SELECT ZipCode, Latitude, Longitude FROM doctordb.postalcodes where (Latitude >= " + str(
        min_lat) + " AND Latitude <= " + str(max_lat) + ") AND (Longitude >= " + str(
        min_long) + " AND Longitude <= " + str(max_long) + ")").fetchall()
    zip_codes = list(temp_zip_codes)
    for each in zip_codes:
        # each = each.split(',')
        zip = each[0]
        if zip == '27405':
            print(zip)
        lat2 = float(each[1])
        long2 = float(each[2])
        distance = get_distance_geopy(starting_long, starting_lat, long2, lat2)
        if distance <= radius_miles:
            tested_zip_codes.append(each[0])
            zips_distance.update({each[0]: distance})

    return_dict = {'tested_zip_codes': tested_zip_codes, 'zips_distance': zips_distance}
    return return_dict


def get_zips_and_distances_new(postal_code, radius_miles, con):
    rows = con.execute("SELECT Latitude, Longitude FROM doctordb.postalcodes where ZipCode = " + str(postal_code)).fetchall()

    if len(rows) == 0:
        return rows

    starting_lat = rows[0][0]
    starting_long = rows[0][1]
    radius_km = radius_miles * 1.609344
    query = build_zip_query(starting_long, starting_lat, radius_km)
    zip_rows = con.execute(query).fetchall()
    tested_zip_codes = []
    zips_distance = dict()
    if len(zip_rows) == 0:
        zips_distance.update({postal_code: 0})
        tested_zip_codes.append(postal_code)
    else:
        for each_zip in zip_rows:
            zips_distance.update({each_zip[1]: each_zip[7]/1.609344})
            tested_zip_codes.append(each_zip[1])

    return_dict = {'tested_zip_codes': tested_zip_codes, 'zips_distance': zips_distance}
    return return_dict


class ApiUserRegister(Resource):
    def get(self):
        organization = request.args.get('organization')
        email = request.args.get('email')
        message = request.args.get('message')
        return_url = request.url
        remote_ip = request.remote_addr
        try:
            ip_count = ip_addresses[remote_ip]
            ip_addresses[remote_ip] = ip_count + 1
        except KeyError:
            ip_addresses[remote_ip] = 1

        if ip_addresses[remote_ip] > 5:
            return send_return_response('Requests limit exceeded', 400)
        # print(remote_ip)
        if not is_phrase_good(organization, 50):
            return send_return_response('Organization must but be <= 50 characters with spaces, and no special characters', 400)
        if not check_email(email):
            return send_return_response('Invalid email format', 400)
        if message != '' and message is not None:
            message = filter_message(message, 150)
        else:
            message = 'No Message'

        yes_url = return_url + '&allow=true'
        no_url = return_url + '&allow=false'
        message = '<span><strong>Organization: </strong>' + organization + '</span></br><span><strong>Email: </strong>' + email + '</span></br></br>' \
                  '<span><strong>Message: </strong>' + message + '</span></br></br>' \
                  '<form method="post" action="' + yes_url + '"class="inline"><input type="hidden" name="" value="">' \
                  '<button type="submit" name="allow" value="True"class="link-button">Allow new API User?</button></form>' \
                    '<form method="post" action="' + no_url +'" class="inline">' \
                    '<input type="hidden" name="extra_submit_param" value="extra_submit_value"><button type="submit" name="allow" ' \
                     'value="True" class="link-button">Reject new API User?</button></form>'
        send_to_email = 'ron.knighton@orasi.com'
        email_response = send_email(send_to_email, message)
        return send_return_response('API User credentials requested from Admin. ' + email_response, 200)

    def post(self):
        url = request.url
        organization = request.args.get('organization')
        email = request.args.get('email')
        allow = request.args.get('allow')
        if allow == 'true':
            api_key = str(uuid.uuid4())
            api_secret = str(uuid.uuid4())
            # Use this if I want to hash the secret.
            # hashed_secret = hash_password(api_secret)
            try:
                con = db.session
                if not is_api_email_available(email, con):
                    return send_return_response('There is already an API account associated with this email.', 400)
                date_time = datetime.now()
                column_names = "Organization, Email, ApiKey, ApiSecret, Created, ApiCalls, Violations"
                con.execute("INSERT INTO doctordb.apiusers (" + column_names + ") VALUES(:Org,:Email,:Key,:Secret,:Created,:Calls,:Violations)",
                            {'Org': organization, 'Email': email, 'Key': api_key, 'Secret': api_secret, 'Created': date_time, 'Calls': str(0), 'Violations': str(0)})
                con.commit()
                message = "<h3>Your account has been authorized.</h3> <h4>API key: " + api_key + "</h4>" \
                          "<h4>API Secret: " + api_secret

                email_response = send_email(email, message)
                return_message = '<h1>The API account has been accepted</h1> <h2>' + email_response + '</h2>'

                return Response(return_message, mimetype='html')

            except mysql.connector.Error as error:
                return send_return_response(str(error), 500)
            except Exception as e:
                return send_return_response(str(e), 500)
        else:
            return_message = '<h1>The API account has been rejected</h1>'
        return Response(return_message, mimetype='html')


class UserRegister(Resource):

    def get(self):
        code = request.args.get('code')
        url = request.url
        if not is_uuid_good(code):
            return_message = '<h1>Your verification code appears to be corrupted</h1>'
            return Response(return_message, mimetype='html')
        try:
            con = db.session
            query = "UPDATE doctordb.users SET Verified = :Bool WHERE VerifyUUID = :Code"
            con.execute(query, {'Bool': True, 'Code': code})
            con.commit()
            return_message = '<h1>Your email has been verified</h1>'
            return Response(return_message, mimetype='html')
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)

    def post(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        firstname = request.args.get('firstname', '')
        lastname = request.args.get('lastname', '')
        nickname = request.args.get('nickname', '')
        email = request.args.get('email', '')
        password = request.args.get('password', '')
        url = request.url

        if not is_string_good(firstname, 25):
            return send_return_response('First name but be <= 25 characters, and no special characters', 400)

        if not is_string_good(lastname, 25):
            return send_return_response('Last name but be <= 25 characters, and no special characters', 400)

        if not is_string_good(nickname, 25):
            return send_return_response('Nickname but be <= 25 characters, and no special characters', 400)

        if not check_email(email):
            return send_return_response('Invalid email format', 400)

        if not validate_password(password):
            return send_return_response('Password cannot have space, and must be less <= 15 characters.', 400)

        try:
            con = db.session
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)
            if not is_email_available(email, con):
                return send_return_response('There is already an account associated with this email.', 400)
            hashed_password = hash_password(password)
            date_time = datetime.now()
            verify_uuid = str(uuid.uuid4())
            column_names = "Firstname, Lastname, Nickname, Email, Password, LoginTime, VerifyUUID"
            con.execute("INSERT INTO doctordb.users (" + column_names + ") VALUES(:Firstname, :Lastname, :Nickname, "
                        ":Email, :Password, :LoginTime, :VerifyUUID)", {'Firstname': firstname, 'Lastname': lastname,
                        'Nickname': nickname, 'Email': email,  'Password': hashed_password, 'LoginTime': date_time,
                        'VerifyUUID': verify_uuid})
            con.commit()
            return_url = request.url
            end_of_url = return_url.find('/UserRegister/')
            return_url = return_url[:end_of_url + 14]
            return_url = return_url + '?code=' + verify_uuid
            message = "Please click <a href=" + return_url + ">link</a> to verify your email"
            email_response = send_email(email, message)
            return send_return_response('User saved. ' + email_response, 200)

        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
            # connection.rollback()
        except Exception as e:
            return send_return_response(str(e), 500)


class UserLogin(Resource):
    def get(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        email = request.args.get('email')
        password = request.args.get('password')
        url = request.url
        if not check_email(email):
            return send_return_response('Invalid email format', 400)

        if not validate_password(password):
            return send_return_response('Invalid password.', 400)

        try:
            con = db.session
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)
            user = con.execute("SELECT * FROM doctordb.users WHERE Email = :Email", {'Email': email}).fetchone()
            if user is None:
                return send_return_response('User not found', 400)
            hashed_password = user["Password"]
            if not check_password(hashed_password, password):
                return send_return_response('Incorrect Password', 400)
            date_time = datetime.now()
            con.execute("UPDATE doctordb.users SET LoginTime = :Date, LoggedIn = :Bool where Id = :Id", {'Date': date_time, 'Bool': True, 'Id': user["Id"]})
            con.commit()
            user = dict(user)
            user["LoginTime"] = date_time
            # return jsonify(user)
            return send_return_response('User is logged in for 1 hour', 200)
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)


class Practitioners(Resource):
    invalid_zip = False

    def get(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        postal_code = request.args.get('postalcode')
        radius_miles = request.args.get('radius_miles')
        taxonomy = request.args.get('taxonomy')
        url = request.url
        if not is_postal_code_good(postal_code):
            return send_return_response('Only 5 digit zip code allowed', 400)

        if not is_radius_good(radius_miles):
            return send_return_response('Radius must be a positive integer value <= 50', 400)
        else:
            radius_miles = int(radius_miles)

        if taxonomy is not None:
            if not is_taxonomy_good(taxonomy):
                return send_return_response('Taxonomy is invalid format', 400)

        print(str(postal_code))
        print(type(postal_code))
        print(str(radius_miles))
        print(type(radius_miles))
        print(str(taxonomy))
        print(type(taxonomy))

        # first_name = request.args.get('firstname')
        # last_name = request.args.get('lastname')
        tested_zip_codes = []
        zips_distance = dict()

        try:
            con = db.session
            # date_time = datetime.now()
            # write_output_connections(str(con), date_time)
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)

            # return_dict = get_zips_and_distances_old(postal_code, radius_miles, con)
            return_dict = get_zips_and_distances_new(postal_code, radius_miles, con)

            if len(return_dict) == 0:
                return send_return_response('Invalid zip code', 400)

            if len(return_dict['tested_zip_codes']) > 100:
                return send_return_response('Too many zip codes to search! Please narrow search', 400)

            tested_zip_codes = return_dict['tested_zip_codes']
            zips_distance = return_dict['zips_distance']

            zip_codes_tuple = tuple(tested_zip_codes)

            start_time = datetime.now()
            if len(zip_codes_tuple) == 1:
                query = "SELECT * FROM doctordb.providers where PostalCode = " + "'" + str(zip_codes_tuple[0]) + "'"
                if taxonomy is not None:
                    query = "SELECT * FROM doctordb.providers where PostalCode = " + "'" + str(zip_codes_tuple[0]) + "'" + " AND Taxonomy1 = " + "'" + str(taxonomy) + "'"
                print(query)
                temp_providers = con.execute(query).fetchall()
            else:
                query = "SELECT * FROM doctordb.providers where PostalCode IN {}".format(zip_codes_tuple)
                if taxonomy is not None:
                    query = "SELECT * FROM doctordb.providers where PostalCode IN {}".format(zip_codes_tuple) + " AND Taxonomy1 = " + "'" + str(taxonomy) + "'"
                temp_providers = con.execute(query).fetchall()
                print(query)
            providers = make_provider_list(temp_providers)
            end_time = datetime.now()
            elapsed_time = end_time - start_time
            print("Get " + str(len(providers)) + " Providers: " + str(elapsed_time))

            if len(providers) == 0:
                return send_return_response('No providers match search', 400)
            if len(providers) > 10000:
                return send_return_response('Providers exceeds 10,000! Please narrow search', 400)

            start_time = datetime.now()
            npi_list = []

            for doc in providers:
                doc.update({"Distance": round(zips_distance[doc["PostalCode"]], 2)})
                npi_list.append(doc['NPI'])

            providers = get_provider_comments(providers, npi_list, con)
            end_time = datetime.now()
            elapsed_time = end_time - start_time
            print("Get distance and comments for Providers: " + str(elapsed_time))
            results = sorted(providers, key=itemgetter('Distance'))

            return jsonify(results)

        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)


class PractitionersByName(Resource):
    def get(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        postal_code = request.args.get('postalcode')
        radius_miles = request.args.get('radius_miles')
        firstname = request.args.get('firstname')
        lastname = request.args.get('lastname')
        url = request.url
        if not is_postal_code_good(postal_code):
            return send_return_response('Only 5 digit zip code allowed', 400)

        if not is_radius_good(radius_miles):
            return send_return_response('Radius must be a positive integer value <= 50', 400)
        else:
            radius_miles = int(radius_miles)

        if firstname != '':
            if not is_string_good(firstname):
                return send_return_response('First name but be <= 25 characters, and no special characters', 400)

        if not is_string_good(lastname):
            return send_return_response('Last name but be <= 25 characters, and no special characters', 400)

        # tested_zip_codes = []
        # zips_distance = dict()

        try:
            con = db.session
            # date_time = datetime.now()
            # write_output_connections(str(con), date_time)
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)

            # return_dict = get_zips_and_distances_old(postal_code, radius_miles, con)
            return_dict = get_zips_and_distances_new(postal_code, radius_miles, con)

            if len(return_dict) == 0:
                return send_return_response('Invalid zip code', 400)

            if len(return_dict['tested_zip_codes']) > 100:
                return send_return_response('Too many zip codes to search! Please narrow search', 400)

            tested_zip_codes = return_dict['tested_zip_codes']
            zips_distance = return_dict['zips_distance']
            zip_codes_tuple = tuple(tested_zip_codes)

            if firstname != '':
                name_search = " AND Firstname = '" + firstname.upper() + "' AND Lastname = '" + lastname.upper() + "'"
            else:
                name_search = " AND Lastname = '" + lastname.upper() + "'"

            if len(zip_codes_tuple) == 0:
                temp_providers = con.execute("SELECT * FROM doctordb.providers where PostalCode = '" + postal_code + "'" + name_search).fetchall()
            elif len(zip_codes_tuple) == 1:
                temp_providers = con.execute("SELECT * FROM doctordb.providers where PostalCode =" + "'" + str(zip_codes_tuple[0]) + "'" + name_search).fetchall()
            else:
                temp_providers = con.execute("SELECT * FROM doctordb.providers where PostalCode IN {}".format(zip_codes_tuple) + name_search).fetchall()

            providers = make_provider_list(temp_providers)

            if len(providers) == 0:
                return send_return_response('No matching providers', 400)
            if len(providers) > 10000:
                return send_return_response('Providers exceeds 10,000! Please narrow search', 400)

            npi_list = []
            for doc in providers:
                doc.update({"Distance": round(zips_distance[doc["PostalCode"]], 2)})
                npi_list.append(doc['NPI'])

            providers = get_provider_comments(providers, npi_list, con)
            results = sorted(providers, key=itemgetter('Distance'))

            return jsonify(results)
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)


class PractitionersByNpi(Resource):
    def get(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        npi = request.args.get('npi')
        postal_code = request.args.get('postalcode')
        url = request.url
        if not is_postal_code_good(postal_code):
            return send_return_response('Only 5 digit zip code allowed', 400)

        if not is_npi_good(npi):
            return send_return_response('Invalid NPI', 400)

        try:
            con = db.session
            # date_time = datetime.now()
            # write_output_connections(str(con), date_time)
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)

            rows = con.execute("SELECT Latitude, Longitude FROM doctordb.postalcodes where ZipCode = :zip", {'zip': str(postal_code)}).fetchall()

            if len(rows) == 0:
                return send_return_response('Zip code entered not in database', 400)

            starting_lat = float(rows[0][0])
            starting_long = float(rows[0][1])

            temp_providers = con.execute("SELECT * FROM doctordb.providers where NPI ='" + npi + "'").fetchall()

            # columns = "Id, NPI, Organization, Lastname, Firstname, Address1, Address2, City, State, PostalCode, Phone, " \
                      # "Taxonomy1, Taxonomy2"
            # temp_providers = con.execute("SELECT " + columns + " FROM doctordb.Providers where NPI =" + npi).fetchall()
            providers = make_provider_list(temp_providers)

            if len(providers) == 0:
                return send_return_response('No matching providers', 400)

            target_postal_code = providers[0]["PostalCode"]
            if target_postal_code == '':
                distance = -1
            else:
                rows = con.execute("SELECT Latitude, Longitude FROM doctordb.postalcodes where ZipCode = " + str(target_postal_code)).fetchall()
                if len(rows) == 0:
                    distance = -1
                else:
                    ending_lat = float(rows[0][0])
                    ending_long = float(rows[0][1])
                    distance = get_distance_geopy(starting_long, starting_lat, ending_long, ending_lat)

            npi_list = []
            for doc in providers:
                doc.update({"Distance": round(distance, 2)})
                npi_list.append(doc['NPI'])

            providers = get_provider_comments(providers, npi_list, con)
            results = sorted(providers, key=itemgetter('Distance'))
            return jsonify(results)
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)


class Comments(Resource):
    def get(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        npi = request.args.get('npi')
        email = request.args.get('email')
        url = request.url
        if not is_npi_good(npi):
            return send_return_response('Invalid NPI', 400)
        try:
            con = db.session
            # date_time = datetime.now()
            # write_output_connections(str(con), date_time)
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)

            user_id = get_user_id_by_email(email, con)
            query = "SELECT * FROM comments where NPI =" + npi
            temp_comments = con.execute(query).fetchall()
            comments = make_comment_list(temp_comments)

            for comment in comments:
                c_user_id = comment['User_Id']
                if c_user_id == user_id:
                    comment['User_Id'] = True
                else:
                    comment['User_Id'] = False

            return jsonify(comments)
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
            # connection.rollback()
        except Exception as e:
            return send_return_response(str(e), 500)

    def post(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        npi = request.args.get('npi')
        comment = request.args.get('comment')
        email = request.args.get('email')
        url = request.url
        if not is_npi_good(npi):
            return send_return_response('Invalid NPI', 400)

        if not is_comment_good(comment):
            return send_return_response('Comment does not meet validation', 400)

        try:
            con = db.session
            # date_time = datetime.now()
            # write_output_connections(str(con), date_time)
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)

            user_id = get_user_id_by_email(email, con)
            if user_id == -1:
                return send_return_response('User invalid, please have user login again', 400)

            column_names = "NPI, Comment, User_Id"
            con.execute("INSERT INTO doctordb.comments (" + column_names + ") VALUES(:npi,:comment,:user_id)", {'npi': npi, 'comment': comment, 'user_id': user_id})
            con.commit()

            return send_return_response('Comment added', 200)
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)

    def put(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        comment = request.args.get('comment')
        id = request.args.get('id')
        email = request.args.get('email')
        url = request.url

        if id is None:
            return send_return_response('Comment ID is not valid', 400)
        if not id.isdigit():
            return send_return_response('Comment ID is not valid', 400)

        if not is_comment_good(comment):
            return send_return_response('Comment does not meet validation', 400)

        try:
            con = db.session
            # date_time = datetime.now()
            # write_output_connections(str(con), date_time)
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)

            user_id = validate_comment_user(email, id, con)
            if user_id == -1:
                return send_return_response('User invalid, user timed out, or user Id not attributed to comment', 400)

            query = "UPDATE doctordb.comments SET Comment = '" + comment + "' WHERE Id = " + str(id)
            con.execute(query)
            con.commit()

            return send_return_response('Comment edited', 200)
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)

    def delete(self):
        api_key = request.args.get('key')
        api_secret = request.args.get('secret')
        id = request.args.get('id')
        email = request.args.get('email')
        url = request.url

        if id is None:
            return send_return_response('Comment ID is not valid', 400)
        if not id.isdigit():
            return send_return_response('Comment ID is not valid', 400)

        try:
            con = db.session
            # date_time = datetime.now()
            # write_output_connections(str(con), date_time)
            if not is_valid_api_user(api_key, api_secret, con):
                return send_return_response("Invalid Key or Secret", 400)

            user_id = get_user_id_by_email(email, con)
            if user_id == -1:
                return send_return_response('User invalid, please have user login again', 400)

            query = "DELETE FROM doctordb.comments WHERE id = " + str(id)
            con.execute(query)
            con.commit()

            return send_return_response('Comment deleted', 200)
        except mysql.connector.Error as error:
            return send_return_response(str(error), 500)
        except Exception as e:
            return send_return_response(str(e), 500)


class HelloWorld(Resource):
    def get(self):
        return {'about': 'Hello World!'}


api.add_resource(HelloWorld, '/')
api.add_resource(ApiUserRegister, "/ApiUserRegister/")
api.add_resource(UserRegister, "/UserRegister/")
api.add_resource(UserLogin, "/UserLogin/")
api.add_resource(Practitioners, "/Practitioners/")  # Route_1
api.add_resource(PractitionersByName, "/PractitionersByName/")  # Route_2
api.add_resource(PractitionersByNpi, "/PractitionersByNpi/")  # Route_3
api.add_resource(Comments, "/Comments/")  # Route_4

if __name__ == '__main__':
    '''
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT)
    '''
    app.run()
