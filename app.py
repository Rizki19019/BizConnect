import os
from os.path import join, dirname
from dotenv import load_dotenv

from pymongo import MongoClient
import jwt
from datetime import datetime, timedelta
import hashlib
from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    make_response,
    send_from_directory
)
from werkzeug.utils import secure_filename

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME = os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]

app = Flask(__name__)

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['UPLOAD_FOLDER'] = './static/profile_pics'
app.config['UPLOAD_FOLDER_INFO'] = './static/info_pics'

SECRET_KEY = 'BizConnect'
TOKEN_KEY = 'mytoken'


@app.route("/")
def home():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )
        user_info = db.users.find_one({"username": payload.get('id')})
        # Retrieve the list of info items from the database
        info_list = list(db.info.find({}, {"_id": 0}))
        event_list = list(db.events.find({}, {"_id": 0}))
        thread_list = list(db.threads.find({}, {"_id": 0}))
        # Periksa peran pengguna (admin atau user)
        if payload.get('id') == 'Admin':
            return render_template('admin/index.html', user_info=user_info, info_list=info_list)
        else:
            return render_template('index.html', user_info=user_info, info_list=info_list, eventList=event_list, thread_list=thread_list)
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="Your token has expired"))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="There was a problem logging you in"))


@app.route('/login', methods=['GET'])
def login():
    msg = request.args.get('msg')
    return render_template('login.html', msg=msg)


@app.route('/user/<username>', methods=['GET'])
def user(username):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        status = username == payload.get('id')
        user_info = db.users.find_one(
            {'username': username},
            {'_id': False}
        )
        return render_template(
            'user.html',
            user_info=user_info,
            status=status
        )
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))


@app.route("/update_profile", methods=["POST"])
def save_img():
    token_receive = request.cookies.get("mytoken")

    try:
        # Verifikasi dan decode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi pengguna dari payload
        username = payload["id"]
        name_receive = request.form['name_give']
        about_receive = request.form['about_give']

        # Persiapkan dokumen profil baru
        new_doc = {
            'profile_name': name_receive,
            'profile_info': about_receive
        }

        # Periksa apakah berkas disertakan dalam permintaan
        if 'file_give' in request.files:
            file = request.files['file_give']
            if file:
                # Simpan berkas dengan nama yang aman
                filename = secure_filename(file.filename)
                extension = filename.split('.')[-1]
                file_path = f"profile_pics/{username}.{extension}"
                file.save("./static/" + file_path)

                # Perbarui dokumen profil dengan informasi berkas
                new_doc['profile_pic'] = filename
                new_doc['profile_pic_real'] = file_path

        # Perbarui profil pengguna dalam basis data
        db.users.update_one({
            'username': username
        }, {
            '$set': new_doc
        })

        return jsonify({
            'result': 'success',
            'msg': 'Profil diperbarui!'
        })

    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        # Tangani kesalahan verifikasi token, redirect ke home atau kembalikan respons kesalahan
        return redirect(url_for('home'))


@app.route("/sign_in", methods=["POST"])
def sign_in():
    try:
        email_receive = request.form.get("email_give")
        username_receive = request.form.get("username_give")
        password_receive = request.form.get("password_give")
        pw_hash = hashlib.sha256(password_receive.encode("utf-8")).hexdigest()

        # Cek apakah login sebagai admin
        if (email_receive == "Admin@gmail.com" or username_receive == "Admin") and password_receive == "Admin123":
            payload = {
                "id": "Admin",
                "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24),
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

            return jsonify({"result": "success", "token": token, "role": "Admin"})

        query = {
            "$or": [{"email": email_receive}, {"username": username_receive}],
            "password": pw_hash,
        }

        result = db.users.find_one(query)

        if result:
            payload = {
                "id": username_receive,
                "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24),
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

            return jsonify({"result": "success", "token": token, "role": "user"})
        else:
            return jsonify({"result": "fail", "msg": "Tidak dapat menemukan pengguna dengan kombinasi id/kata sandi tersebut"})
    except Exception as e:
        print(f"Error in sign_in: {e}")
        return jsonify({"result": "fail", "msg": "An error occurred during login."})


@app.route("/sign_up/save", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email_receive = request.form['email_give']
        username_receive = request.form['username_give']
        password_receive = request.form['password_give']

        password_hash = hashlib.sha256(
            password_receive.encode('utf-8')).hexdigest()

        doc = {
            "email": email_receive,
            "username": username_receive,
            "password": password_hash,
            "profile_name": username_receive,
            "profile_pic": "",
            "profile_pic_real": "profile_pics/profile_placeholder.png",
            "profile_info": ""
        }

        db.users.insert_one(doc)
        return jsonify({'result': 'success'})
    else:
        return render_template('register.html')


@app.route('/sign_up/check_dup', methods=['POST'])
def check_dup():
    email_receive = request.form.get('email_give')
    username_receive = request.form.get('username_give')

    email_exists = bool(db.users.find_one({'email': email_receive}))
    username_exists = bool(db.users.find_one({'username': username_receive}))

    return jsonify({
        'result': 'success',
        'email_exists': email_exists,
        'username_exists': username_exists,
    })


@app.route("/admin_home")
def admin_home():
    return render_template('admin/index.html')


@app.route("/save_info", methods=["POST"])
def save_info():
    try:
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifying and decoding JWT token
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Extract information from the payload
        username = payload["id"]
        text_receive = request.form['text']
        pic_file = request.files.get('picFile')

        # Prepare a new info document
        new_info = {
            'text': text_receive,
            'username': username,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

        # Check if a picture file is provided
        if pic_file:
            # Save the picture with a secure filename
            filename = secure_filename(pic_file.filename)
            file_path = f"info_pics/{filename}"
            pic_file.save("./static/" + file_path)

            # Add the picture information to the new_info document
            new_info['pic_filename'] = filename
            new_info['pic_file_path'] = file_path

        # Insert the new_info document into the database
        db.info.insert_one(new_info)

        return jsonify({
            'result': 'success',
            'msg': 'Info successfully saved!'
        })

    except jwt.ExpiredSignatureError:
        # Handle expired token
        return jsonify({
            'result': 'fail',
            'msg': 'Token has expired.'
        })

    except jwt.exceptions.DecodeError:
        # Handle JWT decode error
        return jsonify({
            'result': 'fail',
            'msg': 'Failed to decode the token.'
        })

    except Exception as e:
        print(f"Error in save_info: {e}")
        # Handle other errors
        return jsonify({
            'result': 'fail',
            'msg': 'An error occurred while saving info.'
        })


@app.route("/delete_info", methods=["POST"])
def delete_info():
    try:
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifikasi dan dekode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi pengguna dari payload
        username = payload["id"]
        text_to_delete = request.form['text']

        # Hapus info dari database
        db.info.delete_one({'username': username, 'text': text_to_delete})

        return jsonify({
            'result': 'success',
            'msg': 'Info berhasil dihapus.'
        })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'result': 'fail',
            'msg': 'Token telah kadaluarsa.'
        })

    except jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': 'Gagal mendekode token.'
        })

    except Exception as e:
        print(f"Error in delete_info: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat menghapus info.'
        })


@app.route("/update_info", methods=["POST"])
def update_info():
    try:
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifikasi dan dekode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi pengguna dari payload
        username = payload["id"]
        original_text = request.form['originalText']
        new_text = request.form['newText']
        pic_file = request.files.get('picFile')

        # Perbarui info dalam basis data
        info = db.info.find_one({'username': username, 'text': original_text})

        if info:
            info['text'] = new_text

            # Periksa apakah berkas gambar disertakan dalam permintaan
            if pic_file:
                # Simpan berkas dengan nama yang aman
                filename = secure_filename(pic_file.filename)
                file_path = f"info_pics/{filename}"
                pic_file.save("./static/" + file_path)
                info['pic_filename'] = filename
                info['pic_file_path'] = file_path

            # Simpan perubahan ke basis data
            db.info.update_one(
                {'username': username, 'text': original_text}, {'$set': info})

            return jsonify({
                'result': 'success',
                'msg': 'Info berhasil diperbarui.'
            })
        else:
            return jsonify({
                'result': 'fail',
                'msg': 'Info tidak ditemukan.'
            })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'result': 'fail',
            'msg': 'Token telah kadaluarsa.'
        })

    except jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': 'Gagal mendekode token.'
        })

    except Exception as e:
        print(f"Error in update_info: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat memperbarui info.'
        })
        
@app.route('/info_pics/<filename>')
def info_pic(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER_INFO'], filename)

@app.route("/get_info_list", methods=["GET"])
def get_info_list():
    try:
        # Retrieve the list of info items from the database
        info_list = list(db.info.find({}, {"_id": 0}))

        return jsonify({
            'result': 'success',
            'infoList': info_list
        })

    except Exception as e:
        print(f"Error in get_info_list: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'An error occurred while fetching info list.'
        })


@app.route("/get_member_list", methods=["GET"])
def get_member_list():
    try:
        # Ambil daftar anggota dari basis data
        member_list = list(db.users.find({}, {"_id": 0}))

        return jsonify({
            'result': 'success',
            'memberList': member_list
        })

    except Exception as e:
        print(f"Error in get_member_list: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat mengambil daftar anggota.'
        })


@app.route("/delete_member", methods=["POST"])
def delete_member():
    try:
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifikasi dan dekode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi pengguna dari payload
        username_to_delete = request.form['username']

        # Hapus anggota dari basis data
        db.users.delete_one({'username': username_to_delete})

        return jsonify({
            'result': 'success',
            'msg': 'Anggota berhasil dihapus.'
        })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'result': 'fail',
            'msg': 'Token telah kadaluarsa.'
        })

    except jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': 'Gagal mendekode token.'
        })

    except Exception as e:
        print(f"Error in delete_member: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat menghapus anggota.'
        })


@app.route("/logout")
def logout():
    # Clear the token by setting an expired cookie
    response = make_response(redirect(url_for("login")))
    response.set_cookie('mytoken', '', expires=0)
    return response


@app.route("/create_event", methods=["POST"])
def create_event():
    try:
        # Mendapatkan token dari cookie
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifikasi dan dekode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi pengguna dari payload
        username = payload["id"]
        title_receive = request.form['title']
        content_receive = request.form['content']
        image_file = request.files.get('image')
        organizer = db.users.find_one({'username': username})['profile_name']

        # Persiapkan dokumen acara baru
        new_event = {
            'title': title_receive,
            'content': content_receive,
            'organizer': organizer,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

        # Cek jika ada berkas gambar yang disertakan
        if image_file:
            # Simpan gambar dengan nama yang aman
            filename = secure_filename(image_file.filename)
            file_path = f"event_images/{filename}"
            image_file.save("./static/" + file_path)

            # Tambahkan informasi gambar ke dokumen acara baru
            new_event['image_filename'] = filename
            new_event['image_file_path'] = file_path

        # Masukkan dokumen acara baru ke dalam basis data
        db.events.insert_one(new_event)

        return jsonify({
            'result': 'success',
            'msg': 'Acara berhasil dibuat!'
        })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'result': 'fail',
            'msg': 'Token telah kadaluarsa.'
        })

    except jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': 'Gagal mendekode token.'
        })

    except Exception as e:
        print(f"Error in create_event: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat membuat acara.'
        })


@app.route("/delete_event", methods=["POST"])
def delete_event():
    try:
        # Mendapatkan token dari cookie
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifikasi dan dekode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi pengguna dari payload
        username = payload["id"]
        title_to_delete = request.form['title']

        # Periksa apakah pengguna adalah pembuat acara
        event = db.events.find_one(
            {'organizer': username, 'title': title_to_delete})
        if event:
            # Hapus acara dari database
            db.events.delete_one(
                {'organizer': username, 'title': title_to_delete})
            return jsonify({
                'result': 'success',
                'msg': 'Acara berhasil dihapus.'
            })
        else:
            return jsonify({
                'result': 'fail',
                'msg': 'Anda tidak memiliki izin untuk menghapus acara ini.'
            })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'result': 'fail',
            'msg': 'Token telah kadaluarsa.'
        })

    except jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': 'Gagal mendekode token.'
        })

    except Exception as e:
        print(f"Error in delete_event: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat menghapus acara.'
        })


@app.route("/get_event_list", methods=["GET"])
def get_event_list():
    try:
        # Ambil daftar acara dari basis data
        event_list = list(db.events.find({}, {"_id": 0}))

        return jsonify({
            'result': 'success',
            'eventList': event_list
        })

    except Exception as e:
        print(f"Error in get_event_list: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat mengambil daftar acara.'
        })


@app.route('/create_thread', methods=['POST'])
def create_thread():
    try:
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifikasi dan dekode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi dari payload
        username = payload["id"]
        post_content = request.form.get('postContent')
        image_file = request.files.get('imageUpload')

        # Dapatkan informasi profil pengguna dari database
        user_info = db.users.find_one({"username": username})
        profile_name = user_info.get("profile_name")
        profile_pic_real = user_info.get("profile_pic_real")

        # Persiapkan dokumen thread baru
        new_thread = {
            'username': username,
            'profile_name': profile_name,
            'profile_pic_real': profile_pic_real,
            'post_content': post_content,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

        # Periksa apakah disertakan berkas gambar
        if image_file:
            # Simpan berkas gambar dengan nama yang aman
            filename = secure_filename(image_file.filename)
            file_path = f"thread_pics/{filename}"
            image_file.save("./static/" + file_path)

            # Tambahkan informasi gambar ke dokumen thread baru
            new_thread['image_filename'] = filename
            new_thread['image_file_path'] = file_path

        # Masukkan dokumen thread baru ke dalam basis data
        db.threads.insert_one(new_thread)

        return jsonify({
            'result': 'success',
            'msg': 'Thread berhasil dibuat!'
        })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'result': 'fail',
            'msg': 'Token telah kadaluarsa.'
        })

    except jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': 'Gagal mendekode token.'
        })

    except Exception as e:
        print(f"Error in create_thread: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat membuat thread.'
        })


@app.route("/get_thread_list", methods=["GET"])
def get_thread_list():
    try:
        # Ambil daftar thread dari basis data
        thread_list = list(db.threads.find({}, {"_id": 0}))

        return jsonify({
            'success': True,
            'threadList': thread_list
        })

    except Exception as e:
        print(f"Error in get_thread_list: {e}")
        return jsonify({
            'success': False,
            'error_msg': 'Terjadi kesalahan saat mengambil daftar thread.'
        })


@app.route('/delete_thread', methods=['POST'])
def delete_thread():
    try:
        token_receive = request.cookies.get(TOKEN_KEY)

        # Verifikasi dan dekode token JWT
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        # Ekstrak informasi dari payload
        username = payload["id"]
        post_content_to_delete = request.form['post_content']

        # Dapatkan informasi thread dari database
        thread_info = db.threads.find_one(
            {'username': username, 'post_content': post_content_to_delete})

        # Periksa apakah pengguna adalah pembuat thread
        if thread_info:
            # Hapus thread dari database
            db.threads.delete_one(
                {'username': username, 'post_content': post_content_to_delete})

            return jsonify({
                'result': 'success',
                'msg': 'Thread berhasil dihapus.'
            })
        else:
            return jsonify({
                'result': 'fail',
                'msg': 'Anda tidak memiliki izin untuk menghapus thread ini.'
            })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'result': 'fail',
            'msg': 'Token telah kadaluarsa.'
        })

    except jwt.exceptions.DecodeError:
        return jsonify({
            'result': 'fail',
            'msg': 'Gagal mendekode token.'
        })

    except Exception as e:
        print(f"Error in delete_thread: {e}")
        return jsonify({
            'result': 'fail',
            'msg': 'Terjadi kesalahan saat menghapus thread.'
        })

@app.route("/comment/<thread_id>")
def comment(thread_id):
    # Lakukan pengolahan data atau kueri database berdasarkan thread_id
    # Contoh penggunaan:
    thread_info = db.threads.find_one({"custom_thread_id": thread_id})

    if thread_info:
        return render_template("comment.html", thread_info=thread_info)
    else:
        # Tampilkan halaman 404 jika thread tidak ditemukan
        return render_template("404.html"), 404

if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
