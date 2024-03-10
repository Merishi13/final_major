import base64
import os
from flask import Flask, request,session,flash,send_from_directory
from flask import render_template,redirect,url_for,make_response
from flask import current_app as app
from application.models import *
from flask_restful import Resource
from flask_restful import Api
from flask_restful import fields
from flask_restful import marshal_with
from flask_restful import reqparse
from werkzeug.exceptions import HTTPException
from flask_bcrypt import Bcrypt
import yagmail
import random,string
from main import cache
from flask_security import auth_required
from flask import request, jsonify
from sumy.summarizers.lsa import LsaSummarizer
import nltk
nltk.download('punkt')
nltk.download('stopwords')
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import gzip
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import PyPDF2


#initialization ------------------------------------------------------------------------------------------------------------------------------
bcrypt = Bcrypt(app)
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'
app.config['SECRET_KEY'] = 'efnefjoejfi3240398#*(@)'
api = None
api = Api(app)
# #@login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

# #APIs------------------------------------------------------------------------------------------------------------------------------------------
#Login and register API
class Hospitaldata(Resource):
    def get(self,hno):
        data = Hospital.query.filter_by(hno=hno).first()
        if data != None:
            return jsonify({'password':data.password})
        else:
            return jsonify({'error':'error'})
    def put(self,hno):
        data = Hospital.query.filter_by(hno=hno).first()
        data.status = 'lin'
        db.session.commit()
        return

class Upload(Resource):
    def put(self,aadhar):
        user = User.query.filter_by(aadhar = aadhar).first()
        try:
            file = request.files["file"]
            pdf_reader = PyPDF2.PdfReader(file)
            page = pdf_reader.pages[0]
            text = page.extract_text()
            if file:
                # file_data = file.read()
                print(type(text.encode('utf-8')))
                print(text.encode('utf-8'))
                # print("Received file data:", file_data)
                compressed_data = gzip.compress(text.encode('utf-8'))
                encodeed_text = text.encode('utf-8')
                print(type(encodeed_text))

                key = b'1234567812345678'
                padded_data = pad(encodeed_text,AES.block_size)
                cipher = AES.new(key, AES.MODE_ECB)
                encrypted_data = cipher.encrypt(padded_data)
                # encrypted_data_readable = encrypted_data.encode('latin-1')
                # print(encrypted_data_readable)

                test = userdata.query.filter_by(ulid = user.id).first()
                print(encrypted_data)
                print(type(encrypted_data))
                test.file=encrypted_data
                db.session.commit()
                return jsonify({"message": "File uploaded successfully"})
            else:
                return jsonify({"error": "No file provided"})
        except Exception as e:
            print("Error:", str(e))
            return jsonify({"error": str(e)})   


class Retrieve(Resource):
    def get(self,aadhar):
        user = User.query.filter_by(aadhar = aadhar).first()
        if user:
            try:
                file_record = userdata.query.filter_by(ulid = user.id).first()
                if file_record:
                    # encrypted_data = base64.b64decode(encrypted_data)
                    key = b'1234567812345678'
                    # Decrypt using AES
                    cipher = AES.new(key, AES.MODE_ECB)

                    decrypted_data = cipher.decrypt(file_record.file)

                    unpadded_data = unpad(decrypted_data,AES.block_size)
                    string_data = unpadded_data.decode('utf-8', errors='replace')
                    return jsonify({"file_data": string_data})
                else:
                    return 
            except Exception as e:
                print("Error:", str(e))
                return jsonify({"error": str(e)})   
        else:
            return

class RetrieveP(Resource):
    def get(self):
        user = User.query.filter_by(status = "lin").first()
        try:
            file_record = userdata.query.filter_by(ulid = user.id).first()
            if file_record:
                # encrypted_data = base64.b64decode(encrypted_data)
                    key = b'1234567812345678'
                    # Decrypt using AES
                    cipher = AES.new(key, AES.MODE_ECB)

                    decrypted_data = cipher.decrypt(file_record.file)

                    unpadded_data = unpad(decrypted_data,AES.block_size)
                    # decompressed_data = gzip.decompress(unpadder.update(padded_data) + unpadder.finalize())
                    string_data = unpadded_data.decode('utf-8', errors='replace')
                    return jsonify({"file_data": string_data})
               
            else:
                return jsonify({"error": "No file found"})
        except Exception as e:
            print("Error:", str(e))
            return jsonify({"error": str(e)})  

class Download(Resource):
    def get(self,aadhar):
        user = User.query.filter_by(aadhar = aadhar).first()
        try:
            file_record = userdata.query.filter_by(ulid = user.id).first()
            if file_record:
                key = b'1234567812345678'
                    # Decrypt using AES
                cipher = AES.new(key, AES.MODE_ECB)

                decrypted_data = cipher.decrypt(file_record.file)

                unpadded_data = unpad(decrypted_data,AES.block_size)
                    # decompressed_data = gzip.decompress(unpadder.update(padded_data) + unpadder.finalize())
                print("hello")
                print(unpadded_data)
                print("hello")
                string_data = unpadded_data.decode('utf-8')
                print(string_data)
                content_type = "text/plain"

                # Create a temporary directory to store the file
                temp_dir = "temp"

                # Write the file to the temporary directory
                temp_file_path = os.path.join(temp_dir, "Report.txt")
                with open(temp_file_path, "w") as temp_file:
                    temp_file.write(string_data)

                # Send the file for download
                return send_from_directory(temp_dir,"Report.txt", as_attachment=True, mimetype=content_type)
            else:
                return jsonify({"error": "File not found"})
        except Exception as e:
            return jsonify({"error": str(e)})
    
class Downloadp(Resource):
    def get(self):
        user = User.query.filter_by(status = "lin").first()
        print(user.id)
        try:
            print("hello")
            file_record = userdata.query.filter_by(ulid = user.id).first()
            print(file_record)
            if file_record:
                print("hii")
                key = b'1234567812345678'
                    # Decrypt using AES
                cipher = AES.new(key, AES.MODE_ECB)

                decrypted_data = cipher.decrypt(file_record.file)

                unpadded_data = unpad(decrypted_data,AES.block_size)
                    # decompressed_data = gzip.decompress(unpadder.update(padded_data) + unpadder.finalize())
                string_data = unpadded_data.decode('utf-8')
                print(string_data)
                content_type = "application/pdf"

                # Create a temporary directory to store the file
                temp_dir = "temp"

                # Write the file to the temporary directory
                temp_file_path = os.path.join(temp_dir, "UserReport")
                with open(temp_file_path, "w") as temp_file:
                    temp_file.write(string_data)

                # Send the file for download
                print("success")
                return send_from_directory(temp_dir,"UserReport", as_attachment=True, mimetype=content_type)
                
            else:
                return jsonify({"error": "File not found"})
        except Exception as e:
            return jsonify({"error": str(e)})
        
class UserData(Resource):
    def get(self,aadhar):
        data = User.query.filter_by(aadhar=aadhar).first()
        if data != None:
            return jsonify({'password':data.password})
        else:
            return jsonify(400, {'error':'error'})
    def put(self,aadhar):
        data = User.query.filter_by(aadhar=aadhar).first()
        print(data.status)
        data.status = 'lin'
        db.session.commit()
        return
    
class access(Resource):
    def get(self,aadhar):
        user = User.query.filter_by(aadhar = aadhar).first()
        if user:
            data = userdata.query.filter_by(ulid = user.id).first()
            return({"pname":data.name,"contact":data.contact,"age":data.age,"gender":data.gender,"height":data.height,"weight":data.weight,"bloodgrp":data.bloodgrp})
        else:
            return
        
class Error(Resource):
    def get(self):
        return jsonify({'error':'error'})

class Redirectp(Resource):
    def get(self):
        data = User.query.filter_by(status = "lin").first()
        if data:
            return {"redirect":"false"}
        else:
            return {"redirect":"true"}
        
class Redirecth(Resource):
    def get(self):
        data = Hospital.query.filter_by(status = "lin").first()
        if data:
            return {"redirect":"false"}
        else:
            return {"redirect":"true"}

class Summary(Resource):
    def get(self):
        data = User.query.filter_by(status="lin").first()
        data1 = userdata.query.filter_by(ulid = data.id).first()
        if data1.file:
            # encrypted_data = base64.b64decode(encrypted_data)
            key = b'1234567812345678'
                    # Decrypt using AES
            cipher = AES.new(key, AES.MODE_ECB)

            decrypted_data = cipher.decrypt(data1.file)

            unpadded_data = unpad(decrypted_data,AES.block_size)


            string_data = unpadded_data.decode("utf-8")
            words = word_tokenize(string_data)
            words = [word for word in words if word.lower() not in stopwords.words('english')]
            cleaned_text = ' '.join(words)
            document = PlaintextParser.from_string(cleaned_text, Tokenizer("english"))
            summarizer = LsaSummarizer()
            summary = summarizer(document.document,10)
            summary_text = [str(sentence) for sentence in summary]
            return {"summary":summary_text}
        return {"summary":"Report Not Uploaded Yet"}
    
class Summaryid(Resource):
    def get(self, aadhar):
        data = User.query.filter_by(aadhar=aadhar).first()
        data1 = userdata.query.filter_by(ulid=data.id).first()
        
        if data1.file:
            # Decrypt using AES
            key = b'1234567812345678'
                    # Decrypt using AES
            cipher = AES.new(key, AES.MODE_ECB)

            decrypted_data = cipher.decrypt(data1.file)

            unpadded_data = unpad(decrypted_data,AES.block_size)
            
            print(unpadded_data)
            print(type(unpadded_data))
            # string_data = unpadded_data.decode("utf-8",)
            try:
                string_data = unpadded_data.decode('utf-8', errors='replace')
                print(string_data)
                words = word_tokenize(string_data)
                words = [word for word in words if word.lower() not in stopwords.words('english')]
                cleaned_text = ' '.join(words)
                document = PlaintextParser.from_string(cleaned_text, Tokenizer("english"))
                summarizer = LsaSummarizer()
                summary = summarizer(document.document, 10)
                summary_text = [str(sentence) for sentence in summary]

                return {"summary": summary_text}
            
            except UnicodeDecodeError as e:
                print(f"Error decoding bytes: {e}")

            

        return {"summary": "Report Not Uploaded Yet"}


          
class Logout(Resource):
    def put(self):
        try:
            data = User.query.filter_by(status="lin").first()
            data.status = "lout"
            db.session.commit()
            return
        except:
            data = Hospital.query.filter_by(status="lin").first()
            data.status = "lout"
            db.session.commit()
            return

regis = {
    "aadhar":fields.String,
    "email":fields.String,
    "password":fields.String,
    "firstname":fields.String,
    "lastname":fields.String
}

regispar = reqparse.RequestParser()
regispar.add_argument("aadhar")
regispar.add_argument("email")
regispar.add_argument("password")
regispar.add_argument("firstname")
regispar.add_argument("lastname")

class Register(Resource):
    # @marshal_with(regis)
    def put(self):
        args = regispar.parse_args()
        aadhar = args.get("aadhar",None)
        email = args.get("email",None)
        password = args.get("password",None)
        firstname = args.get("firstname",None)
        lastname = args.get("lastname",None)

        print(aadhar,email,password, firstname,lastname)
        test = User.query.filter_by(aadhar = aadhar).first()
        if (test):
            print('if')
            return {'message':'error'}
        elif(aadhar == "" or email == "" or password == "" or firstname == "" or lastname == ""):
            print('elif')
            return 400
        else:
            newdata = User(aadhar = aadhar, password = password, firstname=firstname,lastname=lastname, email = email,status = 'lout')
            db.session.add(newdata)
            db.session.commit()
            print('else')
            return {'message':'SUCCESS'}

udata = {
    "name":fields.String,
    "contact":fields.String,
    "age":fields.String,
    "height":fields.String,
    "gender":fields.String,
    "weight":fields.String,
    "bloodgrp":fields.String,
}

upar = reqparse.RequestParser()
upar.add_argument("name")
upar.add_argument("contact")
upar.add_argument("age")
upar.add_argument("height")
upar.add_argument("weight")
upar.add_argument("gender")
upar.add_argument("bloodgrp")
class Udata(Resource):
    # @marshal_with(regis)
    def put(self):
        args = upar.parse_args()
        name = args.get("name",None)
        contact = args.get("contact",None)
        age = args.get("age",None)
        height = args.get("height",None)
        weight = args.get("weight",None)
        gender = args.get("gender",None)
        bloodgrp = args.get("bloodgrp",None)
        
        user = User.query.filter_by(status = "lin").first()
        if(name == "" or contact == "" or age == "" or weight == "" or height == "" or gender == "" or bloodgrp == ""):
            return 400
        else:
            newdata = userdata(name = name, contact = contact, age=age,height=height,gender = gender, weight = weight,bloodgrp=bloodgrp,ulid = user.id)
            db.session.add(newdata)
            db.session.commit()
            return {'message':'SUCCESS'}

class Checkuser(Resource):
    def get(self,aadhar):
        user = User.query.filter_by(aadhar = aadhar).first()
        if user:
            test = userdata.query.filter_by(ulid = user.id).first()
            if test:
                return True
            else:
                return
        else:
            return

class GetOTP(Resource):
    def get(self,aadhar):
        user = User.query.filter_by(aadhar = aadhar).first()
        # Set your email credentials and details
        sender_email = "rishikesh.vankayala@gmail.com"
        receiver_email = user.email
        password = "mnzmnddoiajbqtnz"
        subject = "OTP for JEEVAN"

        # Create the MIME object
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject

        # Add the body of the email
        random_number = random.randint(100000, 999999)
        body = "Use this OTP for validation into JEEVAN " + str(random_number)
        message.attach(MIMEText(body, "plain"))

        # Connect to the SMTP server (in this case, Gmail's SMTP server)
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()

        # Log in to your email account
        server.login(sender_email, password)

        # Send the email
        server.sendmail(sender_email, receiver_email, message.as_string())

        # Close the connection
        server.quit()
        return {'message' : random_number}



api.add_resource(GetOTP,"/api/getotp/<aadhar>")
api.add_resource(Checkuser,"/api/checkuser/<aadhar>")
api.add_resource(Hospitaldata,"/api/data/<hno>","/api/change/<hno>")
api.add_resource(UserData,"/api/udata/<aadhar>","/api/updatestatus/<aadhar>")
api.add_resource(Error,"/api/data/")
api.add_resource(Register,"/api/register")
api.add_resource(Udata,"/api/fillform")
api.add_resource(Logout,"/api/logout")
api.add_resource(Upload,"/api/upload/<aadhar>")
api.add_resource(Retrieve,"/api/retrieve/<aadhar>")
api.add_resource(RetrieveP,"/api/retrievep")
api.add_resource(Download,"/api/download/<aadhar>")
api.add_resource(Downloadp,"/api/downloadp")
api.add_resource(access,"/api/access/<aadhar>")
api.add_resource(Redirecth,"/api/redirecth")
api.add_resource(Redirectp,"/api/redirectp")
api.add_resource(Summary,"/api/summary")
api.add_resource(Summaryid,"/api/summary/<aadhar>")

# api.add_resource(ShowAPI,"/api/displayshow", "/api/editshow/<int:showid>","/api/createshow", "/api/deleteshow/<int:showid>")
# api.add_resource(VenueidAPI,"/api/displayvenue/<int:id>")
# api.add_resource(ShowidAPI,"/api/displayshow/<int:id>")
# api.add_resource(LoginRegisterAPI,"/api/register")#"/api/login/<string:name>",
# api.add_resource(AdminAPI,"/api/admin/<string:name>")
# api.add_resource(VenuefilterAPI,"/api/filtervenue/<string:filter>")
# api.add_resource(ShowfilterratingAPI,"/api/ratingshow/<string:filter>")
# api.add_resource(ShowfiltertagsAPI,"/api/tagsshow/<string:filter>")

#API ERRORS CLASSES----------------------------------------------------------------------------------------------------------------------------

# #app routes------------------------------------------------------------------------------------------------------------------------------------
# @app.route('/logout', methods=['GET', 'POST'])
# #@login_required
# def logout():
#    # logout_user()
#     return redirect(url_for('index'))

# @app.route("/", methods=["GET", "POST"])
# def index():  
#     form = LoginForm()
#     if form.validate_on_submit():
#         temp = User.query.filter_by(username=form.username.data).first()
#         if(temp):
#             if(temp.password == )
#            # if bcrypt.check_password_hash(temp.password, form.password.data):
#                # login_user(temp)
#                 return redirect(url_for('userhome'))
#             return render_template("index.html",form = form,msg= "Password is incorrect")
#         return render_template("index.html",form = form,msg= "User not found please register")
#     return render_template("index.html",form = form,msg= "")


# @app.route("/userhome", methods=["GET", "POST"])
# #@login_required
# def userhome():
#     venues = Venues.query.all()
#     shows = Shows.query.all()
#     return render_template("userhome.html",venues = venues,shows = shows)
    
# @app.route("/bookshow/<showid>", methods=["GET", "POST"])
# #@login_required
# def bookshow(showid):
#     if request.method == "GET":
#         return render_template("bookshow.html",showid = showid)
#     if request.method == "POST":
#         temp = Shows.query.filter_by(id =showid).first()
#         tick = Venues.query.filter_by(id = temp.venue_id).first()
#         tireq = request.form["quantity"]
#         if(int(tireq) > int(tick.capacity)):
#             return render_template("bookshow.html",showid = showid,msg = "Only "+ tick.capacity +" tickets remain")
#         else:
#             tick.capacity = str(int(tick.capacity)-int(tireq))
#             db.session.commit()
#             return redirect(url_for("userhome"))


# # @app.route("/userregister", methods=["GET", "POST"])
# # def userregister():
# #     form = RegisterForm()

# #     if form.validate_on_submit():
# #         hashed_password = bcrypt.generate_password_hash(form.password.data)
# #         new_user = User(username=form.username.data, password=hashed_password)
# #         db.session.add(new_user)
# #         db.session.commit()
# #         return redirect(url_for('index'))
# #     return render_template('userregister.html', form=form)
        

# @app.route("/adminlogin", methods=["GET", "POST"])
# def adminlogin():
#     if request.method == "GET":
#         return render_template("adminlogin.html",msg = "")
#     if request.method == "POST":
#         adminname = request.form["adminname"]
#         adminpass = request.form["adminpass"]
#         ad = Admin.query.filter_by(adminname = adminname).first()
#         if(ad):
#             if ad.adminpass == adminpass:
#                 login_user(ad)
#                 return redirect(url_for("adminhome"))
#             return render_template("adminlogin.html",msg = "Wrong Password")
#         return render_template("adminlogin.html", msg  = "Admin does not exist")
    
# @app.route("/adminhome", methods=["GET", "POST"])
# def adminhome():
#     if request.method == "GET":
#         venues = Venues.query.all()
#         shows = Shows.query.all()
#         return render_template("adminhome.html",venues = venues,shows = shows)
    
# @app.route("/createvenue", methods=["GET", "POST"])
# def createvenue():
#     if request.method == "GET":
#         return render_template("createvenue.html")
#     if request.method == "POST":
#         venuename = request.form["venuename"]
#         place = request.form["place"]
#         capacity = request.form["capacity"]
#         check = Venues.query.filter_by(venuename = venuename).first()
#         if(check):
#             return render_template("createvenue.html",msg = "Venue already exists")
#         newvenue = Venues(venuename=venuename,place = place,capacity = capacity)
#         db.session.add(newvenue)
#         db.session.commit()
#         return redirect(url_for("adminhome"))
    
# @app.route("/createshow/<venueid>", methods=["GET", "POST"])
# def createshow(venueid):
#     if request.method == "GET":
#         return render_template("createshow.html",venueid= venueid)
#     if request.method == "POST":
#         showname = request.form["showname"]
#         rating = request.form["rating"]
#         start = request.form["start"]
#         end = request.form["end"]
#         tags = request.form["tags"]
#         price = request.form["price"]
#         check = Shows.query.filter_by(venue_id = venueid,showname=showname).first()
#         if(check):
#             return render_template("createshow.html",msg = "show already exists")
#         newshow = Shows(showname=showname,rating=rating,start=start,end=end,tags=tags,price=price,venue_id=venueid)
#         db.session.add(newshow)
#         db.session.commit()
#         return redirect(url_for("adminhome"))

# @app.route("/deletevenue/<venueid>", methods=["GET", "POST"])
# def deletevenue(venueid):
#     venue = Venues.query.filter_by(id = venueid).first()
#     db.session.delete(venue)
#     db.session.commit()
#     return redirect(url_for("adminhome"))

# @app.route("/editvenue/<venueid>", methods=["GET", "POST"])
# def editvenue(venueid):
#     venue = Venues.query.filter_by(id = venueid).first()
#     name = venue.venuename
#     place = venue.place
#     capacity = venue.capacity
#     if request.method == "GET":  
#         return render_template("createvenue.html",flag = True,venueid = venueid, name = name,place = place,capacity = capacity)
    
#     if request.method == "POST":
#         check = Venues.query.filter_by(venuename = request.form["venuename"]).first()
#         if(check):
#             return render_template("createvenue.html",msg = "Venue already exists", flag = True,venueid = venueid, name = name,place = place,capacity = capacity)
#         venue.venuename = request.form["venuename"]
#         venue.place = request.form["place"]
#         venue.capacity = request.form["capacity"]

#         db.session.commit()
#         return redirect(url_for("adminhome"))
    
# @app.route("/deleteshow/<showid>", methods=["GET", "POST"])
# def deleteshow(showid):
#     show = Shows.query.filter_by(id = showid).first()
#     db.session.delete(show)
#     db.session.commit()
#     return redirect(url_for("adminhome"))

# @app.route("/editshow/<showid>", methods=["GET", "POST"])
# def editshow(showid):
#     show = Shows.query.filter_by(id = showid).first()
#     name = show.showname
#     rating = show.rating
#     start = show.start
#     end = show.end
#     tags = show.tags
#     price = show.price
#     if request.method == "GET":
#         return render_template("createshow.html",flag = True,showname=name,showid = showid, rating=rating,start=start,end=end,tags=tags,price=price)
#     if request.method == "POST":
#         #check = Shows.query.filter_by().first()
#         #if(check):
#         #    return render_template("createshow.html",flag = True,msg = "show already exists",showname=name, rating=rating,start=start,end=end,tags=tags,price=price)
#         show.showname = request.form["showname"]
#         show.rating = request.form["rating"]
#         show.start = request.form["start"]
#         show.end=request.form["end"]
#         show.tags=request.form["tags"]
#         show.price=request.form["price"]

#         db.session.commit()
#         return redirect(url_for("adminhome"))
    