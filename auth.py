from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
import re 
import json
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
from flask_swagger_ui import get_swaggerui_blueprint
from flask_marshmallow import Marshmallow 



with open('config.json', 'r') as c:
    params = json.load(c)["params"]

local_server = True
app=Flask(__name__)


app.config['SECRET_KEY'] = 'thisissecret'
if(local_server):
    app.config['SQLALCHEMY_DATABASE_URI'] = params['local_uri']
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = params['prod_uri']



SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Test Task "
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)



db = SQLAlchemy(app)
ma = Marshmallow(app)

class User(db.Model):
    # __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    first_name=db.Column(db.String(),nullable=False)
    last_name=db.Column(db.String())
    username = db.Column(db.String(),unique=True, nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(),nullable=False)
    public_id = db.Column(db.String(), unique=True)
 

    @validates('username') 
    def validate_username(self, key, username):
        if not username:
            raise AssertionError('No username provided')
        if User.query.filter(User.username == username).first():
            raise AssertionError('Username is already in use')
        if len(username) < 5 or len(username) > 20:
            raise AssertionError('Username must be between 5 and 20 characters') 
        return username 
    @validates('email')     
    def validate_email(self, key, email):
        if not email:
            raise AssertionError('No email provided')
        if not re.match("[^@]+@[^@]+\.[^@]+", email):
            raise AssertionError('Provided email is not an email address') 
        return email
    
       

class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_title=db.Column(db.String())
    job_description=db.Column(db.String())
    job_rate=db.Column(db.Integer)
    latitude=db.Column(db.Float)
    longitude=db.Column(db.Float)
    is_active=db.Column(db.Boolean)
    user_id = db.Column(db.Integer)
    job_created=db.Column(db.DateTime)
    job_updated=db.Column(db.DateTime,nullable=True)

class jobSchema(ma.Schema):
    class Meta:
        fields = ('id','job_title','job_description','job_rate','latitude','longitude','is_active','user_id','job_created','job_updated')



db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token,  "secret", algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user,*args, **kwargs)

    return decorated



@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
#    if not current_user.username:
#         return jsonify({'message' : 'Cannot perform that function!'})
  
   
   users = User.query.all() 

   result = []   

   for user in users:   
       user_data = {}   
       user_data['public_id'] = user.public_id 
       user_data['first_name'] = user.first_name
       user_data['last_name'] = user.last_name  
       user_data['username'] = user.username 
       user_data['email'] = user.email 
       user_data['password'] = user.password

       
       result.append(user_data)   

   return jsonify({'users': result})


@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
 data = request.get_json()  

 hashed_password = generate_password_hash(data['password'], method='sha256')
 
 new_user = User(first_name=data['first_name'],last_name=data['last_name'],public_id=str(uuid.uuid4()), username=data['username'],email=data['email'], password=hashed_password) 
 db.session.add(new_user)  
 db.session.commit()    

 return jsonify({'message': 'registered successfully'})

# @app.route('/user/<public_id>', methods=['PUT'])
# @token_required
# def promote_user(current_user, public_id):
#     if not current_user.admin:
#         return jsonify({'message' : 'Cannot perform that function!'})

#     user = User.query.filter_by(public_id=public_id).first()

#     if not user:
#         return jsonify({'message' : 'No user found!'})

#     user.admin = True
#     db.session.commit()

#     return jsonify({'message' : 'The user has been promoted!'})


@app.route('/login', methods=['GET', 'POST'])  
def login():
    auth = request.authorization
    print("auth",auth)
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    print(auth.password)
    user = User.query.filter_by(username=auth.username).first()
    print("filter",user)
    if not user:
        print("FDFD2")
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    

 
    encoded = jwt.encode({'public_id' : user.public_id,}, "secret", algorithm="HS256")
    print(encoded)
    jwt.decode(encoded, "secret", algorithms=["HS256"])
    return jsonify({'token': encoded})


@app.route('/createjob', methods=['POST'])
@token_required
def create_job(current_user):
    data = request.get_json()
    print(data)
    new_job = Jobs(job_title=data['job_title'],job_description=data['job_description'],job_rate=data['job_rate'],latitude=data['latitude'],longitude=data['longitude'], is_active=True, user_id=current_user.id,job_created=datetime.datetime.utcnow(),job_updated=datetime.datetime.utcnow())
    db.session.add(new_job)
    db.session.commit()

    return jsonify({'message' : "job created!"})


@app.route('/job/<job_id>', methods=['PUT'])
@token_required
def update_job_by_id(current_user,job_id):
   data = request.get_json()
   print(data)
   get_job = Jobs.query.filter_by(id=job_id, user_id=current_user.id).first()
   print(get_job)
   #get_job = Jobs.query.get(id)
   if data.get('job_title'):
       get_job.job_title = data['job_title']
   if data.get('job_description'):
       get_job.job_description = data['job_description']
   if data.get('job_rate'):
       get_job.job_rate = data['job_rate']
   if data.get('latitude'):
       get_job.latitude = data['latitude']
   if data.get('longitude'):
       get_job.latitude = data['longitude']
  
   get_job.job_updated =datetime.datetime.utcnow()
   db.session.add(get_job)
   db.session.commit()

   return jsonify({'message' : 'The job has been updated!'})

      

@app.route('/job/<job_id>', methods=['DELETE'])
@token_required
def delete_job(current_user,job_id):
    job = Jobs.query.filter_by(id=job_id, user_id=current_user.id).first()
    # job=Jobs.query.get(id)
    if not job:
        return jsonify({'message' : 'No job found!'})

    db.session.delete(job)
    db.session.commit()

    return jsonify({'message' : 'job  deleted!'})



@app.route('/jobs', methods=['GET'])
@token_required
def get_all_jobs(current_user):
    jobs = Jobs.query.filter_by(user_id=current_user.id).all()

    output = []

    for job in jobs:
        job_data = {}
        job_data['id'] = job.id
        job_data['job_title'] = job.job_title
        job_data['job_description'] = job.job_description
        job_data['job_rate'] = job.job_rate
        job_data['job_created'] = job.job_created
        job_data['job_updated'] = job.job_updated
        job_data['latitude'] = job.latitude
        job_data['longitude'] = job.longitude
        output.append(job_data)

    return jsonify({'jobs' : output})




if __name__ == '__main__':
    app.run(debug=True)