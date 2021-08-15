from flask import Flask, request, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from decouple import config
import json
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = config('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120))
    surname = db.Column(db.String(120))
    is_parent = db.Column(db.Boolean)
    password = db.Column(db.String(500))
    token = db.Column(db.String(500))

    def __repr__(self):
        return '<User %r>' % self.id


class Family(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    id_parent = db.Column(db.Integer)
    id_child = db.Column(db.Integer)

    def __repr__(self):
        return '<Family %r>' % self.id


class Metric(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    id_user = db.Column(db.Integer)
    timestamp = db.Column(db.Integer)
    latitude = db.Column(db.Integer)
    longitude = db.Column(db.Integer)
    cell_id = db.Column(db.Integer)
    lac = db.Column(db.Integer)
    rsrp = db.Column(db.Integer)
    rsrq = db.Column(db.Integer)
    sinr = db.Column(db.Integer)
    device_id = db.Column(db.String(120))
    imsi = db.Column(db.String(120))

    def __repr__(self):
        return '<Metric %r>' % self.id


db.create_all()


@app.route('/')
def home():
    return Response('[territory of 2 engers]', status=200)


@app.route('/auth/registration', methods=['POST'])
def registration():
    value = request.json
    token = jwt.encode({'email': value['email']}, key=app.config['SECRET_KEY'])
    user = User(
        email=value['email'],
        name=value['name'],
        surname=value['surname'],
        is_parent=value['is_parent'],
        password=generate_password_hash(value['password']),
        token=token
    )
    try:
        db.session.add(user)
        db.session.commit()
        if not value['is_parent']:
            parent = User.query.filter_by(email=value['parent_email']).first()
            child = User.query.filter_by(email=value['email']).first()
            family = Family(id_parent=parent.id, id_child=child.id)
            db.session.add(family)
            db.session.commit()
        response = json.dumps({'token': token})
        return Response(response, status=200, mimetype='application/json')
    except:
        return Response(status=400)


@app.route('/auth/login', methods=['POST'])
def login():
    value = request.json
    user = User.query.filter_by(email=value['email']).first()
    if check_password_hash(user.password, value['password']):
        response = json.dumps({'token': user.token, 'is_parent': user.is_parent})
        return Response(response, status=200, mimetype='application/json')
    else:
        return Response(status=400)


@app.route('/users/children', methods=['GET'])
def get_children():
    token = request.headers.get('Authorization')
    user = User.query.filter_by(token=token).first()
    if user.is_parent:
        family = Family.query.filter_by(id_parent=user.id).all()
        children = []
        for pair in family:
            child = User.query.filter_by(id=pair.id_child).first()
            children.append({
                "id": child.id,
                "email": child.email,
                "name": child.name,
                "surname": child.surname
            })
        response = json.dumps({'children': children})
        return Response(response, status=200, mimetype='application/json')
    else:
        return Response(status=400)


@app.route('/metrics', methods=['POST'])
def send_metrics():
    value = request.json
    token = request.headers.get('Authorization')
    user = User.query.filter_by(token=token).first()
    metric = Metric(
        id_user=user.id,
        timestamp=value['timestamp'],
        latitude=value['latitude'],
        longitude=value['longitude'],
        cell_id=value['cell_id'],
        lac=value['lac'],
        rsrp=value['rsrp'],
        rsrq=value['rsrq'],
        sinr=value['sinr'],
        device_id=value['device_id'],
        imsi=value['imsi']
    )
    try:
        db.session.add(metric)
        db.session.commit()
        return Response(status=200)
    except:
        return Response(status=400)


@app.route('/metrics/user/<int:id>', methods=['GET'])
def get_metrics(id):
    token = request.headers.get('Authorization')
    user = User.query.filter_by(token=token).first()
    if (user.is_parent and Family.query.filter_by(id_parent=user.id, id_child=id).first()
            or User.query.filter_by(token=token).first().id == id):
        values = Metric.query.filter_by(id_user=id).all()
        metrics = []
        for value in values:
            metrics.append({
                "timestamp": value.timestamp,
                "latitude": value.latitude,
                "longitude": value.longitude,
                "cell_id": value.cell_id,
                "device_id": value.device_id,
                "lac": value.lac,
                "rsrp": value.rsrp,
                "rsrq": value.rsrq,
                "sinr": value.sinr,
                "imsi": value.imsi,
            })
        response = json.dumps({'metrics': metrics})
        return Response(response, status=200, mimetype='application/json')
    else:
        return Response(status=400)


if __name__ == '__main__':
    app.run()
