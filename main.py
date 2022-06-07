import flask
from flask import Flask, render_template, redirect, url_for, flash, jsonify, request
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import SignUpForm, SignInForm
from functools import wraps
from flask import abort
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///sifone.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

#
# db.create_all()



def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.get_id() != "1":
            return abort(403)
        return function(*args, **kwargs)

    return decorated_function


@app.route("/")
def home_page():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route("/register", methods=["POST"])
def register():
    salt = "pbkdf2:sha256"
    salt_length = 8
    new_user = User(
        email=request.form.get("email"),
        password=generate_password_hash(request.form.get("password"), method=salt, salt_length=salt_length),
        name=request.form.get("name")
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return jsonify(response={"success": "Successfully added the new cafe."}), 200


@app.route("/signin", methods=["GET", "POST"])
def signin():
    email = request.args.get("email")
    password = request.args.get("password")
    user = db.session.query(User).filter_by(email=email).first()
    if user:
        return jsonify(cafe=user.to_dict())
    elif not user:
        return jsonify(error={"Not Found": "Sorry a user with that email was not found in the database."}), 404
    elif not check_password_hash(user.password, password):
        return jsonify(error={"Not Found": "Sorry your password does not match "
                                           "with that email was not found in the database."}), 404


@app.route("/logout")
def logout():
    pass



@app.route("/about")
def about():
    pass


@app.route("/search")
@login_required
def search():
    pass


@app.route("/news")
@login_required
def news():
    pass


@app.route("/support")
@login_required
def support():
    pass


if __name__ == "__main__":
    app.run(debug=True)
