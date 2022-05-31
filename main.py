import flask
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import SignUpForm, SignInForm
from functools import wraps
from flask import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sifone.db'
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


@app.route("/register", methods=["GET", "POST"])
def register():
    salt = "pbkdf2:sha256"
    salt_length = 8
    form = SignUpForm()
    if form.validate_on_submit():
        new_user = User(
            email=form.email.data,
            password=generate_password_hash(form.password.data, method=salt, salt_length=salt_length),
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home_page"))
    return render_template("signup.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/signin", methods=["GET", "POST"])
def signin():
    form = SignInForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flask.flash("That email is not tied to any account")
            return redirect(url_for("signin"))
        elif not check_password_hash(user.password, password):
            flask.flash("Incorrect Password")
            return redirect(url_for("signin"))
        else:
            login_user(user)
            flask.flash("Logged in Successfully")
            return redirect(url_for("home_page"))
    return render_template("signin.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home_page"))



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
