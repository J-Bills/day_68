from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE TABLE IN DB


class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form_data = request.form.to_dict()
        hash_password = generate_password_hash(form_data['password'], method='pbkdf2:sha256', salt_length=8)
        print(check_password_hash(hash_password,form_data.get('password')))
        user = db.session.execute(db.select(User).where(User.email == form_data.get('password'))).scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        form_data['password'] = hash_password
        new_user = User(**form_data)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets'))
    return render_template("register.html",logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            flash('That user doesn\'t exist.')
            return redirect(url_for('login'))
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html", logged_in =current_user.is_authenticated)



@login_required
@app.route('/secrets', methods=['GET','POST'])
def secrets():
    print(current_user)
    return render_template("secrets.html", user_name=current_user.name, logged_in=current_user.is_authenticated)

@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@login_required
@app.route('/download')
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
