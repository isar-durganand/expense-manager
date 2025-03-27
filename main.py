from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Expense
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey123'

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create database tables
with app.app_context():
    db.create_all()


# Auth routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter((User.username == username)
                                          | (User.email == email)).first()

        if existing_user:
            flash('Username/Email already exists!', 'danger')
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check username/password', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Expense routes
@app.route('/')
@login_required
def index():
    month_filter = request.args.get('month')
    query = Expense.query.filter_by(user_id=current_user.id)

    if month_filter:
        year, month = month_filter.split('-')
        query = query.filter(
            db.func.strftime("%Y-%m", Expense.date) == f"{year}-{month}")

    expenses = query.order_by(Expense.date.desc()).all()
    total = sum(expense.amount for expense in expenses)

    category_data = defaultdict(float)
    for expense in expenses:
        category_data[expense.category] += expense.amount

    return render_template('index.html',
                           expenses=expenses,
                           total=total,
                           categories=list(category_data.keys()),
                           amounts=[float(v) for v in category_data.values()],
                           current_month=month_filter
                           or datetime.today().strftime('%Y-%m'))


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        try:
            new_expense = Expense(amount=float(request.form['amount']),
                                  category=request.form['category'],
                                  description=request.form['description'],
                                  date=request.form['date']
                                  or datetime.today().strftime('%Y-%m-%d'),
                                  user_id=current_user.id)
            db.session.add(new_expense)
            db.session.commit()
            flash('Expense added successfully!', 'success')
        except:
            db.session.rollback()
            flash('Error adding expense!', 'danger')
        return redirect(url_for('index'))

    return render_template('add_expense.html')


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_expense(id):
    expense = Expense.query.filter_by(id=id,
                                      user_id=current_user.id).first_or_404()

    if request.method == 'POST':
        try:
            expense.amount = float(request.form['amount'])
            expense.category = request.form['category']
            expense.description = request.form['description']
            expense.date = request.form['date']
            db.session.commit()
            flash('Expense updated successfully!', 'info')
        except:
            db.session.rollback()
            flash('Error updating expense!', 'danger')
        return redirect(url_for('index'))

    return render_template('edit_expense.html', expense=expense)


@app.route('/delete/<int:id>')
@login_required
def delete_expense(id):
    try:
        expense = Expense.query.filter_by(
            id=id, user_id=current_user.id).first_or_404()
        db.session.delete(expense)
        db.session.commit()
        flash('Expense deleted successfully!', 'warning')
    except:
        db.session.rollback()
        flash('Error deleting expense!', 'danger')
    return redirect(url_for('index'))


@app.route('/export')
@login_required
def export_csv():
    expenses = Expense.query.filter_by(user_id=current_user.id).order_by(
        Expense.date).all()
    csv_data = "Date,Category,Description,Amount\n"
    for expense in expenses:
        csv_data += f"{expense.date},{expense.category},{expense.description},{expense.amount}\n"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=expenses.csv"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
