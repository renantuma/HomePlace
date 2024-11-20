from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.secret_key = 'Campos1971'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = './static/uploads'  


if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    value = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='items', lazy=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Você entrou com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nome de usuário ou senha incorretos.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já está em uso.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('E-mail já cadastrado.', 'danger')
        else:
            new_user = User(username=username, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/')
def dashboard():
    if 'user_id' not in session:
        flash('Por favor, faça login antes de acessar o dashboard.', 'warning')
        return redirect(url_for('login'))
    
    
    user = User.query.get(session['user_id'])

    items = Item.query.all()

    return render_template('dashboard.html', username=user.username, items=items)

@app.route('/add-item', methods=['GET', 'POST'])
def add_item():
    if 'user_id' not in session:
        flash('Por favor, faça login antes de adicionar um item.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        description = request.form['description']
        value = request.form['value']
        image = request.files['image']

        
        if image:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(image_path)

            
            new_item = Item(
                image=f"uploads/{image.filename}",
                description=description,
                value=float(value),
                user_id=session['user_id']
            )
            db.session.add(new_item)
            db.session.commit()
            flash('Item adicionado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('add_item.html')

@app.route('/delete-item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if 'user_id' not in session:
        flash('Faça login para continuar.', 'warning')
        return redirect(url_for('login'))

   
    item = Item.query.get_or_404(item_id)

    
    if item.user_id != session['user_id']:
        flash('Você não tem permissão para excluir este item.', 'danger')
        return redirect(url_for('dashboard'))

    
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(item.image))
    if os.path.exists(image_path):
        os.remove(image_path)

    
    db.session.delete(item)
    db.session.commit()

    flash('Item excluído com sucesso!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
