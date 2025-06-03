from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import pytz
import os
import logging
from logging.handlers import RotatingFileHandler
from flask_mail import Mail, Message
import jwt

# Configuración de logging
if not os.path.exists('logs'):
    os.makedirs('logs')
    
file_handler = RotatingFileHandler('logs/sisalud.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)

# Crear la aplicación Flask
app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:3000",  # Para desarrollo local
            "https://sisalud-frontend.onrender.com",  # Para el frontend en Render (ajusta según tu dominio)
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('SiSalud API startup')

# Configuración básica
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'tu_clave_secreta')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{os.path.abspath(os.path.dirname(__file__))}/instance/sisalud.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de correo electrónico
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'tu_email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'tu_password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'tu_email@gmail.com')

# Inicializar extensiones
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

mail = Mail(app)

# Modelos
class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(20), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    edad = db.Column(db.Integer)
    id_unico = db.Column(db.String(20), unique=True, nullable=False)
    especialidad = db.Column(db.String(100))
    cedula = db.Column(db.String(50))
    enfermedades = db.Column(db.Text)
    fecha_registro = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    activo = db.Column(db.Boolean, default=True)
    reset_token = db.Column(db.String(20))
    reset_token_expiry = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'tipo': self.tipo,
            'nombre': self.nombre,
            'email': self.email,
            'edad': self.edad,
            'id_unico': self.id_unico,
            'especialidad': self.especialidad,
            'cedula': self.cedula,
            'enfermedades': self.enfermedades,
            'fecha_registro': self.fecha_registro.strftime('%Y-%m-%d %H:%M:%S') if self.fecha_registro else None,
            'activo': self.activo
        }

class Appointment(db.Model):
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    doctor = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(5), nullable=False)
    status = db.Column(db.String(20), default='pendiente')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Decorador para requerir inicio de sesión
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor inicia sesión para acceder', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@app.route('/inicio')
def inicio():
    return render_template('inicio.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        tipo_usuario = request.form.get('tipo_usuario')
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        password = request.form.get('password')
        id_unico = request.form.get('id_unico')

        # Verificar si el email ya existe
        if Usuario.query.filter_by(email=email).first():
            flash('El correo electrónico ya está registrado', 'error')
            return render_template('registro.html', hide_nav=True)

        # Verificar si el ID único ya existe
        if Usuario.query.filter_by(id_unico=id_unico).first():
            flash('El ID único ya está en uso', 'error')
            return render_template('registro.html', hide_nav=True)

        # Crear nuevo usuario
        nuevo_usuario = Usuario(
            id_unico=id_unico,
            nombre=nombre,
            email=email,
            password=generate_password_hash(password),
            tipo=tipo_usuario,
            fecha_registro=datetime.now(pytz.UTC)
        )

        # Agregar campos específicos según el tipo de usuario
        if tipo_usuario == 'paciente':
            nuevo_usuario.edad = request.form.get('edad')
        elif tipo_usuario == 'doctor':
            nuevo_usuario.especialidad = request.form.get('especialidad')
            nuevo_usuario.cedula = request.form.get('cedula')

        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            # Iniciar sesión automáticamente después del registro
            session['usuario_id'] = nuevo_usuario.id
            session['usuario_tipo'] = nuevo_usuario.tipo
            flash('Registro exitoso', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error al registrar usuario: ' + str(e), 'error')
            return render_template('registro.html', hide_nav=True)

    return render_template('registro.html', hide_nav=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        id_unico = request.form.get('id_unico')
        password = request.form.get('password')

        usuario = Usuario.query.filter_by(id_unico=id_unico).first()

        if usuario and check_password_hash(usuario.password, password):
            session['usuario_id'] = usuario.id
            session['usuario_tipo'] = usuario.tipo
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('ID o contraseña incorrectos', 'error')
            return render_template('login.html', hide_nav=True)

    return render_template('login.html', hide_nav=True)

@app.route('/dashboard')
@login_required
def dashboard():
    usuario = Usuario.query.get(session['usuario_id'])
    
    if usuario.tipo == 'doctor':
        # Obtener citas del día para el doctor
        citas_hoy = Appointment.query.filter_by(
            user_id=usuario.id,
            date=datetime.now().strftime('%Y-%m-%d')
        ).all()
        return render_template('dashboard.html', 
                             usuario=usuario, 
                             citas_hoy=citas_hoy,
                             hide_nav=True,
                             hide_footer=True)
    else:
        # Obtener próxima cita y últimos registros para el paciente
        proxima_cita = Appointment.query.filter_by(
            user_id=usuario.id
        ).filter(
            Appointment.date >= datetime.now().strftime('%Y-%m-%d')
        ).first()
        
        return render_template('dashboard.html', 
                             usuario=usuario,
                             proxima_cita=proxima_cita,
                             hide_nav=True,
                             hide_footer=True)

@app.route('/cerrar_sesion')
def cerrar_sesion():
    session.clear()
    flash('Has cerrado sesión exitosamente', 'info')
    return redirect(url_for('inicio'))

@app.route('/datos_personales')
@login_required
def datos_personales():
    usuario = Usuario.query.get(session['usuario_id'])
    return render_template('datos_personales.html', usuario=usuario, hide_nav=True, hide_footer=True)

@app.route('/carga_documentos')
@login_required
def carga_documentos():
    return render_template('carga_documentos.html', hide_nav=True, hide_footer=True)

@app.route('/consulta_citas')
@login_required
def consulta_citas():
    usuario = Usuario.query.get(session['usuario_id'])
    if usuario.tipo == 'doctor':
        citas = Appointment.query.filter_by(user_id=usuario.id).all()
    else:
        citas = Appointment.query.filter_by(user_id=usuario.id).all()
    return render_template('consulta_citas.html', citas=citas, usuario=usuario, hide_nav=True, hide_footer=True)

@app.route('/admin/usuarios')
@login_required
def lista_usuarios():
    if current_user.tipo != 'admin':
        flash('No tienes permiso para acceder a esta página', 'error')
        return redirect(url_for('dashboard'))
        
    tipo_filtro = request.args.get('tipo', 'todos')
    
    if tipo_filtro != 'todos':
        usuarios = Usuario.query.filter_by(tipo=tipo_filtro, activo=True).order_by(Usuario.fecha_registro.desc()).all()
    else:
        usuarios = Usuario.query.filter_by(activo=True).order_by(Usuario.fecha_registro.desc()).all()
    
    total_usuarios = Usuario.query.filter_by(activo=True).count()
    total_doctores = Usuario.query.filter_by(tipo='doctor', activo=True).count()
    total_pacientes = Usuario.query.filter_by(tipo='paciente', activo=True).count()
    
    estadisticas = {
        'total': total_usuarios,
        'doctores': total_doctores,
        'pacientes': total_pacientes
    }
    
    return render_template('lista_usuarios.html', 
                         usuarios=usuarios, 
                         estadisticas=estadisticas,
                         tipo_actual=tipo_filtro)

@app.route('/admin/usuario/<int:id>/desactivar', methods=['POST'])
@login_required
def desactivar_usuario(id):
    if current_user.tipo != 'admin':
        flash('No tienes permiso para realizar esta acción', 'error')
        return redirect(url_for('dashboard'))
        
    usuario = Usuario.query.get_or_404(id)
    usuario.activo = False
    db.session.commit()
    flash('Usuario desactivado exitosamente', 'success')
    return redirect(url_for('lista_usuarios'))

@app.route('/admin/usuario/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if current_user.tipo != 'admin':
        flash('No tienes permiso para realizar esta acción', 'error')
        return redirect(url_for('dashboard'))
        
    usuario = Usuario.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            usuario.nombre = request.form['nombre']
            usuario.email = request.form['email']
            
            if usuario.tipo == 'paciente':
                edad = request.form.get('edad')
                if edad:
                    usuario.edad = int(edad)
            else:
                usuario.especialidad = request.form.get('especialidad')
                usuario.cedula = request.form.get('cedula')
            
            db.session.commit()
            flash('Usuario actualizado exitosamente', 'success')
            return redirect(url_for('lista_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar usuario: {str(e)}', 'error')
    
    return render_template('editar_usuario.html', usuario=usuario)

@app.route('/recuperar_password', methods=['GET', 'POST'])
def recuperar_password():
    if request.method == 'POST':
        email = request.form.get('email')
        usuario = Usuario.query.filter_by(email=email).first()
        
        if usuario:
            # Generar token de recuperación
            token = generate_password_hash(str(datetime.now()))[:20]
            usuario.reset_token = token
            usuario.reset_token_expiry = datetime.now() + timedelta(hours=24)
            db.session.commit()
            
            # Enviar correo de recuperación
            recovery_url = url_for('reset_password', token=token, _external=True)
            try:
                send_email(
                    'Recuperación de Contraseña - SiSalud',
                    usuario.email,
                    'email/notification',
                    title='Recuperación de Contraseña',
                    content='Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:',
                    action_url=recovery_url,
                    action_text='Restablecer Contraseña'
                )
                app.logger.info(f'Correo de recuperación enviado a {usuario.email}')
                flash('Se ha enviado un enlace de recuperación a tu correo', 'success')
            except Exception as e:
                app.logger.error(f'Error al enviar correo de recuperación: {str(e)}')
                flash('Error al enviar el correo de recuperación', 'error')
            
            return redirect(url_for('login'))
        else:
            flash('No se encontró una cuenta con ese correo', 'error')
    
    return render_template('recuperar_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    usuario = Usuario.query.filter_by(reset_token=token).first()
    
    if not usuario or usuario.reset_token_expiry < datetime.now():
        flash('El enlace de recuperación es inválido o ha expirado', 'error')
        return redirect(url_for('recuperar_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
            return render_template('reset_password.html')
        
        usuario.password = generate_password_hash(password)
        usuario.reset_token = None
        usuario.reset_token_expiry = None
        db.session.commit()
        
        flash('Tu contraseña ha sido actualizada exitosamente', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

def init_db():
    with app.app_context():
        # Crear todas las tablas
        db.create_all()
        
        # Verificar si ya existe un usuario administrador
        admin = Usuario.query.filter_by(tipo='admin').first()
        if not admin:
            # Crear usuario administrador por defecto
            admin = Usuario(
                tipo='admin',
                nombre='Administrador',
                email='admin@sisalud.com',
                password=generate_password_hash('admin123'),
                id_unico='ADMIN001',
                fecha_registro=datetime.now(pytz.UTC)
            )
            try:
                db.session.add(admin)
                db.session.commit()
                print('Usuario administrador creado exitosamente')
            except Exception as e:
                db.session.rollback()
                print(f'Error al crear usuario administrador: {str(e)}')

def send_email(subject, recipient, template, **kwargs):
    msg = Message(subject,
                 recipients=[recipient])
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Page not found: {request.url}')
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    app.logger.error(f'Forbidden access: {request.url}')
    return render_template('errors/403.html'), 403

# Rutas API
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    id_unico = data.get('id_unico')
    password = data.get('password')

    usuario = Usuario.query.filter_by(id_unico=id_unico).first()
    if usuario and check_password_hash(usuario.password, password):
        session['usuario_id'] = usuario.id
        return jsonify({
            'status': 'success',
            'message': 'Login exitoso',
            'user': usuario.to_dict()
        })
    return jsonify({
        'status': 'error',
        'message': 'Credenciales inválidas'
    }), 401

@app.route('/api/registro', methods=['POST'])
def api_registro():
    data = request.get_json()
    
    if Usuario.query.filter_by(email=data['email']).first():
        return jsonify({
            'status': 'error',
            'message': 'El correo electrónico ya está registrado'
        }), 400

    if Usuario.query.filter_by(id_unico=data['id_unico']).first():
        return jsonify({
            'status': 'error',
            'message': 'El ID único ya está en uso'
        }), 400

    nuevo_usuario = Usuario(
        tipo=data['tipo_usuario'],
        nombre=data['nombre'],
        email=data['email'],
        password=generate_password_hash(data['password']),
        id_unico=data['id_unico'],
        fecha_registro=datetime.now(pytz.UTC)
    )

    if data['tipo_usuario'] == 'paciente':
        nuevo_usuario.edad = data.get('edad')
    elif data['tipo_usuario'] == 'doctor':
        nuevo_usuario.especialidad = data.get('especialidad')
        nuevo_usuario.cedula = data.get('cedula')

    try:
        db.session.add(nuevo_usuario)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Usuario registrado exitosamente',
            'user': nuevo_usuario.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error al registrar usuario: {str(e)}'
        }), 500

@app.route('/api/usuarios', methods=['GET'])
def api_lista_usuarios():
    tipo_filtro = request.args.get('tipo', 'todos')
    
    if tipo_filtro != 'todos':
        usuarios = Usuario.query.filter_by(tipo=tipo_filtro, activo=True).all()
    else:
        usuarios = Usuario.query.filter_by(activo=True).all()
    
    return jsonify({
        'usuarios': [usuario.to_dict() for usuario in usuarios]
    })

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]

        if not token:
            return jsonify({'message': 'Token faltante'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'Token inválido'}), 401
            return f(current_user, *args, **kwargs)
        except:
            return jsonify({'message': 'Token inválido'}), 401
    return decorator

@app.route('/api/appointments', methods=['GET'])
@token_required
def get_appointments(current_user):
    appointments = Appointment.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'appointments': [{
            'id': a.id,
            'doctor': a.doctor,
            'date': a.date,
            'time': a.time,
            'status': a.status
        } for a in appointments]
    })

@app.route('/api/appointments/create', methods=['POST'])
@token_required
def create_appointment(current_user):
    data = request.get_json()

    if not all(k in data for k in ('doctor', 'date', 'time')):
        return jsonify({'message': 'Faltan datos requeridos'}), 400

    appointment = Appointment(
        user_id=current_user.id,
        doctor=data['doctor'],
        date=data['date'],
        time=data['time'],
        status=data.get('status', 'pendiente')
    )

    db.session.add(appointment)
    db.session.commit()

    return jsonify({
        'message': 'Cita creada exitosamente',
        'appointment': {
            'id': appointment.id,
            'doctor': appointment.doctor,
            'date': appointment.date,
            'time': appointment.time,
            'status': appointment.status
        }
    }), 201

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not all(k in data for k in ('name', 'email', 'password')):
        return jsonify({'message': 'Faltan datos requeridos'}), 400

    if Usuario.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'El correo electrónico ya está registrado'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = Usuario(
        nombre=data['name'],
        email=data['email'],
        password=hashed_password,
        tipo='paciente',
        id_unico=data['name'][:3].upper() + data['email'][:3].upper(),
        fecha_registro=datetime.now(pytz.UTC)
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login_api():
    data = request.get_json()

    if not all(k in data for k in ('email', 'password')):
        return jsonify({'message': 'Faltan datos requeridos'}), 400

    user = Usuario.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Credenciales inválidas'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(days=1)
    }, app.config['SECRET_KEY'])

    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'name': user.nombre,
            'email': user.email
        }
    })

if __name__ == '__main__':
    init_db()  # Inicializar la base de datos
    app.run(debug=True) 