# SiSalud Backend API

Backend del sistema de gestión de salud SiSalud, desarrollado con Flask.

## Requisitos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)

## Instalación

1. Clonar el repositorio:
```bash
git clone <url-del-repositorio>
cd backend
```

2. Crear un entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instalar dependencias:
```bash
pip install -r requirements.txt
```

4. Configurar variables de entorno:
Crear un archivo `.env` con:
```
SECRET_KEY=tu_clave_secreta
DATABASE_URL=sqlite:///instance/sisalud.db
MAIL_USERNAME=tu_email@gmail.com
MAIL_PASSWORD=tu_password
MAIL_DEFAULT_SENDER=tu_email@gmail.com
```

## Ejecutar en desarrollo

```bash
python app.py
```

El servidor estará disponible en `http://127.0.0.1:5000`

## API Endpoints

### Autenticación

- POST `/api/auth/login`
  ```json
  {
    "email": "usuario@ejemplo.com",
    "password": "contraseña"
  }
  ```

- POST `/api/auth/register`
  ```json
  {
    "name": "Nombre Usuario",
    "email": "usuario@ejemplo.com",
    "password": "contraseña"
  }
  ```

### Citas

- GET `/api/appointments`
  - Requiere: Header `Authorization: Bearer <token>`
  - Retorna lista de citas del usuario

- POST `/api/appointments/create`
  - Requiere: Header `Authorization: Bearer <token>`
  ```json
  {
    "doctor": "Dr. Ejemplo",
    "date": "2024-03-20",
    "time": "15:30"
  }
  ```

## Despliegue

El backend está configurado para ser desplegado en servicios como Render o Heroku:

1. Configurar las variables de entorno en el panel del servicio
2. El archivo `Procfile` ya está configurado para usar gunicorn
3. La base de datos SQLite se puede reemplazar por PostgreSQL modificando DATABASE_URL

## Seguridad

- Autenticación mediante JWT
- CORS configurado para permitir solo dominios específicos
- Contraseñas hasheadas
- Protección contra CSRF
- Manejo seguro de sesiones 