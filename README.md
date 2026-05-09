# SecureVault — SWE210 Group Project

A secure Flask web application demonstrating Authentication, RBAC, and Fernet encryption with MongoDB.

## Project Structure

```
sofware scurity project/
│
├── 📄 app.py
├── 📄 requirements.txt
├── 📄 README.md
│
├── 📁 static/
│   └── 🖼️  hexagon.ico
│
└── 📁 templates/
    ├── 🧱 base.html
    ├── 🏠 index.html
    ├── 🔑 login.html
    ├── 📝 register.html
    ├── 📊 dashboard.html
    ├── ⚙️  admin.html
    ├── 🚫 403.html
    └── ❓ 404.html
```

## Setup & Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Start MongoDB
Make sure MongoDB is running locally:
```bash
mongod
```
Or set a custom URI via environment variable:
```bash
export MONGO_URI="mongodb://localhost:27017/"
```

### 3. (Optional) Set a persistent Fernet key
If you want encrypted notes to survive app restarts, generate and save a key:
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```
Then:
```bash
export FERNET_KEY="your-generated-key-here"
```

### 4. Set a strong secret key for sessions
```bash
export SECRET_KEY="your-very-random-secret-key"
```

### 5. Before running the app
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
then
```bash
set FERNET_KEY= paste your key here
python app.py
```

### 6. Run the app
```bash
python app.py
```
Visit: http://127.0.0.1:5000

## Creating an Admin User

1. Register a normal user account via the UI.
2. Open MongoDB shell or Compass and run:
```js
use secure_web_app
db.users.updateOne({ username: "your_username" }, { $set: { role: "admin" } })
```
3. Log in — you'll now see the Admin Panel link.

Alternatively, once one admin exists, they can promote other users directly from the Admin Panel UI.

## Security Features

| Feature | Implementation |
|---|---|
| Password hashing | `werkzeug.security.generate_password_hash` (Bcrypt) |
| No plaintext passwords | Passwords never stored or logged |
| RBAC | `role` field in MongoDB (`user` / `admin`) |
| Admin route protection | `@admin_required` decorator → returns 403 if not admin |
| UI role-based rendering | Jinja2 `{% if current_user.role == 'admin' %}` blocks |
| Data encryption | `cryptography.Fernet` (AES-128-CBC + HMAC-SHA256) |
| Input validation | Length checks, required fields, injection-safe (PyMongo parameterized) |
| Session management | Flask server-side sessions with signed cookies |

## Routes

| Route | Access | Description |
|---|---|---|
| `/` | Public | Landing page |
| `/register` | Public | User registration |
| `/login` | Public | User login |
| `/logout` | Logged in | Clear session |
| `/dashboard` | Logged in | View/add/delete encrypted notes |
| `/admin` | Admin only | User management panel |
| `/admin/promote/<id>` | Admin only | Promote user to admin |
| `/admin/demote/<id>` | Admin only | Demote admin to user |
| `/admin/delete_user/<id>` | Admin only | Delete user account |
