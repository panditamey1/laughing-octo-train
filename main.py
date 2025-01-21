from fastapi import FastAPI, HTTPException, status, Depends, Header, File, UploadFile
from pydantic import BaseModel, EmailStr
import bcrypt
import pymysql
from typing import Optional
import jwt
from datetime import datetime, timedelta
import os

app = FastAPI()

# Database connection settings
db_config = {
    "host": "localhost",
    "user": "your_username",
    "password": "your_password",
    "database": "your_database",
    "cursorclass": pymysql.cursors.DictCursor
}

# JWT Secret Key and Algorithm
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Predefined directory for storing uploaded files
UPLOAD_DIRECTORY = "uploads/"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

# User input schema
class RegisterUser(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginUser(BaseModel):
    email: EmailStr
    password: str

# Dependency to get a database connection
def get_db():
    connection = pymysql.connect(**db_config)
    try:
        yield connection
    finally:
        connection.close()

# Helper function to decode JWT
def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token."
        )

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(user: RegisterUser, db=Depends(get_db)):
    """API endpoint to register a new user."""
    with db.cursor() as cursor:
        # Check if the username or email already exists
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (user.username, user.email))
        existing_user = cursor.fetchone()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already exists."
            )

        # Hash the password
        hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the database
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (user.username, user.email, hashed_password)
        )

        # Commit the transaction
        db.commit()

        return {"message": "User registered successfully."}

@app.post("/api/auth/login", status_code=status.HTTP_200_OK)
def login_user(user: LoginUser, db=Depends(get_db)):
    """API endpoint to log in a user and generate a JWT token."""
    with db.cursor() as cursor:
        # Fetch user by email
        cursor.execute("SELECT id, password FROM users WHERE email = %s", (user.email,))
        db_user = cursor.fetchone()

        if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user['password'].encode('utf-8')):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        # Generate JWT token
        payload = {
            "sub": db_user['id'],
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return {"access_token": token, "token_type": "bearer"}

@app.get("/api/user/profile", status_code=status.HTTP_200_OK)
def get_user_profile(Authorization: str = Header(...), db=Depends(get_db)):
    """API endpoint to fetch authenticated user details."""
    token = Authorization.split(" ")[1] if "Bearer" in Authorization else Authorization
    payload = decode_jwt(token)
    user_id = payload.get("sub")

    with db.cursor() as cursor:
        # Fetch user details by ID
        cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        return user

@app.post("/api/resume/upload", status_code=status.HTTP_201_CREATED)
def upload_resume(Authorization: str = Header(...), file: UploadFile = File(...), db=Depends(get_db)):
    """API endpoint to upload a resume and store metadata."""
    token = Authorization.split(" ")[1] if "Bearer" in Authorization else Authorization
    payload = decode_jwt(token)
    user_id = payload.get("sub")

    file_path = os.path.join(UPLOAD_DIRECTORY, file.filename)

    # Save the file to the predefined directory
    with open(file_path, "wb") as f:
        f.write(file.file.read())

    with db.cursor() as cursor:
        # Save metadata to the database
        cursor.execute(
            "INSERT INTO resumes (user_id, file_name, file_path, upload_date) VALUES (%s, %s, %s, %s)",
            (user_id, file.filename, file_path, datetime.utcnow())
        )
        db.commit()

    return {"message": "Resume uploaded successfully.", "file_name": file.filename}
