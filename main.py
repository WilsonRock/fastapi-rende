from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from pytube import YouTube
import sqlite3
from passlib.hash import pbkdf2_sha256
from jose import JWTError, jwt
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup


app = FastAPI(title="Laboratorio Gisoft 2023",
    version="0.0.1",
    terms_of_service="http://example.com/terms/",
    contact={
        "name": "Deadpoolio the Amazing",
        "url": "http://x-force.example.com/contact/",
        "email": "dp@x-force.example.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },)

security = HTTPBasic()
globals = {}

# Define user model
class User(BaseModel):
    username: str
    password: str
    
class CreditCard(BaseModel):
    number: str
    expiration_month: str
    expiration_year: str
    cvv: str

    

# Create users table in SQLite
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL UNIQUE,
              password TEXT NOT NULL);''')
conn.commit()
conn.close()
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS credit_cards
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              number TEXT NOT NULL,
              expiration_month TEXT NOT NULL,
              expiration_year TEXT NOT NULL,
              cvv TEXT NOT NULL);''')
conn.commit()
conn.close()


# Secret key for signing JWT tokens
SECRET_KEY = "mysecretkey"

# Token expiration time in minutes
EXPIRATION_TIME = 30

# Generate JWT token
def create_token(username: str, password: str):
    expiration = datetime.utcnow() + timedelta(minutes=EXPIRATION_TIME)
    token_payload = {"sub": username, "exp": expiration}
    return jwt.encode(token_payload, SECRET_KEY)

# Verify JWT token
def verify_token(token: str):
    try:
        token_payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = token_payload["sub"]
        globals['user'] = username
        return True
    except JWTError:
        return False

# Verify user credentials
def verify_user(username: str, password: str):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        hashed_password = result[0]
        return pbkdf2_sha256.verify(password, hashed_password)
    else:
        return False

# Endpoint for registering a new user
@app.post("/register")
async def register(user: User):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed_password = pbkdf2_sha256.hash(user.password)
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_password))
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    token = create_token(user.username, user.password)
    return {"message": f"User with ID {user_id} has been registered", "token": token}

# Endpoint for downloading a video
@app.get("/download_video/{extension}")
async def download_video(video_url: str = Query(...), extension: str = None, token: str = Query(...)):
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        # Instantiate a YouTube object with the video URL
        yt = YouTube(video_url)

        # Print video title
        title = yt.title

        # Filter streams by extension if specified
        if extension:
            streams = yt.streams.filter(progressive=True, file_extension=extension)
        else:
            streams = yt.streams.filter(progressive=True)

        # Get the first stream with the highest resolution and download it
        stream = streams.order_by('resolution').desc().first()
        file_path = stream.download()

        # Return the video title and file path as a response
        return {"title": title, "file_path": file_path}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/vulnerable")
async def vulnerable_page(query_param: str):
    username = credentials.username
    password = credentials.password
    if not verify_user(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    sanitized_param = html.escape(query_param)
    return f"<h1>¡Hola, {sanitized_param}!</h1>"


""" @app.post("/login")
async def login(credentials: HTTPBasicCredentials = Depends(security)):
    user = await authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"message": "Logged in successfully"} """
# Endpoint for user login
@app.post("/login")
async def login(credentials: HTTPBasicCredentials):
    username = credentials.username
    password = credentials.password
    if not verify_user(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(username, password)
    return {"token": token}

@app.get("/vulnerable_sql")
async def vulnerable_sql(query_param: str, token: str = Query(...)):
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Invalid token")
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    query = f"SELECT * FROM credit_cards WHERE number = '{query_param}'"
    c.execute(query)
    result = c.fetchone()
    conn.close()
    if result:
        return {"credit_card": result}
    else:
        raise HTTPException(status_code=404, detail="Credit card not found")

# Endpoint for adding a credit card
@app.post("/credit_cards")
async def add_credit_card(credit_card: CreditCard, token: str = Query(...)):
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Invalid token")
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO credit_cards (number, expiration_month, expiration_year, cvv) VALUES (?, ?, ?, ?)",
              (credit_card.number, credit_card.expiration_month, credit_card.expiration_year, credit_card.cvv))
    credit_card_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"message": f"Credit card with ID {credit_card_id} has been added"}

@app.get("/download_video/")
async def download_video(url: str):
    # Obtener el contenido de la página
    response = requests.get(url)
    html = response.content

    # Utilizar BeautifulSoup para extraer la URL del video
    soup = BeautifulSoup(html, 'html.parser')
    source_tag = soup.find('source')

    if source_tag is not None:
        video_url = source_tag['src']
        # Descargar el video
        video_response = requests.get(video_url, stream=True)

        # Enviar la descarga del video al cliente
        headers = {
            'Content-Type': 'video/mp4',
            'Content-Disposition': 'attachment; filename=video.mp4',
        }
        return StreamingResponse(video_response.iter_content(chunk_size=1024), headers=headers)
    else:
        # Manejar el caso en que no se encontró la URL del video
        return {"message": "No se encontró la URL del video en la página."}



        




    return {"message": inp.msg.upper()}


@app.get("/path/{path_id}")
async def demo_get_path_id(path_id: int):
    return {"message": f"This is /path/{path_id} endpoint, use post request to retrieve result"}
