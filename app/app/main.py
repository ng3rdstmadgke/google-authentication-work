from fastapi import FastAPI, Cookie, Request, HTTPException, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from google.oauth2 import id_token
from google.auth.transport import requests
import os
import hashlib

def random_string() -> str:
    return hashlib.sha256(os.urandom(1024)).hexdigest()

class Environment(BaseSettings):
    client_id: str = "578516381021-94ulrphd2s5ch0d6i9h12c8f5p31cb7m.apps.googleusercontent.com"
    redirect_uri: str = "http://localhost:8000/gtoken"

env = Environment()


app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
        }
    )

@app.get("/login", response_class=HTMLResponse)
def login(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "client_id": env.client_id,
            "redirect_uri": env.redirect_uri,
        }
    )


@app.post("/gtoken", response_class=HTMLResponse)
def gtoken(
    request: Request,
    g_csrf_token: str = Form(),
    credential: str = Form(),
):
    g_csrf_token_cookie = request.cookies.get("g_csrf_token")
    if g_csrf_token_cookie != g_csrf_token:
        raise HTTPException(status_code=404, detail="Failed to verify double submit cookie.")
    idinfo = id_token.verify_oauth2_token(credential, requests.Request(), env.client_id)
    if idinfo['aud'] not in [env.client_id]:
        raise HTTPException(status_code=404, detail="Could not verify audience.")
    return templates.TemplateResponse(
        request=request,
        name="gtoken.html",
        context={
            "idinfo": idinfo,
        }
    )

import hashlib
import os
