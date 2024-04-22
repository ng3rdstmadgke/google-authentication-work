from fastapi import FastAPI, Cookie, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
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

env = Environment()


app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )


@app.get("/callback_mode", response_class=HTMLResponse)
async def callback_mode(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="callback_mode.html",
        context={
            "client_id": env.client_id,
        }
    )

class SigninRequest(BaseModel):
    credential: str
    nonce: str

@app.post("/callback_mode/verify")
def api_verify(
    data: SigninRequest,
):
    idinfo = id_token.verify_oauth2_token(data.credential, requests.Request(), env.client_id)
    if idinfo['aud'] not in [env.client_id]:
        raise HTTPException(status_code=400, detail="Could not verify audience.")
    if idinfo['nonce'] != data.nonce:
        raise HTTPException(status_code=400, detail="nonce not match.")
    return idinfo