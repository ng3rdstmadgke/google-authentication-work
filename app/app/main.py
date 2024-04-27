import os
import hashlib
import json
from typing import Optional
from fastapi import FastAPI, Cookie, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from google.oauth2 import id_token
from google.auth.transport import requests
import requests as tmp_requests

def random_string() -> str:
    return hashlib.sha256(os.urandom(1024)).hexdigest()

class Environment(BaseSettings):
    client_id: str
    client_secret: str

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

#############################################
# リダイレクト
#############################################
@app.get("/redirect_mode/", response_class=HTMLResponse)
async def redirect_mode(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="redirect_mode/index.html",
        context={
            "client_id": env.client_id,
        }
    )

@app.post("/redirect_mode/verify", response_class=HTMLResponse)
def redirect_mode_verify(
    request: Request,
    # パラメータ: https://developers.google.com/identity/gsi/web/reference/html-reference?authuser=1&hl=ja#server-side
    credential: str = Form(...),
    g_csrf_token: str = Form(...),
    select_by: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
):
    csrf_token_cookie = request.cookies.get("g_csrf_token")
    if not csrf_token_cookie:
        raise HTTPException(status_code=400, detail="No CSRF token in Cookie.")
    if g_csrf_token != csrf_token_cookie:
        raise HTTPException(status_code=400, detail="Failed to verify double submit cookie.")

    idinfo = id_token.verify_oauth2_token(credential, requests.Request(), env.client_id)
    if idinfo['aud'] not in [env.client_id]:
        raise HTTPException(status_code=400, detail="Could not verify audience.")

    return templates.TemplateResponse(
        request=request,
        name="redirect_mode/verify.html",
        context={
            "redirect_form_data": json.dumps({
                "credential": credential,
                "g_csrf_token": g_csrf_token,
                "select_by": select_by,
                "state": state,
            }, ensure_ascii=False),
            "idinfo": json.dumps(idinfo, ensure_ascii=False),
        }
    )

#############################################
# コールバック
#############################################
@app.get("/callback_mode/", response_class=HTMLResponse)
async def callback_mode(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="callback_mode/index.html",
        context={
            "client_id": env.client_id,
        }
    )

class CallBackVerifyRequest(BaseModel):
    credential: str
    nonce: str

@app.post("/api/callback_mode/verify")
def callback_mode_verify(
    data: CallBackVerifyRequest,
):
    idinfo = id_token.verify_oauth2_token(data.credential, requests.Request(), env.client_id)
    if idinfo['aud'] not in [env.client_id]:
        raise HTTPException(status_code=400, detail="Could not verify audience.")
    if idinfo['nonce'] != data.nonce:
        raise HTTPException(status_code=400, detail="nonce not match.")
    return idinfo


#############################################
# OIDC
#############################################
@app.get("/oidc_mode/", response_class=HTMLResponse)
def oidc_mode(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="oidc_mode/index.html",
        context={
            "client_id": env.client_id,
        }
    )

@app.get("/oidc_mode/code", response_class=HTMLResponse)
def oidc_mode_code(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="oidc_mode/code.html",
        context={}
    )

class OidcModeTokenRequest(BaseModel):
    code: str
    nonce: str

class GoogleOidcTokenResponse(BaseModel):
    access_token: str
    expires_in: int
    id_token: str
    scope: str
    token_type: str
    refresh_token: Optional[str] = None  # 認証リクエストで access_type パラメータが offline に設定されている場合にのみ

@app.post("/api/oidc_mode/token")
def oidc_mode_token(
    data: OidcModeTokenRequest,
):
    # 4. code をアクセス トークンと ID トークンと交換する
    # https://developers.google.com/identity/openid-connect/openid-connect?authuser=1&hl=ja#exchangecode
    url = "https://oauth2.googleapis.com/token"
    res = tmp_requests.post(
        url=url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        params={
            "code": data.code,
            "client_id": env.client_id,
            "client_secret": env.client_secret,
            "redirect_uri": "http://localhost:8000/oidc_mode/code",
            "grant_type": "authorization_code",
        }
    )
    if res.status_code != 200:
        raise HTTPException(status_code=400, detail=res.text)

    token_response = GoogleOidcTokenResponse.model_validate(res.json())
    idinfo = id_token.verify_oauth2_token(token_response.id_token, requests.Request(), env.client_id)
    if idinfo['nonce'] != data.nonce:
        raise HTTPException(status_code=400, detail="nonce not match.")
    return {
        "token_response": token_response,
        "idinfo": idinfo,
    }
