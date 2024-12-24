from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests
import requests as tmp_requests
from app.settings import get_env, templates, Environment

router = APIRouter()

#############################################
# OIDC方式
#############################################
@router.get("/oidc_mode/", response_class=HTMLResponse)
def oidc_mode(
    request: Request,
    env: Environment = Depends(get_env),
):
    """ログイン画面を表示する"""
    return templates.TemplateResponse(
        request=request,
        name="oidc_mode/index.html",
        context={
            "client_id": env.client_id,
        }
    )

@router.get("/oidc_mode/code", response_class=HTMLResponse)
def oidc_mode_code(request: Request):
    """認可レスポンスのリダイレクションエンドポイント"""
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

@router.post("/api/oidc_mode/token")
def oidc_mode_token(
    data: OidcModeTokenRequest,
    env: Environment = Depends(get_env),
):
    """認可コードをアクセストークンに交換する"""
    # - Google Identity - OpenID Connect - 4. code をアクセス トークンと ID トークンと交換する
    #   https://developers.google.com/identity/openid-connect/openid-connect?authuser=1&hl=ja#exchangecode
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

    # - Google Identity - OpenID Connect - 5. ID トークンからユーザー情報を取得する
    #   https://developers.google.com/identity/openid-connect/openid-connect?authuser=1&hl=ja#obtainuserinfo
    idinfo = id_token.verify_oauth2_token(token_response.id_token, requests.Request(), env.client_id)
    if idinfo['nonce'] != data.nonce:
        raise HTTPException(status_code=400, detail="nonce not match.")
    return {
        "token_response": token_response,
        "idinfo": idinfo,
    }
