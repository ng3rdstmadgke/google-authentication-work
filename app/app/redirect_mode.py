import json
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse
from google.oauth2 import id_token
from google.auth.transport import requests
from app.settings import get_env, templates, Environment

router = APIRouter()

#############################################
# リダイレクト方式
#############################################
@router.get("/redirect_mode/", response_class=HTMLResponse)
async def redirect_mode(
    request: Request,
    env: Environment = Depends(get_env),
):
    """ログイン画面を表示する"""
    return templates.TemplateResponse(
        request=request,
        name="redirect_mode/index.html",
        context={
            "client_id": env.client_id,
        }
    )

@router.post("/redirect_mode/verify", response_class=HTMLResponse)
def redirect_mode_verify(
    request: Request,
    # パラメータ: 
    credential: str = Form(...),
    g_csrf_token: str = Form(...),
    select_by: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    env: Environment = Depends(get_env),
):
    """
    認可レスポンスのリダイレクションエンドポイント。IDトークンを検証する
    このエンドポイントのパラメータには以下が含まれます
    - Google Identity - ウェブでGoogleでログイン - HTML API - サーバーサイドの統合
      https://developers.google.com/identity/gsi/web/reference/html-reference?authuser=1&hl=ja#server-side
    """

    # CSRFトークンの検証 (認可レスポンスのパラメータとCookieの値を比較する)
    csrf_token_cookie = request.cookies.get("g_csrf_token")
    if not csrf_token_cookie:
        raise HTTPException(status_code=400, detail="No CSRF token in Cookie.")
    if g_csrf_token != csrf_token_cookie:
        raise HTTPException(status_code=400, detail="Failed to verify double submit cookie.")

    # IDトークンの検証
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
