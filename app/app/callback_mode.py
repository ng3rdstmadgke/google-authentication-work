from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests
from app.settings import get_env, templates, Environment

router = APIRouter()

#############################################
# コールバック方式
#############################################
@router.get("/callback_mode/", response_class=HTMLResponse)
async def callback_mode(
    request: Request,
    env: Environment = Depends(get_env)
):
    """ログイン画面を表示する"""
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

@router.post("/api/callback_mode/verify")
def callback_mode_verify(
    data: CallBackVerifyRequest,
    env: Environment = Depends(get_env)
):
    """認可レスポンスのIDトークンを検証する"""
    idinfo = id_token.verify_oauth2_token(data.credential, requests.Request(), env.client_id)
    if idinfo['aud'] not in [env.client_id]:
        raise HTTPException(status_code=400, detail="Could not verify audience.")
    if idinfo['nonce'] != data.nonce:
        raise HTTPException(status_code=400, detail="nonce not match.")
    return idinfo