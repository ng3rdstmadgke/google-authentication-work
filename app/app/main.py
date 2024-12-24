from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from app.settings import templates
from app.redirect_mode import router as redirect_router
from app.callback_mode import router as callback_router
from app.oidc_mode import router as oidc_router


app = FastAPI()
# 静的ファイル
app.mount("/static", StaticFiles(directory=f"static/", html=True), name="front")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )

app.include_router(redirect_router)
app.include_router(callback_router)
app.include_router(oidc_router)