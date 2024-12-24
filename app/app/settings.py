from pydantic_settings import BaseSettings
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

class Environment(BaseSettings):
    client_id: str
    client_secret: str

def get_env() -> Environment:
    return Environment()