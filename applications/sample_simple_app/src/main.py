import asyncio
import logging
import os

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

load_dotenv()

LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")

logger = logging.getLogger(__name__)
logging.basicConfig(level=LOG_LEVEL.upper())

RUN_HOST = os.environ.get("RUN_HOST", "0.0.0.0")
RUN_PORT = os.environ.get("RUN_PORT", "8080")
RELOAD = os.environ.get("RELOAD", "false").lower() in ["true", "t", "y", "yes"]
TOKEN_EXPIRATION_TIME = 3600
TOKEN_EXPIRATION_LOOKUP = 60

ROOT_DIR = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/..")

app = FastAPI()

templates = Jinja2Templates(directory=f"{ROOT_DIR}/templates")

templates.env.globals['title'] = 'Sample Simple APP'


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})


async def start_app():
    config = uvicorn.Config("src.main:app", host=RUN_HOST, port=int(RUN_PORT), log_level=LOG_LEVEL, reload=RELOAD)
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(start_app())
