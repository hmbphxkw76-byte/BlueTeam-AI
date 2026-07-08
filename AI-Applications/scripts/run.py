"""启动 AI-300 FastAPI 靶机（本地开发模式）。"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("src.llamafw:app", host="127.0.0.1", port=8000, reload=True)
