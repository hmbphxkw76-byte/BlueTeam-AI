"""通过 ModelScope（魔搭）国内镜像下载 Prompt Guard 模型（无需 HF Token）"""
import os
import shutil
import sys
from pathlib import Path

# HuggingFace 镜像站，脚本直接运行时也生效
HF_ENDPOINT = "https://hf-mirror.com"
os.environ["HF_ENDPOINT"] = HF_ENDPOINT

PROJECT_ROOT = Path(__file__).resolve().parent  # prompt_guard_model/ 目录本身

# 安装 modelscope
try:
    from modelscope import snapshot_download
except ImportError:
    print("正在安装 modelscope...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "modelscope", "-q"])
    from modelscope import snapshot_download

model_name = "LLM-Research/Llama-Prompt-Guard-2-86M"

print(f"正在从 ModelScope（魔搭）下载模型: {model_name}")
print("国内直连，无需 HuggingFace Token")
print()

# 1. 从 ModelScope 下载
modelscope_path = snapshot_download(model_name)
print(f"ModelScope 下载完成: {modelscope_path}")

# 2. 复制到 HF 缓存目录（让 LlamaFirewall 能找到）
# 目录名固定为 meta-llama/Llama-Prompt-Guard-2-86M（LlamaFirewall 内部用的是这个名字）
hf_name = "meta-llama/Llama-Prompt-Guard-2-86M"
hf_name_clean = hf_name.replace("/", "--")

# 直接放在本地 ./models 目录下，然后在 .env 中设置 HF_HOME 指向此处
local_model_dir = PROJECT_ROOT / "models" / "hub" / f"models--{hf_name_clean}" / "snapshots" / "downloaded"
local_model_dir.mkdir(parents=True, exist_ok=True)

# 复制所有模型文件
src = Path(modelscope_path)
copied = 0
for f in src.iterdir():
    if f.is_file():
        target = local_model_dir / f.name
        if not target.exists() or f.stat().st_size != target.stat().st_size:
            shutil.copy2(f, target)
            copied += 1

print(f"已复制 {copied} 个文件到: {local_model_dir}")

# 3. 创建 refs 文件（huggingface_hub 需要）
refs_dir = local_model_dir.parent.parent / "refs"
refs_dir.mkdir(parents=True, exist_ok=True)
(refs_dir / "main").write_text("downloaded")

# 4. 将本地缓存目录注册到 .env；HF_ENDPOINT 只在脚本运行时生效
env_path = PROJECT_ROOT / ".env"
cache_root = str(PROJECT_ROOT / "models")
hf_home_line = f"HF_HOME={cache_root}"

# 读取 .env，检查是否已有 HF_HOME
if env_path.exists():
    env_content = env_path.read_text(encoding="utf-8")
    # 处理 HF_HOME
    if "HF_HOME=" in env_content:
        env_content = "\n".join(
            line if not line.startswith("HF_HOME=") else hf_home_line
            for line in env_content.splitlines()
        )
    else:
        env_content = f"{env_content}\n# 本地模型缓存目录\n{hf_home_line}\n"
    env_path.write_text(env_content, encoding="utf-8")
    print(f"已更新 .env: HF_HOME={cache_root}")
    print(f"当前脚本使用 HF_ENDPOINT={HF_ENDPOINT}")

print(f"\n✅ 完成！模型文件数: {len(list(local_model_dir.iterdir()))}")
print(f"   模型位置: {local_model_dir}")
print(f"   无需 HF Token，本地可直接使用")
