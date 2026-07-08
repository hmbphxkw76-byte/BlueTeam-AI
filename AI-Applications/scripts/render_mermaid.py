import json
import os
import re
import subprocess
from pathlib import Path

from PIL import Image


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def extract_mermaid(doc_path: Path) -> str:
    doc = doc_path.read_text(encoding="utf-8")
    match = re.search(r"## 3\. 核心流程框架.*?```mermaid\n(.*?)```", doc, re.S)
    if not match:
        raise RuntimeError("未找到 §3 的 mermaid 流程图")
    src = match.group(1).strip()
    # 移除文档里用于 Markdown 预览放大的 init 指令，由 mmdc 统一控制样式
    src = re.sub(r"%%\{init:.*?\}%%\n?", "", src, flags=re.S).strip()
    return src


def main():
    doc_path = PROJECT_ROOT / "docs/architecture.md"
    out_dir = PROJECT_ROOT / "docs/images"
    out_dir.mkdir(parents=True, exist_ok=True)

    mmd_src = extract_mermaid(doc_path)
    mmd_path = out_dir / "core-flow.mmd"
    mmd_path.write_text(mmd_src, encoding="utf-8")

    config_path = out_dir / "mermaid-config.json"
    config_path.write_text(
        json.dumps(
            {
                "theme": "default",
                "flowchart": {
                    "nodeSpacing": 100,
                    "rankSpacing": 120,
                    "curve": "basis",
                    "padding": 30,
                },
                "themeVariables": {
                    "fontSize": "36px",
                    "primaryColor": "#e1f5fe",
                    "primaryTextColor": "#333",
                    "primaryBorderColor": "#0288d1",
                    "lineColor": "#666",
                    "secondaryColor": "#fff3e0",
                    "tertiaryColor": "#e8f5e9",
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    puppeteer_config = {
        "args": [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
        ],
    }
    if os.getenv("PUPPETEER_EXECUTABLE_PATH"):
        puppeteer_config["executablePath"] = os.getenv("PUPPETEER_EXECUTABLE_PATH")

    puppeteer_config_path = out_dir / "puppeteer-config.json"
    puppeteer_config_path.write_text(
        json.dumps(
            puppeteer_config,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    base_png = out_dir / "core-flow-base.png"
    final_png = out_dir / "core-flow-10x.png"

    # 使用 mermaid-cli 渲染高分辨率底图
    cmd = (
        f'npx -y @mermaid-js/mermaid-cli '
        f'-i "{mmd_path}" -o "{base_png}" '
        f'-c "{config_path}" -p "{puppeteer_config_path}" -b white -w 1600'
    )
    subprocess.run(cmd, check=True, cwd=str(PROJECT_ROOT), shell=True)

    # 用 PIL 放大 10 倍
    with Image.open(base_png) as img:
        new_size = (img.width * 10, img.height * 10)
        scaled = img.resize(new_size, Image.Resampling.LANCZOS)
        scaled.save(final_png, "PNG", dpi=(300, 300))

    print(f"已生成 10x 流程图: {final_png}")
    print(f"原始尺寸: {img.width}x{img.height}, 放大后: {new_size[0]}x{new_size[1]}")

    # 清理中间文件
    mmd_path.unlink(missing_ok=True)
    config_path.unlink(missing_ok=True)
    puppeteer_config_path.unlink(missing_ok=True)
    base_png.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
