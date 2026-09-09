"""
SecureMailScope - Development Server Runner
Launches the FastAPI application using Uvicorn with optimized hot-reloading
restricted to the 'securemailscope' directory, preventing reload loops on OneDrive/.venv.
"""

import uvicorn

if __name__ == "__main__":
    print("======================================================================")
    print("SecureMailScope - Cryptographic Posture Assessment Framework")
    print("Starting API Server on http://127.0.0.1:8000")
    print("Interactive Documentation: http://127.0.0.1:8000/docs")
    print("======================================================================")
    uvicorn.run(
        "securemailscope.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["securemailscope"],
        reload_excludes=[".venv", "tests", "*.pcap", "__pycache__", ".git"],
        log_level="info",
    )
