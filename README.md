# CodeShield AI
Semgrep static scan -> LLM triage/patch (+ optional model you fine-tune) -> dashboard + Markdown report.

## Run
    cd backend
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=your_key      # optional; without it you still get scanner findings
    uvicorn main:app --reload
Open http://127.0.0.1:8000 and click "Load vulnerable sample".
If Semgrep isn't available on your OS (use WSL on Windows), a regex fallback engine is used automatically.

## Train your own model (later)
See training/train_classifier.py. Put the output at training/out and each finding gets a "model: NN% vuln" badge.

## Deploy
Needs git + semgrep, so use a container host (Render, Railway, Fly.io), not Vercel serverless.
