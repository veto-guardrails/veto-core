import logging
import os

from fastapi import FastAPI
from pydantic import BaseModel, Field
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

MODEL_ID = os.getenv("VETO_INJECTION_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
MAX_LEN = int(os.getenv("VETO_MAX_LEN", "512"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("veto-inference")

log.info("loading model %s", MODEL_ID)
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
model.eval()

id2label = {int(k): v for k, v in model.config.id2label.items()}
injection_idx = next((i for i, lbl in id2label.items() if lbl.upper().startswith("INJ")), 1)
log.info("model ready: labels=%s injection_idx=%d", id2label, injection_idx)


class DetectRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=32_000)


app = FastAPI(title="veto-inference", version="0.1.0")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "model": MODEL_ID}


@torch.inference_mode()
@app.post("/detect/injection")
def detect_injection(req: DetectRequest):
    inputs = tokenizer(
        req.text,
        return_tensors="pt",
        truncation=True,
        max_length=MAX_LEN,
    )
    logits = model(**inputs).logits[0]
    probs = torch.softmax(logits, dim=-1).tolist()
    score = float(probs[injection_idx])
    label = id2label[int(torch.argmax(logits).item())]
    return {"injection": score, "label": label, "probs": probs}
