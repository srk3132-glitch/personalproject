"""Fine-tune a code model to classify snippets as vulnerable (1) or safe (0).
Data: CSV with columns `code,label`. Public sources: DiverseVul, CVEfixes, Devign, Big-Vul
(pick one, keep Python/JS/Java functions, split by *project* not randomly, export train.csv / val.csv).
Run:  pip install transformers datasets torch scikit-learn accelerate
      python train_classifier.py --train train.csv --val val.csv --out out
The backend auto-loads ./training/out (override with CS_CLASSIFIER_DIR)."""
import argparse, numpy as np
from datasets import load_dataset
from sklearn.metrics import precision_recall_fscore_support
from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments

ap = argparse.ArgumentParser()
ap.add_argument("--train", required=True); ap.add_argument("--val", required=True)
ap.add_argument("--base", default="microsoft/codebert-base"); ap.add_argument("--out", default="out")
ap.add_argument("--epochs", type=int, default=3)
a = ap.parse_args()

tok = AutoTokenizer.from_pretrained(a.base)
ds = load_dataset("csv", data_files={"train": a.train, "val": a.val})
ds = ds.map(lambda b: tok(b["code"], truncation=True, max_length=512, padding="max_length"), batched=True)
model = AutoModelForSequenceClassification.from_pretrained(a.base, num_labels=2)

def metrics(p):
    preds = np.argmax(p.predictions, axis=1)
    pr, rc, f1, _ = precision_recall_fscore_support(p.label_ids, preds, average="binary")
    return {"precision": pr, "recall": rc, "f1": f1}

Trainer(model=model, processing_class=tok, compute_metrics=metrics,
        args=TrainingArguments(output_dir=a.out, num_train_epochs=a.epochs, per_device_train_batch_size=8,
                               learning_rate=2e-5, eval_strategy="epoch", save_strategy="no", report_to=[]),
        train_dataset=ds["train"], eval_dataset=ds["val"]).train()
model.save_pretrained(a.out); tok.save_pretrained(a.out)
print("Saved to", a.out)
