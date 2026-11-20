"""Byte-level char-CNN of notebook 13 (identical architecture, training and seeds),
with the trained weights cached in models/ so notebooks 15 and 16 can reuse them.

`get_cnn(cfg, seed, train, val)` trains once per (cfg, seed) and afterwards loads
models/charcnn_<cfg>_<seed>.pt. Training is deterministic
(torch.use_deterministic_algorithms, 4 CPU threads), so epochs and validation F1
must match results/13_char_cnn_raw.csv.
"""

from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from experiments import rates
from normalize import normalize

MODELS = Path(__file__).resolve().parent.parent / "models"
MAXLEN, BATCH, EPOCHS, PATIENCE = 512, 128, 10, 3
torch.set_num_threads(4)
torch.use_deterministic_algorithms(True)

CONFIGS = {"CNN baza": str.lower, "CNN + normallaşdırma": normalize}
_SLUG = {"CNN baza": "base", "CNN + normallaşdırma": "norm"}


class CharCNN(nn.Module):
    def __init__(self, emb=32, filters=64, kernels=(3, 5, 7), dropout=0.3):
        super().__init__()
        self.emb = nn.Embedding(257, emb, padding_idx=0)
        self.convs = nn.ModuleList(nn.Conv1d(emb, filters, k, padding=k // 2) for k in kernels)
        self.drop = nn.Dropout(dropout)
        self.out = nn.Linear(filters * len(kernels), 1)

    def forward(self, x):
        mask = (x != 0).unsqueeze(1)
        h = self.emb(x).transpose(1, 2)
        pooled = [torch.relu(c(h)).masked_fill(~mask, 0).amax(dim=2) for c in self.convs]
        return self.out(self.drop(torch.cat(pooled, dim=1))).squeeze(1)


def trim(xb):
    return xb[:, :max(int((xb != 0).sum(1).max()), 7)]


def encode(texts):
    arr = np.zeros((len(texts), MAXLEN), dtype=np.int64)
    for i, t in enumerate(texts):
        b = t.encode("utf-8", "surrogatepass")[:MAXLEN]
        arr[i, :len(b)] = np.frombuffer(b, dtype=np.uint8).astype(np.int64) + 1
    return torch.from_numpy(arr)


class CNNDetector:
    def __init__(self, prep):
        self.prep = prep

    def _x(self, xs):
        return encode([self.prep(x) for x in xs])

    def fit(self, train, val, seed):
        torch.manual_seed(seed)
        g = torch.Generator().manual_seed(seed)
        self.model = CharCNN()
        opt = torch.optim.Adam(self.model.parameters(), lr=1e-3)
        lossf = nn.BCEWithLogitsLoss()
        X, y = self._x(train.Query), torch.tensor(train.Label.values, dtype=torch.float32)
        best, best_state, bad, self.history = -1, None, 0, []
        for ep in range(EPOCHS):
            self.model.train()
            perm = torch.randperm(len(X), generator=g)
            for i in range(0, len(X), BATCH):
                idx = perm[i:i + BATCH]
                opt.zero_grad()
                lossf(self.model(trim(X[idx])), y[idx]).backward()
                opt.step()
            f1 = rates(val.Label, self.predict(val.Query))["f1"]
            self.history.append(f1)
            if f1 > best:
                best, bad = f1, 0
                best_state = {k: v.clone() for k, v in self.model.state_dict().items()}
            else:
                bad += 1
                if bad >= PATIENCE:
                    break
        self.model.load_state_dict(best_state)
        self.best_val_f1, self.epochs = best, len(self.history)
        return self

    @torch.no_grad()
    def proba(self, xs):
        self.model.eval()
        X = self._x(list(xs))
        if len(X) == 0:
            return np.zeros(0)
        return torch.cat([torch.sigmoid(self.model(trim(X[i:i + 1024]))) for i in range(0, len(X), 1024)]).numpy()

    def predict(self, xs):
        return (self.proba(xs) >= 0.5).astype(int)


def get_cnn(cfg, seed, train, val):
    """Train (or load cached) CNN for config name `cfg` and split seed `seed`."""
    path = MODELS / f"charcnn_{_SLUG[cfg]}_{seed}.pt"
    det = CNNDetector(CONFIGS[cfg])
    if path.exists():
        ck = torch.load(path, weights_only=True)
        det.model = CharCNN()
        det.model.load_state_dict(ck["state"])
        det.epochs, det.best_val_f1 = int(ck["epochs"]), float(ck["val_f1"])
        return det
    det.fit(train, val, seed)
    MODELS.mkdir(exist_ok=True)
    torch.save({"state": det.model.state_dict(), "epochs": det.epochs, "val_f1": det.best_val_f1}, path)
    return det
