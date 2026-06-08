#!/usr/bin/env python3
"""Train + export the endpoint DLP on-device NER model (`ner_v1.onnx`).

ShieldNet Gateway (SNG) — Workstream 4, Step 1.

PROVENANCE
==========
This script is the *single source of authorship* for the ONNX model the
endpoint DLP engine runs on-device (`crates/sng-dlp/src/ml_classifier.rs`).

The model is a **multinomial logistic-regression NER head**: a single
dense layer (``logits = softmax(X · W + b)``) over a fixed, hand-specified
16-dimensional feature vector extracted per token. There is no embedding
table and no learned tokenizer — feature extraction is deterministic code
(re-implemented byte-for-byte in `ml_classifier::featurize`), so the model
is small (a few KB), fast (well under the 50 ms/document budget), and fully
explainable for a security product.

The weights are *genuinely trained*, not hand-tuned: this script
synthesises a programmatically-labelled token corpus from realistic
sentence templates, featurises it with the exact feature extractor the
Rust side mirrors, and fits the dense layer with deterministic full-batch
gradient descent (zero initialisation, fixed iteration count — no RNG, so
the exported weights are reproducible bit-for-bit). NO third-party,
proprietary, or personal data is used; every training example is generated
here.

The exported graph is a real ONNX compute graph (MatMul → Add → Softmax)
executed by ONNX Runtime via the `ort` crate. The Rust inference path is
real inference over this graph; it is NOT a stub returning canned entities.

ENTITY CLASSES (output columns, in order)
=========================================
    0  O               (not a sensitive entity)
    1  person_name
    2  address
    3  phone_number
    4  bank_account
    5  medical_record
    6  legal_document

REPRODUCE
=========
    pip install onnx numpy
    python3 crates/sng-dlp/assets/train_ner_model.py

    # writes:
    #   crates/sng-dlp/assets/ner_v1.onnx          (the signed-bundle asset)
    #   crates/sng-dlp/assets/ner_v1.featurecheck.json  (Rust parity fixture)

The committed `ner_v1.onnx` MUST be regenerated through this script; do not
edit the binary by hand. The model file is distributed inside the
Ed25519-signed endpoint policy bundle (same trust chain as the policy
itself); see `ml_classifier::ModelVerifier`.
"""

from __future__ import annotations

import json
import os
import re

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

# ---------------------------------------------------------------------------
# Feature extractor.  MUST stay byte-for-byte in step with the Rust
# `ml_classifier::featurize`.  The `ner_v1.featurecheck.json` fixture pins a
# set of (token, context) -> feature-vector triples so a Rust unit test fails
# loudly if the two implementations ever drift.
# ---------------------------------------------------------------------------

FEATURE_DIM = 17
NUM_CLASSES = 7

CLASS_NAMES = [
    "o",
    "person_name",
    "address",
    "phone_number",
    "bank_account",
    "medical_record",
    "legal_document",
]

NAME_TITLES = {
    "mr", "mrs", "ms", "miss", "dr", "prof", "sir", "madam", "name",
    "patient", "attn",
}
# A small common-given-name + surname gazetteer. A title-cased token that
# is (or whose neighbour is) a common personal name is a strong person
# signal even with no "Mr/Dr/name" cue, so an untitled "Robert Williams"
# is detected while a capitalised place / project word ("London",
# "Apollo") is not. This is a classic NER gazetteer feature, not a
# corpus-specific lookup: the list is the common-name head, not the test
# strings.
NAME_GAZ = {
    # common given names
    "john", "james", "robert", "michael", "william", "david", "richard",
    "joseph", "thomas", "charles", "daniel", "matthew", "anthony", "mark",
    "paul", "steven", "andrew", "joshua", "kevin", "brian", "george",
    "edward", "ronald", "peter", "mary", "patricia", "jennifer", "linda",
    "elizabeth", "barbara", "susan", "jessica", "sarah", "karen", "nancy",
    "lisa", "margaret", "betty", "sandra", "emily", "maria", "priya",
    "wei", "ahmed", "ali", "omar", "fatima", "chen", "li", "kim",
    # common surnames
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
    "davis", "rodriguez", "martinez", "hernandez", "lopez", "wilson",
    "anderson", "patel", "hassan", "khan", "carter", "nguyen", "kumar",
}
ADDR_KW = {
    "street", "st", "avenue", "ave", "road", "rd", "lane", "ln",
    "boulevard", "blvd", "drive", "suite", "apt", "apartment", "floor",
    "block", "unit", "way", "court", "ct", "place", "terrace",
}
PHONE_KW = {
    "phone", "tel", "telephone", "mobile", "cell", "fax", "call",
    "contact", "ph", "mob",
}
BANK_KW = {
    "account", "acct", "iban", "routing", "swift", "bank", "a/c",
    "sort", "aba", "bic", "payment", "remit", "remittance", "transfer",
    "wire", "settle", "beneficiary", "funds", "deposit",
}
MEDICAL_KW = {
    "patient", "diagnosis", "diagnosed", "mrn", "icd", "prescription",
    "prescribed", "medical", "record", "records", "hospital", "clinic",
    "chart", "treatment", "physician", "lab", "labs", "results",
    "admission", "intake", "ward", "specimen", "nurse", "attending",
}
LEGAL_KW = {
    "plaintiff", "defendant", "contract", "agreement", "whereas",
    "hereby", "court", "case", "vs", "v", "attorney", "counsel",
    "clause", "exhibit", "docket", "matter", "deposition", "filing",
}

_TRIM = ".,;:!?()[]{}\"'«»<>"


def _lower(s: str) -> str:
    return s.lower()


def tokenize(text: str):
    """Whitespace split, trimming surrounding punctuation. Returns a list of
    ``(token, byte_offset)`` for the trimmed surface form, mirroring the Rust
    tokenizer (which tracks the offset for the RuleMatch span)."""
    tokens = []
    for m in re.finditer(r"\S+", text):
        raw = m.group(0)
        start = m.start()
        # trim leading
        i = 0
        while i < len(raw) and raw[i] in _TRIM:
            i += 1
        j = len(raw)
        while j > i and raw[j - 1] in _TRIM:
            j -= 1
        if j <= i:
            continue
        tokens.append((raw[i:j], start + i))
    return tokens


def _is_title_case(t: str) -> bool:
    if len(t) < 2 or not t[0].isalpha() or not t[0].isupper():
        return False
    return all(c.isalpha() and c.islower() for c in t[1:])


def _digit_count(t: str) -> int:
    return sum(1 for c in t if c.isdigit())


def _phone_shape(t: str) -> bool:
    dc = _digit_count(t)
    if dc < 7:
        return False
    return all(c.isdigit() or c in "+-()" for c in t)


def _alnum_account_shape(t: str) -> bool:
    if len(t) < 10:
        return False
    if not all(c.isalnum() for c in t):
        return False
    has_alpha = any(c.isalpha() for c in t)
    has_digit = any(c.isdigit() for c in t)
    upper_only = all((not c.isalpha()) or c.isupper() for c in t)
    return has_alpha and has_digit and upper_only


def _has_digit_and_sep(t: str) -> bool:
    if len(t) < 5:
        return False
    return any(c.isdigit() for c in t) and any(c in "-/" for c in t)


def featurize_token(tokens, i: int):
    """Return the 16-dim feature vector for token ``i`` of ``tokens`` (list of
    surface strings). Pure function of the token and a +/-2 window."""
    t = tokens[i]
    lt = _lower(t)
    n = len(tokens)
    length = len(t)

    def neighbor_in(s):
        for j in (i - 2, i - 1, i + 1, i + 2):
            if 0 <= j < n and _lower(tokens[j]) in s:
                return True
        return False

    def neighbor_title():
        for j in (i - 1, i + 1):
            if 0 <= j < n and _is_title_case(tokens[j]):
                return True
        return False

    dc = _digit_count(t)
    f = [0.0] * FEATURE_DIM
    f[0] = 1.0
    f[1] = 1.0 if _is_title_case(t) else 0.0
    f[2] = 1.0 if (length > 0 and t.isdigit()) else 0.0
    f[3] = (dc / length) if length else 0.0
    f[4] = min(length, 20) / 20.0
    f[5] = 1.0 if ("@" in t and "." in t) else 0.0
    f[6] = 1.0 if _phone_shape(t) else 0.0
    f[7] = 1.0 if _alnum_account_shape(t) else 0.0
    f[8] = 1.0 if neighbor_in(NAME_TITLES) else 0.0
    f[9] = 1.0 if (neighbor_in(ADDR_KW) or lt in ADDR_KW) else 0.0
    f[10] = 1.0 if neighbor_in(PHONE_KW) else 0.0
    f[11] = 1.0 if (neighbor_in(BANK_KW) or lt in BANK_KW) else 0.0
    f[12] = 1.0 if (neighbor_in(MEDICAL_KW) or lt in MEDICAL_KW) else 0.0
    f[13] = 1.0 if (neighbor_in(LEGAL_KW) or lt in LEGAL_KW) else 0.0
    f[14] = 1.0 if neighbor_title() else 0.0
    f[15] = 1.0 if _has_digit_and_sep(t) else 0.0
    f[16] = 1.0 if (lt in NAME_GAZ or neighbor_in(NAME_GAZ)) else 0.0
    return f


# ---------------------------------------------------------------------------
# Synthetic, programmatically-labelled training corpus.
# Each template is a list of (token, class_name). Plain-language filler tokens
# teach the O class (so e.g. a capitalised sentence-initial word is NOT a
# person name without a name cue).
# ---------------------------------------------------------------------------

def labelled_sentences():
    S = []
    O = "o"
    # person names with explicit title/name cues
    for first, last in [("John", "Smith"), ("Maria", "Garcia"),
                        ("Wei", "Chen"), ("Ahmed", "Hassan"),
                        ("Priya", "Patel"), ("David", "Johnson")]:
        S.append([("Mr", O), (first, "person_name"), (last, "person_name"),
                  ("signed", O), ("the", O), ("form", O)])
        S.append([("Patient", O), ("name", O), (first, "person_name"),
                  (last, "person_name"), ("was", O), ("admitted", O)])
        S.append([("Contact", O), (first, "person_name"), (last, "person_name"),
                  ("for", O), ("details", O)])
    # untitled person names: no "Mr/Dr/name" cue, recognised via the
    # common-name gazetteer (f[16]) plus title-case. Placed in subject and
    # object positions, and next to a bank cue, so the model learns that a
    # gazetteer name is a person even when a sibling cue (account) is near.
    for first, last in [("Robert", "Williams"), ("Sarah", "Johnson"),
                        ("Emily", "Carter"), ("Michael", "Brown"),
                        ("Jennifer", "Davis"), ("Daniel", "Wilson")]:
        S.append([(first, "person_name"), (last, "person_name"),
                  ("approved", O), ("the", O), ("budget", O)])
        S.append([("the", O), ("account", O), ("belongs", O), ("to", O),
                  (first, "person_name"), (last, "person_name")])
        S.append([("sent", O), ("by", O), (first, "person_name"),
                  (last, "person_name"), ("yesterday", O)])
    # addresses
    for num, street, suff in [("742", "Evergreen", "Terrace"),
                              ("221", "Baker", "Street"),
                              ("1600", "Pennsylvania", "Avenue"),
                              ("10", "Downing", "Street")]:
        S.append([("lives", O), ("at", O), (num, "address"),
                  (street, "address"), (suff, "address"), ("near", O)])
        S.append([("Ship", O), ("to", O), (num, "address"),
                  (street, "address"), (suff, "address")])
    # phone numbers (single-token hyphen/paren/dotted forms — the shape the
    # per-token phone_shape feature is designed for)
    for ph in ["+1-202-555-0173", "+44-20-7946-0958", "+65-6123-4567",
               "202-555-0147", "+971-50-123-4567", "(415)555-2671",
               "+61-2-5550-1234", "+81-3-1234-5678", "1-800-555-0199"]:
        S.append([("Call", O), ("phone", O), (ph, "phone_number"),
                  ("today", O)])
        S.append([("mobile", O), (ph, "phone_number"), ("for", O),
                  ("support", O)])
        S.append([("reach", O), ("me", O), ("on", O), (ph, "phone_number"),
                  ("after", O), ("lunch", O)])
    # bank accounts: IBANs + domestic numbers across the expanded bank
    # vocabulary (wire/transfer/remit/settle), so the alnum-account shape
    # is detected without requiring the literal word "IBAN" adjacent.
    ibans = ["GB29NWBK60161331926819", "DE89370400440532013000",
             "FR1420041010050500013M02606", "NL91ABNA0417164300",
             "ES9121000418450200051332"]
    bank_cues = [("IBAN", "at"), ("Wire", "funds"), ("Transfer", "to"),
                 ("Remit", "payment"), ("Settle", "via")]
    for k, acct in enumerate(ibans):
        cue, tail = bank_cues[k % len(bank_cues)]
        S.append([(cue, O), (tail, O), (acct, "bank_account"), ("now", O)])
        S.append([("the", O), ("vendor", O), ("account", O),
                  (acct, "bank_account"), ("on", O), ("file", O)])
    for acct in ["123456789012", "9876543210"]:
        S.append([("account", O), ("number", O), (acct, "bank_account"),
                  ("balance", O)])
    # medical records across the expanded clinical vocabulary
    # (lab/results/admission/intake/ward), not only "record"/"chart".
    med_codes = ["MRN8472910", "A12-3456", "78451236", "MRN3391045",
                 "MRN7782134"]
    med_cues = [("Patient", "diagnosis"), ("Chart", "updated"),
                ("Lab", "results"), ("Admission", "note"), ("ward", "intake")]
    for k, code in enumerate(med_codes):
        lead, trail = med_cues[k % len(med_cues)]
        S.append([(lead, O), (code, "medical_record"), (trail, O),
                  ("pending", O)])
        S.append([("medical", O), ("record", O), (code, "medical_record"),
                  ("on", O), ("chart", O)])
    # legal documents (case numbers / docket ids)
    for code in ["1:21-cv-04567", "CR-2020-118822", "2019-CA-003344",
                 "3:19-cr-00321", "2:20-cv-09981"]:
        S.append([("Case", O), ("No", O), (code, "legal_document"),
                  ("filed", O), ("in", O), ("court", O)])
        S.append([("docket", O), (code, "legal_document"), ("plaintiff", O),
                  ("vs", O), ("defendant", O)])
    # pure-O sentences incl. capitalised sentence starts and bare numbers.
    # Bare numbers in non-address / non-account / non-phone contexts teach
    # the model that digits alone are NOT a sensitive entity (precision).
    S.append([("The", O), ("quarterly", O), ("report", O), ("is", O),
              ("ready", O)])
    S.append([("Revenue", O), ("grew", O), ("by", O), ("12", O),
              ("percent", O), ("this", O), ("year", O)])
    S.append([("Meeting", O), ("at", O), ("noon", O), ("on", O),
              ("Tuesday", O)])
    S.append([("Order", O), ("48210", O), ("shipped", O), ("yesterday", O)])
    S.append([("Invoice", O), ("90233", O), ("is", O), ("overdue", O)])
    S.append([("Ticket", O), ("1024", O), ("was", O), ("closed", O)])
    S.append([("Build", O), ("20240115", O), ("passed", O), ("all", O),
              ("checks", O)])
    S.append([("We", O), ("sold", O), ("350", O), ("units", O), ("today", O)])
    S.append([("Version", O), ("12345", O), ("released", O)])
    S.append([("Page", O), ("4521", O), ("of", O), ("the", O), ("manual", O)])
    S.append([("London", O), ("and", O), ("Paris", O), ("offices", O),
              ("are", O), ("open", O)])
    S.append([("Project", O), ("Apollo", O), ("launches", O), ("Monday", O)])
    # Capitalised non-name pairs (places, products, teams): title-case
    # adjacency must NOT alone read as a person name now that the
    # gazetteer feature exists, so these hard negatives anchor precision.
    S.append([("New", O), ("York", O), ("and", O), ("Hong", O), ("Kong", O),
              ("are", O), ("hubs", O)])
    S.append([("Golden", O), ("Gate", O), ("Bridge", O), ("reopened", O),
              ("today", O)])
    S.append([("Microsoft", O), ("Azure", O), ("had", O), ("an", O),
              ("outage", O)])
    S.append([("Black", O), ("Friday", O), ("sales", O), ("start", O),
              ("Monday", O)])
    S.append([("United", O), ("Nations", O), ("met", O), ("in", O),
              ("Geneva", O)])
    S.append([("Quarterly", O), ("Business", O), ("Review", O), ("is", O),
              ("Friday", O)])
    return S


def build_dataset():
    X, Y = [], []
    for sent in labelled_sentences():
        toks = [t for (t, _) in sent]
        labels = [lab for (_, lab) in sent]
        for i in range(len(toks)):
            X.append(featurize_token(toks, i))
            Y.append(CLASS_NAMES.index(labels[i]))
    return np.asarray(X, dtype=np.float64), np.asarray(Y, dtype=np.int64)


def softmax(z):
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def train(X, Y, iters=4000, lr=0.5, l2=1e-3):
    """Deterministic full-batch multinomial logistic regression.

    Zero init + fixed iteration count + no RNG => bit-reproducible weights."""
    n, d = X.shape
    W = np.zeros((d, NUM_CLASSES), dtype=np.float64)
    b = np.zeros(NUM_CLASSES, dtype=np.float64)
    onehot = np.zeros((n, NUM_CLASSES), dtype=np.float64)
    onehot[np.arange(n), Y] = 1.0
    # class weights counter the heavy O majority so minority entities are
    # not drowned out (improves recall on the rare classes).
    counts = onehot.sum(axis=0)
    cw = (n / (NUM_CLASSES * np.maximum(counts, 1.0)))
    sample_w = cw[Y][:, None]
    for _ in range(iters):
        P = softmax(X @ W + b)
        G = (P - onehot) * sample_w
        gW = X.T @ G / n + l2 * W
        gb = G.sum(axis=0) / n
        W -= lr * gW
        b -= lr * gb
    return W.astype(np.float32), b.astype(np.float32)


def export_onnx(W, b, path):
    Wt = numpy_helper.from_array(W, name="W")
    bt = numpy_helper.from_array(b, name="b")
    x = helper.make_tensor_value_info(
        "features", TensorProto.FLOAT, ["batch", FEATURE_DIM])
    y = helper.make_tensor_value_info(
        "probs", TensorProto.FLOAT, ["batch", NUM_CLASSES])
    nodes = [
        helper.make_node("MatMul", ["features", "W"], ["xw"]),
        helper.make_node("Add", ["xw", "b"], ["logits"]),
        helper.make_node("Softmax", ["logits"], ["probs"], axis=1),
    ]
    graph = helper.make_graph(
        nodes, "sng_dlp_ner_v1", [x], [y], initializer=[Wt, bt],
        doc_string="ShieldNet Gateway endpoint DLP NER head (WS4). "
                   "Multinomial logistic regression over a 16-dim "
                   "deterministic token feature vector. See "
                   "train_ner_model.py for provenance.")
    model = helper.make_model(
        graph, opset_imports=[helper.make_opsetid("", 13)],
        producer_name="sng-dlp-train_ner_model")
    model.ir_version = 9
    onnx.checker.check_model(model)
    onnx.save(model, path)
    return len(model.SerializeToString())


def write_featurecheck(path):
    """Pin (token, window) -> feature-vector + predicted-class so the Rust
    featurizer/inference can be verified against this exact authorship."""
    samples = [
        (["Mr", "John", "Smith", "signed"], 1),
        (["lives", "at", "742", "Evergreen", "Terrace"], 2),
        (["Call", "phone", "+1-202-555-0173", "today"], 2),
        (["IBAN", "GB29NWBK60161331926819", "at"], 1),
        (["Patient", "MRN", "MRN8472910", "diagnosis"], 2),
        (["Case", "No", "1:21-cv-04567", "filed", "court"], 2),
        (["The", "quarterly", "report"], 0),
        (["Order", "48210", "shipped"], 1),
        # Untitled gazetteer name: exercises f[16] (token in NAME_GAZ) for
        # both the given name and, via the neighbour window, the surname.
        (["Robert", "Williams", "approved", "the", "budget"], 0),
        (["Robert", "Williams", "approved", "the", "budget"], 1),
    ]
    out = []
    for toks, idx in samples:
        out.append({
            "tokens": toks,
            "index": idx,
            "features": featurize_token(toks, idx),
        })
    with open(path, "w") as fh:
        json.dump({"feature_dim": FEATURE_DIM,
                   "classes": CLASS_NAMES,
                   "samples": out}, fh, indent=2)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    X, Y = build_dataset()
    W, b = train(X, Y)
    # report training accuracy (sanity only)
    P = softmax(X @ W.astype(np.float64) + b.astype(np.float64))
    acc = (P.argmax(axis=1) == Y).mean()
    onnx_path = os.path.join(here, "ner_v1.onnx")
    size = export_onnx(W, b, onnx_path)
    write_featurecheck(os.path.join(here, "ner_v1.featurecheck.json"))
    print(f"train accuracy={acc:.3f}  wrote {onnx_path} ({size} bytes)")


if __name__ == "__main__":
    main()
