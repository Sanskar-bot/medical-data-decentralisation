"""voice_utils.py - speech -> English text -> verified visit draft.
Pure Python helpers. No Flask imports. Never log transcript text."""
import json
import os
import re
import threading

import requests

_WHISPER = None
_LOCK = threading.Lock()
_HINT = ("Doctor's clinical note. Write numbers as digits. "
         "Example: paracetamol 500 mg twice a day for 3 days, BP 120/80.")
OLLAMA_URL = os.environ.get("MEDVAULT_OLLAMA_URL", "http://127.0.0.1:11434")

_EXTRACT_PROMPT = (
    "You extract structured data from a doctor's dictated visit text. "
    "Reply with JSON only, exactly this shape: "
    '{"diagnosis": "", "medications": [{"name": "", "dosage": "", "frequency": "", "duration": ""}]}. '
    "Rules: use ONLY words and numbers that appear in the text; never invent or correct anything; "
    "if the doctor did not state a diagnosis leave diagnosis as an empty string; "
    "include only drugs the doctor tells the patient to take; "
    "copy dosage, frequency and duration exactly as spoken and leave a field empty if not stated; "
    "no explanations.\n\nTEXT:\n"
)


def _get_whisper():
    global _WHISPER
    if _WHISPER is None:
        import av
        if not getattr(av.open, "_medvault_metadata_errors_compat", False):
            original_open = av.open

            def open_compat(*args, **kwargs):
                try:
                    return original_open(*args, **kwargs)
                except TypeError as exc:
                    if "metadata_errors" not in kwargs or "metadata_errors" not in str(exc):
                        raise
                    retry_kwargs = dict(kwargs)
                    retry_kwargs.pop("metadata_errors")
                    return original_open(*args, **retry_kwargs)

            open_compat._medvault_metadata_errors_compat = True
            av.open = open_compat
        from faster_whisper import WhisperModel
        _WHISPER = WhisperModel(os.environ.get("MEDVAULT_WHISPER_MODEL", "medium"),
                                device="cpu", compute_type="int8")
    return _WHISPER


def transcribe_both(audio_path, lang="hi"):
    """Return (english_text, original_text). lang: 'hi' | 'en' | 'auto'."""
    with _LOCK:
        model = _get_whisper()
        if lang == "en":
            segs, _ = model.transcribe(audio_path, language="en", task="transcribe",
                                       vad_filter=True, initial_prompt=_HINT)
            text = " ".join(s.text.strip() for s in segs).strip()
            return text, text
        language = None if lang == "auto" else lang
        segs, _ = model.transcribe(audio_path, language=language, task="translate",
                                   vad_filter=True, initial_prompt=_HINT)
        english = " ".join(s.text.strip() for s in segs).strip()
        segs2, _ = model.transcribe(audio_path, language=language, task="transcribe",
                                    vad_filter=True)
        original = " ".join(s.text.strip() for s in segs2).strip()
        return english, original


def _ollama_model():
    name = os.environ.get("MEDVAULT_OLLAMA_MODEL", "").strip()
    if name:
        return name
    r = requests.get(OLLAMA_URL + "/api/tags", timeout=5)
    r.raise_for_status()
    models = r.json().get("models", [])
    if not models:
        raise RuntimeError("no_ollama_model")
    return models[0]["name"]


def extract_with_llm(english_text):
    body = {"model": _ollama_model(), "stream": False, "format": "json",
            "options": {"temperature": 0}, "prompt": _EXTRACT_PROMPT + english_text}
    r = requests.post(OLLAMA_URL + "/api/generate", json=body, timeout=120)
    r.raise_for_status()
    data = json.loads(r.json().get("response", "{}"))
    return data if isinstance(data, dict) else {}


def _clean(x):
    return str(x or "").strip()[:200]


def _digits(s):
    return re.findall(r"\d+(?:\.\d+)?", s or "")


def _supported(value, hay, hay_digits):
    """True if every number and every word (3+ letters) of value appears in hay."""
    value = (value or "").lower()
    nums = _digits(value)
    if nums and not all(n in hay_digits for n in nums):
        return False
    words = re.findall(r"[a-z]{3,}", value)
    return all(w in hay for w in words)


def verify_visit(draft, english_text, original_text=""):
    """Return (diagnosis, medications). Unverified diagnosis is dropped;
    medicine fields that cannot be found in the transcript are listed in 'unverified'."""
    if not isinstance(draft, dict):
        draft = {}
    hay = (english_text + " " + original_text).lower()
    hay_digits = set(_digits(hay))
    meds = []
    raw = draft.get("medications")
    for m in (raw if isinstance(raw, list) else [])[:20]:
        if not isinstance(m, dict):
            continue
        name = _clean(m.get("name"))
        if not name:
            continue
        row = {"name": name, "dosage": _clean(m.get("dosage")),
               "frequency": _clean(m.get("frequency")),
               "duration": _clean(m.get("duration")), "unverified": []}
        for field in ("name", "dosage", "frequency", "duration"):
            if row[field] and not _supported(row[field], hay, hay_digits):
                row["unverified"].append(field)
        meds.append(row)
    diag = _clean(draft.get("diagnosis"))
    if diag and not _supported(diag, hay, hay_digits):
        diag = ""
    return diag, meds


def split_sentences(text):
    parts = re.split(r"(?<=[.!?])\s+|\n+", (text or "").strip())
    return [p.strip() for p in parts if p.strip()]


def build_note(english_text, meds):
    """Note = the English sentences that do not mention a prescribed medicine."""
    names = [m["name"].lower() for m in meds if m.get("name")]
    keep = [s for s in split_sentences(english_text)
            if not any(n in s.lower() for n in names)]
    return " ".join(keep)


def build_visit_draft(audio_path, lang="hi"):
    english, original = transcribe_both(audio_path, lang)
    result = {"english_text": english, "original_text": original,
              "diagnosis": "", "medications": [], "note": english, "warning": ""}
    if not english:
        result["warning"] = "No speech detected."
        return result
    try:
        draft = extract_with_llm(english)
        diag, meds = verify_visit(draft, english, original)
        result["diagnosis"] = diag
        result["medications"] = meds
        result["note"] = build_note(english, meds)
    except Exception:
        result["warning"] = ("Auto-extraction unavailable (is Ollama running?). "
                             "The full text was placed in the note.")
    return result


def _selftest():
    eng = ("The patient has fever for 3 days. Give paracetamol 500 mg twice a day "
           "for 3 days. Come back after 3 days.")
    draft = {"diagnosis": "Typhoid", "medications": [
        {"name": "Paracetamol", "dosage": "500 mg", "frequency": "twice a day", "duration": "3 days"},
        {"name": "Cetirizine", "dosage": "10 mg", "frequency": "at night", "duration": "5 days"}]}
    diag, meds = verify_visit(draft, eng, "")
    assert diag == "", "unverified diagnosis must be dropped"
    assert meds[0]["unverified"] == [], meds[0]
    assert "name" in meds[1]["unverified"] and "dosage" in meds[1]["unverified"], meds[1]
    note = build_note(eng, [meds[0]])
    assert "paracetamol" not in note.lower() and "fever" in note.lower(), note
    print("selftest ok")


if __name__ == "__main__":
    _selftest()
