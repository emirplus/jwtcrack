import hashlib
import hmac
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event

from jwtcrack.decoder import base64url_decode, split_token

HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _compute_hmac(signing_input, secret, hash_func):
    return hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hash_func,
    ).digest()


def _try_secrets(signing_input, target_signature, hash_func, words, found_event, result_holder):
    for word in words:
        if found_event.is_set():
            return
        computed = _compute_hmac(signing_input, word, hash_func)
        if hmac.compare_digest(computed, target_signature):
            result_holder["secret"] = word
            found_event.set()
            return


def _chunk_list(lst, n):
    chunk_size = max(1, len(lst) // n)
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]


def crack_token(token, wordlist_path, num_threads=8):
    header_b64, payload_b64, signature_b64 = split_token(token)
    signing_input = f"{header_b64}.{payload_b64}"

    import json
    header = json.loads(base64url_decode(header_b64))
    alg = header.get("alg", "")

    if alg not in HMAC_ALGORITHMS:
        return {
            "success": False,
            "error": f"Algorithm '{alg}' is not supported for cracking. Only {', '.join(HMAC_ALGORITHMS)} are supported.",
            "secret": None,
            "attempts": 0,
            "elapsed": 0,
            "speed": 0,
        }

    hash_func = HMAC_ALGORITHMS[alg]
    target_signature = base64url_decode(signature_b64)

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    if not words:
        return {
            "success": False,
            "error": "Wordlist is empty.",
            "secret": None,
            "attempts": 0,
            "elapsed": 0,
            "speed": 0,
        }

    found_event = Event()
    result_holder = {"secret": None}
    total_words = len(words)

    start_time = time.time()

    chunks = list(_chunk_list(words, num_threads))
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for chunk in chunks:
            future = executor.submit(
                _try_secrets,
                signing_input,
                target_signature,
                hash_func,
                chunk,
                found_event,
                result_holder,
            )
            futures.append(future)

        for future in as_completed(futures):
            future.result()

    elapsed = time.time() - start_time
    speed = total_words / elapsed if elapsed > 0 else 0

    return {
        "success": result_holder["secret"] is not None,
        "secret": result_holder["secret"],
        "attempts": total_words,
        "elapsed": elapsed,
        "speed": speed,
        "error": None if result_holder["secret"] else "Secret not found in wordlist.",
    }
