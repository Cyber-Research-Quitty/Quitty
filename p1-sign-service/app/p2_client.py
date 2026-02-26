from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, Optional


class P2ClientError(RuntimeError):
    pass


def post_json(url: str, payload: Dict[str, Any], timeout_seconds: float = 3.0) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8")
            if not body:
                return {"ok": True}
            return json.loads(body)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        raise P2ClientError(f"HTTP {e.code} from P2: {raw}") from e
    except Exception as e:
        raise P2ClientError(f"Failed to call P2: {type(e).__name__}: {e}") from e
