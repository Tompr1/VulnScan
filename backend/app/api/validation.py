"""
422 responses without secrets.

FastAPI's default validation response echoes the rejected input, so an
almost-valid password or client secret would be sent back to the browser
and could end up in logs. This handler keeps the error list (field, message)
but redacts the input of sensitive fields, including inside nested bodies.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

REDACTED = "[redacted]"
_SENSITIVE_MARKERS = ("secret", "password", "passphrase", "token", "api_key", "apikey", "private_key")


def is_sensitive(field_name: Any) -> bool:
    name = str(field_name).lower()
    return any(marker in name for marker in _SENSITIVE_MARKERS)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: REDACTED if is_sensitive(key) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def redact_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    redacted = []
    for error in errors:
        error = dict(error)
        if "input" in error:
            error["input"] = REDACTED if any(is_sensitive(part) for part in error.get("loc", ())) else redact(error["input"])
        redacted.append(error)
    return redacted


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(redact_errors(list(exc.errors())))})


def install_validation_error_handler(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, validation_error_handler)
