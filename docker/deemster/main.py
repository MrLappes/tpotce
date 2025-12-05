from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, TypedDict, AsyncIterator

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, Field

load_dotenv()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Honeypot JSON logger for Logstash integration
def _get_log_file_path() -> Path:
    """Get writable log file path, with fallback options."""
    primary_dir = Path(os.getenv("LOG_DIR", "/opt/deemster/log"))
    fallback_dir = Path("/tmp/deemster/log")
    
    # Try primary directory first
    try:
        primary_dir.mkdir(parents=True, exist_ok=True)
        test_file = primary_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
        return primary_dir / "deemster.json"
    except (OSError, PermissionError):
        # Fall back to /tmp if /data is not writable
        logging.getLogger("cxc-honeypod").warning(
            f"Cannot write to {primary_dir}, using fallback {fallback_dir}"
        )
        try:
            fallback_dir.mkdir(parents=True, exist_ok=True)
            return fallback_dir / "deemster.json"
        except (OSError, PermissionError) as e:
            logging.getLogger("cxc-honeypod").error(
                f"Cannot create log directory: {e}. Logging will be disabled."
            )
            return None


LOG_FILE = _get_log_file_path()


class HoneypotLogger:
    """
    Logger that writes JSON entries to a log file for Logstash to consume.
    Each log entry contains src_ip, src_port, dest_ip, dest_port, timestamp, and event data.
    """

    def __init__(self, log_file: Optional[Path]) -> None:
        self.log_file = log_file
        self.enabled = log_file is not None
        if not self.enabled:
            logging.getLogger("cxc-honeypod").warning("Honeypot logging is disabled due to lack of writable directory")

    def _get_timestamp(self) -> str:
        """Return ISO8601 timestamp in UTC."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _extract_text_from_response(self, response_data: Optional[str]) -> Optional[str]:
        """Extract readable text from token-based response."""
        if not response_data:
            return None
        try:
            # Response might be token stream like: {"token_id": 0, "text": "I'm"}{"token_id": 1, "text": " "}...
            # Extract all "text" values
            text_parts = []
            for line in response_data.split("}{"):
                line = line.strip("{}")
                if '"text":' in line:
                    try:
                        obj = json.loads("{" + line + "}")
                        if "text" in obj:
                            text_parts.append(obj["text"])
                    except:
                        pass
            return "".join(text_parts) if text_parts else response_data
        except:
            return response_data

    def log_event(
        self,
        event_type: str,
        src_ip: str,
        src_port: int,
        dest_ip: str,
        dest_port: int,
        endpoint: str,
        request_data: Optional[Dict[str, Any]] = None,
        response_data: Optional[str] = None,
        session_id: Optional[str] = None,
        username: Optional[str] = None,
        http_method: str = "POST",
        user_agent: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Write a JSON log entry for Logstash.
        
        Args:
            event_type: Type of event (e.g., "attack", "chat", "session_start", "session_end")
            src_ip: Source IP address (attacker)
            src_port: Source port
            dest_ip: Destination IP (honeypot)
            dest_port: Destination port (honeypot)
            endpoint: API endpoint accessed
            request_data: The incoming request payload
            response_data: The response we sent back (for attack logging)
            session_id: Session identifier if available
            username: Username from JWT claims if available
            http_method: HTTP method used
            user_agent: User-Agent header if available
            extra: Any additional fields to include
        """
        log_entry: Dict[str, Any] = {
            "timestamp": self._get_timestamp(),
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "endpoint": endpoint,
            "http_method": http_method,
            "session_id": session_id or str(uuid.uuid4()),
        }

        if request_data:
            log_entry["request"] = request_data
        if response_data:
            log_entry["response"] = response_data
            # Add human-readable response text
        response_text = self._extract_text_from_response(response_data)
        if response_text:
            log_entry["response_text"] = response_text
        if username:
            log_entry["username"] = username
        if user_agent:
            log_entry["http_user_agent"] = user_agent
        if extra:
            log_entry.update(extra)

        # Write JSON line to log file
        if not self.enabled or not self.log_file:
            return
        
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.getLogger("cxc-honeypod").error(f"Failed to write log entry: {e}")


# Global honeypot logger instance
honeypot_logger = HoneypotLogger(LOG_FILE)


class TokenInfo(TypedDict):
    token: str
    claims: Dict[str, Any]


async def validate_jwt(token: str = Depends(oauth2_scheme)) -> TokenInfo:
    """
    Validate the bearer token using the same JWT_SECRET/ALGORITHM as the backend.
    Returns both the raw token and decoded claims.
    """
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="Server JWT configuration missing")
    try:
        alg = os.getenv("ALGORITHM", "HS256")
        decoded: Dict[str, Any] = jwt.decode(token, secret, algorithms=[alg])
        return TokenInfo(token=token, claims=decoded)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

class ProxyReplyRequest(BaseModel):
    session_id: str = Field(..., description="Opaque session id issued by backend")
    message: str = Field(..., description="User message or prior question text")
    index: Optional[int] = Field(
        default=None, ge=0, description="Optional scripted question index to align reply"
    )

class ProxyScanReplyRequest(BaseModel):
    session_id: str = Field(..., description="Opaque session id issued by backend")
    question: str = Field(..., description="Which question to scan the scripted reply for")
    index: Optional[int] = Field(default=None, ge=0)

class EndSessionRequest(BaseModel):
    session_id: str = Field(..., description="Opaque session id issued by backend")

class FrameworkAttackRequest(BaseModel):
    adversarial_prompt: str = Field(..., description="The adversarial prompt to get attack response for")

class HoneypodAPI:
    app: FastAPI
    logger: logging.Logger
    backend_port: int
    listen_port: int
    JWT_SECRET: Optional[str]
    algorithm: str

    def __init__(self) -> None:
        self.app = FastAPI(title="cxc-honeypod-api")

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self.logger = logging.getLogger("cxc-honeypod")
        self.backend_port = int(os.getenv("BACKEND_PORT", "8000"))
        self.listen_port = int(os.getenv("PORT", "8001"))
        self.jwt_secret = os.getenv("JWT_SECRET")
        self.algorithm = os.getenv("ALGORITHM", "HS256")

        if not self.jwt_secret:
            self.logger.warning(
                "JWT_SECRET not set; JWT validation will fail until JWT_SECRET is provided."
            )

        self.app.post("/token")(self.token_route)
        self.app.get("/start-session")(self.start_session)
        self.app.post("/end-session")(self.end_session)
        self.app.post("/chat")(self.proxy_reply)
        self.app.post("/stream/chat")(self.proxy_stream_reply)
        self.app.post("/scan-reply")(self.proxy_scan_reply)
        self.app.post("/ask")(self.proxy_attack_reply)
        self.app.post("/ask/stream")(self.proxy_stream_attack_reply)

    def _get_request_info(self, request: Request) -> Dict[str, Any]:
        """Extract logging info from request."""
        client_host = request.client.host if request.client else "unknown"
        client_port = request.client.port if request.client else 0
        # Get destination IP from request's Host header or server info
        host_header = request.headers.get("host", "")
        dest_ip = host_header.split(":")[0] if host_header else request.url.hostname or "unknown"
        return {
            "src_ip": client_host,
            "src_port": client_port,
            "dest_ip": dest_ip,
            "dest_port": self.listen_port,
            "user_agent": request.headers.get("user-agent"),
        }

    async def token_route(
        self, request: Request, form_data: OAuth2PasswordRequestForm = Depends()
    ) -> Dict[str, Any]:
        """
        Proxies token requests to the backend /users/token so Swagger/UI auth works here.
        """
        # Get client IP from request
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")
        url = f"http://{client_ip}:{self.backend_port}/users/token"
        data: Dict[str, str] = {"username": form_data.username, "password": form_data.password}
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, data=data)
        except httpx.HTTPError as exc:
            self.logger.exception("HTTP error contacting backend for token: %s", exc)
            raise HTTPException(status_code=502, detail="Failed to reach backend")

        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text or "Backend error")

        try:
            return resp.json()
        except ValueError:
            return {"data": resp.text}

    async def start_session(self, request: Request, token_info: TokenInfo = Depends(validate_jwt)) -> Dict[str, str]:
        """
        Creates a session_id on the backend bound to the user's last active combo.
        The user must have selected a combo and called /question at least once so the backend
        knows the 'last combo'.
        """
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")

        url = f"http://{client_ip}:{self.backend_port}/sessions/start"
        headers = {"Authorization": f"Bearer {token_info['token']}"}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, headers=headers)
        except httpx.HTTPError as exc:
            self.logger.exception("HTTP error contacting backend (start-session): %s", exc)
            raise HTTPException(status_code=502, detail="Failed to reach backend")

        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text or "Backend error")

        try:
            return resp.json()
        except ValueError:
            return {"data": resp.text}

    async def end_session(self, request: Request, payload: EndSessionRequest, token_info: TokenInfo = Depends(validate_jwt)) -> Dict[str, Any]:
        """
        End a session by session_id. Accepts the session_id as a query parameter
        and forwards the request to the backend /sessions/end endpoint.
        """
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")

        url = f"http://{client_ip}:{self.backend_port}/sessions/end"
        headers = {"Authorization": f"Bearer {token_info['token']}"}
        body: Dict[str, str] = {"session_id": payload.session_id}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            self.logger.exception("HTTP error contacting backend (end-session): %s", exc)
            raise HTTPException(status_code=502, detail="Failed to reach backend")

        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text or "Backend error")

        try:
            return resp.json()
        except ValueError:
            return {"data": resp.text}

    async def proxy_reply(
        self, request: Request, payload: ProxyReplyRequest, token_info: TokenInfo = Depends(validate_jwt)
    ) -> Dict[str, Any]:
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")

        req_info = self._get_request_info(request)
        username = token_info["claims"].get("sub") if token_info else None

        await asyncio.sleep(random.uniform(0.3, 1.0))

        url = f"http://{client_ip}:{self.backend_port}/sessions/reply"
        headers = {"Authorization": f"Bearer {token_info['token']}"}
        body: Dict[str, Any] = {
            "session_id": payload.session_id,
            "question": payload.message,
            "index": payload.index,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            self.logger.exception("HTTP error contacting backend (reply): %s", exc)
            raise HTTPException(status_code=502, detail="Failed to reach backend")

        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text or "Backend error")

        try:
            result = resp.json()
        except ValueError:
            result = {"data": resp.text}

        # Log the chat interaction
        honeypot_logger.log_event(
            event_type="chat",
            src_ip=req_info["src_ip"],
            src_port=req_info["src_port"],
            dest_ip=req_info["dest_ip"],
            dest_port=req_info["dest_port"],
            endpoint="/chat",
            request_data={"message": payload.message, "session_id": payload.session_id},
            response_data=json.dumps(result) if isinstance(result, dict) else str(result),
            session_id=payload.session_id,
            username=username,
            user_agent=req_info["user_agent"],
        )

        return result

    async def proxy_stream_reply(
        self, request: Request, payload: ProxyReplyRequest, token_info: TokenInfo = Depends(validate_jwt)
    ) -> StreamingResponse:
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")

        req_info = self._get_request_info(request)
        username = token_info["claims"].get("sub") if token_info else None

        url = f"http://{client_ip}:{self.backend_port}/sessions/stream/reply"
        headers = {"Authorization": f"Bearer {token_info['token']}"}
        body: Dict[str, Any] = {
            "session_id": payload.session_id,
            "question": payload.message,
            "index": payload.index,
        }

        async def stream_generator() -> AsyncIterator[bytes]:
            response_chunks: list[str] = []
            try:
                async with httpx.AsyncClient(timeout=None) as client:
                    async with client.stream("POST", url, json=body, headers=headers) as resp:
                        if resp.status_code >= 400:
                            text = await resp.aread()
                            self.logger.error(
                                "Backend stream error %s %s", resp.status_code, text
                            )
                            raise HTTPException(
                                status_code=resp.status_code, detail="Backend stream error"
                            )
                        async for line in resp.aiter_lines():
                            response_chunks.append(line)
                            yield (line + "\n").encode("utf-8")
            except HTTPException:
                raise
            except Exception as exc:
                self.logger.exception("Error while streaming from backend: %s", exc)
                raise HTTPException(status_code=502, detail="Error while streaming from backend")
            finally:
                # Log the streaming chat interaction
                honeypot_logger.log_event(
                    event_type="chat_stream",
                    src_ip=req_info["src_ip"],
                    src_port=req_info["src_port"],
                    dest_ip=req_info["dest_ip"],
                    dest_port=req_info["dest_port"],
                    endpoint="/stream/chat",
                    request_data={"message": payload.message, "session_id": payload.session_id},
                    response_data="".join(response_chunks),
                    session_id=payload.session_id,
                    username=username,
                    user_agent=req_info["user_agent"],
                )

        return StreamingResponse(stream_generator(), media_type="application/jsonl; charset=utf-8")

    async def proxy_scan_reply(
        self, request: Request, payload: ProxyScanReplyRequest, token_info: TokenInfo = Depends(validate_jwt)
    ) -> Dict[str, Any]:
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")

        url = f"http://{client_ip}:{self.backend_port}/sessions/scan-reply"
        headers = {"Authorization": f"Bearer {token_info['token']}"}
        body: Dict[str, Any] = {
            "session_id": payload.session_id,
            "question": payload.question,
            "index": payload.index,
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            self.logger.exception("HTTP error contacting backend (scan-reply): %s", exc)
            raise HTTPException(status_code=502, detail="Failed to reach backend")

        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text or "Backend error")

        try:
            return resp.json()
        except ValueError:
            return {"data": resp.text}

    async def proxy_attack_reply(
        self, request: Request, payload: FrameworkAttackRequest, token_info: TokenInfo = Depends(validate_jwt)
    ) -> Dict[str, Any]:
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")

        req_info = self._get_request_info(request)
        username = token_info["claims"].get("sub") if token_info else None

        url = f"http://{client_ip}:{self.backend_port}/framework/attack"
        headers = {"Authorization": f"Bearer {token_info['token']}"}
        body: Dict[str, Any] = {
            "adversarial_prompt": payload.adversarial_prompt,
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            self.logger.exception("HTTP error contacting backend (attack-reply): %s", exc)
            raise HTTPException(status_code=502, detail="Failed to reach backend")

        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text or "Backend error")

        try:
            result = resp.json()
        except ValueError:
            result = {"data": resp.text}

        # Log the attack interaction
        honeypot_logger.log_event(
            event_type="attack",
            src_ip=req_info["src_ip"],
            src_port=req_info["src_port"],
            dest_ip=req_info["dest_ip"],
            dest_port=req_info["dest_port"],
            endpoint="/ask",
            request_data={"adversarial_prompt": payload.adversarial_prompt},
            response_data=json.dumps(result) if isinstance(result, dict) else str(result),
            username=username,
            user_agent=req_info["user_agent"],
        )

        return result

    async def proxy_stream_attack_reply(
        self, request: Request, payload: FrameworkAttackRequest, token_info: TokenInfo = Depends(validate_jwt)
    ) -> StreamingResponse:
        client_ip = request.client.host if hasattr(request, "client") else None
        if not client_ip:
            raise HTTPException(status_code=500, detail="Cannot determine client IP")

        req_info = self._get_request_info(request)
        username = token_info["claims"].get("sub") if token_info else None

        url = f"http://{client_ip}:{self.backend_port}/framework/stream/attack"
        headers = {"Authorization": f"Bearer {token_info['token']}"}
        body: Dict[str, Any] = {
            "adversarial_prompt": payload.adversarial_prompt,
        }

        async def stream_generator() -> AsyncIterator[bytes]:
            response_chunks: list[str] = []
            try:
                async with httpx.AsyncClient(timeout=None) as client:
                    async with client.stream("POST", url, json=body, headers=headers) as resp:
                        if resp.status_code == 404:
                            # Handle 404 gracefully by streaming fallback message
                            fallback_message = "Sorry, I can't help you with that."
                            response_chunks.append(fallback_message)
                            for char in fallback_message:
                                yield char.encode("utf-8")
                                await asyncio.sleep(0.05)  # Simulate streaming delay
                            return
                        elif resp.status_code >= 400:
                            text = await resp.aread()
                            self.logger.error(
                                "Backend stream error %s %s", resp.status_code, text
                            )
                            raise HTTPException(
                                status_code=resp.status_code, detail="Backend stream error"
                            )
                        async for line in resp.aiter_lines():
                            response_chunks.append(line)
                            yield (line + "\n").encode("utf-8")
            except HTTPException:
                raise
            except Exception as exc:
                self.logger.exception("Error while streaming from backend: %s", exc)
                raise HTTPException(status_code=502, detail="Error while streaming from backend")
            finally:
                # Log the streaming attack interaction
                honeypot_logger.log_event(
                    event_type="attack_stream",
                    src_ip=req_info["src_ip"],
                    src_port=req_info["src_port"],
                    dest_ip=req_info["dest_ip"],
                    dest_port=req_info["dest_port"],
                    endpoint="/ask/stream",
                    request_data={"adversarial_prompt": payload.adversarial_prompt},
                    response_data="".join(response_chunks),
                    username=username,
                    user_agent=req_info["user_agent"],
                )

        return StreamingResponse(stream_generator(), media_type="application/jsonl; charset=utf-8")


server: HoneypodAPI = HoneypodAPI()
app: FastAPI = server.app

if __name__ == "__main__":
    host: str = os.getenv("HOST", "0.0.0.0")
    port_str: str = os.getenv("PORT", "8001")
    try:
        port: int = int(port_str)
    except ValueError:
        port = 8001
    reload_env: bool = os.getenv("UVICORN_RELOAD", "false").lower() in ("1", "true", "yes")
    log_level: str = os.getenv("UVICORN_LOG_LEVEL", "info")
    uvicorn.run(app, host=host, port=port, reload=reload_env, log_level=log_level)
