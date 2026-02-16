import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import typer

app = typer.Typer(help="Authorization Station CLI for routing, credentials, and auth sessions")
config_app = typer.Typer(help="Manage local CLI config (contexts + reusable references)")
app.add_typer(config_app, name="config")

CONFIG_PATH = Path.home() / ".auth-station" / "config.json"


def _default_config() -> dict[str, Any]:
    return {
        "active_context": "default",
        "contexts": {
            "default": {
                "api_url": None,
                "api_key": None,
                "profile": "default",
                "provider": "google",
                "redirect_uri": None,
            }
        },
        "references": {
            "model": {},
            "provider": {},
            "profile": {},
            "redirect": {},
        },
    }


def _load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return _default_config()
    try:
        loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return _default_config()

    cfg = _default_config()
    cfg.update({k: v for k, v in loaded.items() if k in cfg})
    cfg["contexts"].update((loaded.get("contexts") or {}))
    for key in cfg["references"]:
        cfg["references"][key].update(((loaded.get("references") or {}).get(key) or {}))
    return cfg


def _save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _active_context(config: dict[str, Any]) -> dict[str, Any]:
    context_name = config.get("active_context") or "default"
    contexts = config.get("contexts") or {}
    return contexts.get(context_name) or contexts.get("default") or {}


def _expand_reference_value(raw_value: str | None, ref_type: str, config: dict[str, Any]) -> str | None:
    if not raw_value or not isinstance(raw_value, str):
        return raw_value
    prefix = f"@{ref_type}:"
    if not raw_value.startswith(prefix):
        return raw_value
    ref_name = raw_value[len(prefix) :]
    return (config.get("references") or {}).get(ref_type, {}).get(ref_name) or raw_value


def _resolve_runtime(
    api_url: str | None,
    api_key: str | None,
    profile: str | None = None,
    provider: str | None = None,
    redirect_uri: str | None = None,
) -> dict[str, str | None]:
    cfg = _load_config()
    ctx = _active_context(cfg)
    resolved_api_url = api_url or ctx.get("api_url")
    resolved_api_key = api_key or ctx.get("api_key")
    resolved_profile = profile or ctx.get("profile") or "default"
    resolved_provider = provider or ctx.get("provider")
    resolved_redirect = redirect_uri or ctx.get("redirect_uri")

    if not resolved_api_url or not resolved_api_key:
        raise typer.BadParameter(
            "Missing api_url/api_key. Run 'auth-station config init' once, or pass --api-url and --api-key."
        )

    return {
        "api_url": resolved_api_url,
        "api_key": resolved_api_key,
        "profile": _expand_reference_value(resolved_profile, "profile", cfg) or "default",
        "provider": _expand_reference_value(resolved_provider, "provider", cfg),
        "redirect_uri": _expand_reference_value(resolved_redirect, "redirect", cfg),
    }


def _headers(api_key: str) -> dict[str, str]:
    return {"x-api-key": api_key}


def _post(api_url: str, path: str, api_key: str, payload: dict, timeout: int = 30) -> dict:
    response = httpx.post(f"{api_url}{path}", json=payload, headers=_headers(api_key), timeout=timeout)
    response.raise_for_status()
    return response.json()


def _get(api_url: str, path: str, api_key: str, timeout: int = 30) -> dict | list:
    response = httpx.get(f"{api_url}{path}", headers=_headers(api_key), timeout=timeout)
    response.raise_for_status()
    return response.json()


@config_app.command("init")
def config_init(
    context: str = typer.Option("default", help="Context name to create/update"),
    api_url: str | None = typer.Option(None, help="Base API URL, e.g. http://localhost:8080"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    profile: str = typer.Option("default", help="Default profile for this context"),
    provider: str = typer.Option("google", help="Default provider for this context"),
    redirect_uri: str | None = typer.Option(None, help="Default browser redirect URI"),
    set_active: bool = typer.Option(True, help="Make this context active now"),
):
    cfg = _load_config()
    final_api_url = api_url or typer.prompt("API URL", default="http://localhost:8080")
    final_api_key = api_key or typer.prompt("API key", hide_input=True)
    cfg.setdefault("contexts", {})[context] = {
        "api_url": final_api_url,
        "api_key": final_api_key,
        "profile": profile,
        "provider": provider,
        "redirect_uri": redirect_uri,
    }
    if set_active:
        cfg["active_context"] = context
    _save_config(cfg)
    typer.echo(f"Saved context '{context}'. Active context: {cfg.get('active_context')}")


@config_app.command("show")
def config_show(include_secrets: bool = typer.Option(False, help="Include API keys in output")):
    cfg = _load_config()
    safe = json.loads(json.dumps(cfg))
    if not include_secrets:
        for ctx in (safe.get("contexts") or {}).values():
            if ctx.get("api_key"):
                ctx["api_key"] = "***redacted***"
    typer.echo(json.dumps(safe, indent=2))


@config_app.command("use")
def config_use(context: str = typer.Argument(..., help="Context name to activate")):
    cfg = _load_config()
    if context not in (cfg.get("contexts") or {}):
        raise typer.BadParameter(f"Context '{context}' not found")
    cfg["active_context"] = context
    _save_config(cfg)
    typer.echo(f"Active context set to '{context}'")


@config_app.command("set")
def config_set(
    context: str | None = typer.Option(None, help="Context to update (defaults to active)"),
    api_url: str | None = typer.Option(None),
    api_key: str | None = typer.Option(None),
    profile: str | None = typer.Option(None),
    provider: str | None = typer.Option(None),
    redirect_uri: str | None = typer.Option(None),
):
    cfg = _load_config()
    ctx_name = context or cfg.get("active_context") or "default"
    cfg.setdefault("contexts", {}).setdefault(ctx_name, {})
    ctx = cfg["contexts"][ctx_name]

    changes = 0
    for key, value in {
        "api_url": api_url,
        "api_key": api_key,
        "profile": profile,
        "provider": provider,
        "redirect_uri": redirect_uri,
    }.items():
        if value is not None:
            ctx[key] = value
            changes += 1

    if changes == 0:
        raise typer.BadParameter("No values provided. Pass at least one option to update.")

    _save_config(cfg)
    typer.echo(f"Updated context '{ctx_name}'")


@config_app.command("ref-set")
def config_ref_set(
    ref_type: str = typer.Option(..., help="Reference type: model/provider/profile/redirect"),
    name: str = typer.Option(..., help="Reference key, e.g. fast or prod"),
    value: str = typer.Option(..., help="Reference value"),
):
    if ref_type not in {"model", "provider", "profile", "redirect"}:
        raise typer.BadParameter("ref_type must be one of: model, provider, profile, redirect")
    cfg = _load_config()
    cfg.setdefault("references", {}).setdefault(ref_type, {})[name] = value
    _save_config(cfg)
    typer.echo(f"Saved @{ref_type}:{name} -> {value}")


@config_app.command("ref-list")
def config_ref_list(ref_type: str | None = typer.Option(None, help="Optional filter type")):
    cfg = _load_config()
    refs = cfg.get("references") or {}
    if ref_type:
        if ref_type not in refs:
            raise typer.BadParameter("Unknown ref_type")
        typer.echo(json.dumps({ref_type: refs.get(ref_type, {})}, indent=2))
        return
    typer.echo(json.dumps(refs, indent=2))


@config_app.command("doctor")
def config_doctor(
    check_api: bool = typer.Option(True, help="Check API /healthz using active context"),
    check_auth: bool = typer.Option(False, help="Check authenticated endpoint /api/providers/status"),
):
    cfg = _load_config()
    issues: list[str] = []
    warnings: list[str] = []
    infos: list[str] = []

    contexts = cfg.get("contexts") or {}
    active_name = cfg.get("active_context") or "default"
    active = contexts.get(active_name)

    if not contexts:
        issues.append("No contexts configured. Run: auth-station config init")
    if active is None:
        issues.append(f"Active context '{active_name}' not found. Run: auth-station config use <context>")
    else:
        if not active.get("api_url"):
            issues.append(f"Context '{active_name}' is missing api_url")
        if not active.get("api_key"):
            issues.append(f"Context '{active_name}' is missing api_key")
        if not active.get("profile"):
            warnings.append(f"Context '{active_name}' is missing profile (will fall back to 'default')")
        if not active.get("provider"):
            warnings.append(f"Context '{active_name}' is missing provider (commands may default to 'google')")

    refs = cfg.get("references") or {}
    for ref_type in ("model", "provider", "profile", "redirect"):
        bucket = refs.get(ref_type)
        if bucket is None:
            warnings.append(f"Reference bucket '{ref_type}' missing (will be treated as empty)")
        elif not isinstance(bucket, dict):
            issues.append(f"Reference bucket '{ref_type}' should be an object")

    if check_api and active and active.get("api_url"):
        try:
            response = httpx.get(f"{active['api_url']}/healthz", timeout=10)
            if response.status_code == 200:
                infos.append(f"API reachable at {active['api_url']} (/healthz ok)")
            else:
                warnings.append(
                    f"API reachable but /healthz returned status {response.status_code} for {active['api_url']}"
                )
        except Exception as exc:
            warnings.append(f"Could not reach API health endpoint: {exc}")

    if check_auth and active and active.get("api_url") and active.get("api_key"):
        profile = active.get("profile") or "default"
        try:
            response = httpx.get(
                f"{active['api_url']}/api/providers/status",
                params={"profile": profile},
                headers=_headers(active["api_key"]),
                timeout=15,
            )
            if response.status_code == 200:
                infos.append("Authenticated API check passed (/api/providers/status)")
            elif response.status_code == 401:
                issues.append("Authenticated API check failed: unauthorized API key")
            else:
                warnings.append(f"Authenticated API check returned status {response.status_code}")
        except Exception as exc:
            warnings.append(f"Authenticated API check failed to run: {exc}")

    typer.echo("\n=== auth-station config doctor ===")
    typer.echo(f"Active context: {active_name}")
    typer.echo(f"Contexts found: {len(contexts)}")

    if issues:
        typer.echo("\nIssues:")
        for item in issues:
            typer.echo(f"- {item}")

    if warnings:
        typer.echo("\nWarnings:")
        for item in warnings:
            typer.echo(f"- {item}")

    if infos:
        typer.echo("\nChecks:")
        for item in infos:
            typer.echo(f"- {item}")

    if not issues and not warnings:
        typer.echo("\nResult: healthy")
        return

    if issues:
        raise typer.Exit(code=1)


@app.command()
def set_pref(
    api_url: str | None = typer.Option(None, help="Base API URL, e.g. http://localhost:8080"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    profile: str | None = typer.Option(None),
    model: str = typer.Option("gpt-4.1-mini"),
    thinking: bool = typer.Option(False),
    verbose: bool = typer.Option(False),
    compaction: bool = typer.Option(False),
):
    runtime = _resolve_runtime(api_url, api_key, profile=profile)
    cfg = _load_config()
    payload = {
        "profile": runtime["profile"],
        "model": _expand_reference_value(model, "model", cfg),
        "thinking": thinking,
        "verbose": verbose,
        "compaction": compaction,
    }
    _post(runtime["api_url"], "/api/preferences/upsert", runtime["api_key"], payload)
    typer.echo(f"Updated settings for profile '{runtime['profile']}'.")


@app.command()
def route(
    api_url: str | None = typer.Option(None, help="Base API URL, e.g. http://localhost:8080"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    profile: str | None = typer.Option(None, help="Routing profile"),
    model: str | None = typer.Option(None, help="Model override"),
    provider_hints: str = typer.Option("", help="Comma-separated providers"),
    thinking: bool | None = typer.Option(None, help="Thinking mode override"),
    verbose: bool | None = typer.Option(None, help="Verbose mode override"),
    compaction: bool | None = typer.Option(None, help="Compaction mode override"),
):
    runtime = _resolve_runtime(api_url, api_key, profile=profile)
    cfg = _load_config()
    hints = [h.strip() for h in provider_hints.split(",") if h.strip()]
    hints = [(_expand_reference_value(h, "provider", cfg) or h) for h in hints]
    payload = {
        "profile": runtime["profile"],
        "provider_hints": hints,
        "model": _expand_reference_value(model, "model", cfg),
        "thinking": thinking,
        "verbose": verbose,
        "compaction": compaction,
    }
    result = _post(runtime["api_url"], "/api/route/decide", runtime["api_key"], payload)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def providers(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    profile: str | None = typer.Option(None, help="Profile to evaluate token availability"),
):
    runtime = _resolve_runtime(api_url, api_key, profile=profile)
    result = _get(runtime["api_url"], f"/api/providers/status?profile={runtime['profile']}", runtime["api_key"])
    typer.echo(json.dumps(result, indent=2))


@app.command()
def credential_status(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    provider: str | None = typer.Option(None, help="Provider (openai/google/gemini/...)"),
    profile: str | None = typer.Option(None, help="Credential profile"),
):
    runtime = _resolve_runtime(api_url, api_key, profile=profile, provider=provider)
    final_provider = runtime["provider"] or "google"
    result = _get(
        runtime["api_url"],
        f"/api/providers/{final_provider}/credentials/{runtime['profile']}/status",
        runtime["api_key"],
    )
    typer.echo(json.dumps(result, indent=2))


@app.command()
def auth_start(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    provider: str | None = typer.Option(None, help="Provider (google/gemini/openai/...)"),
    profile: str | None = typer.Option(None, help="Profile to attach authorization to"),
    flow: str = typer.Option("device", help="Auth flow: device or browser"),
    redirect_uri: str | None = typer.Option(None, help="Redirect URI (for browser flow)"),
):
    runtime = _resolve_runtime(api_url, api_key, profile=profile, provider=provider, redirect_uri=redirect_uri)
    payload = {
        "provider": runtime["provider"] or "google",
        "profile": runtime["profile"],
        "flow": flow,
        "redirect_uri": runtime["redirect_uri"],
    }
    result = _post(runtime["api_url"], "/api/auth-sessions/start", runtime["api_key"], payload)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def auth_poll(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    session_id: str = typer.Option(..., help="Session id from auth-start"),
):
    runtime = _resolve_runtime(api_url, api_key)
    result = _post(runtime["api_url"], "/api/auth-sessions/poll", runtime["api_key"], {"session_id": session_id})
    typer.echo(json.dumps(result, indent=2))


@app.command()
def auth_complete(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    session_id: str = typer.Option(..., help="Session id from auth-start"),
    authorization_code: str | None = typer.Option(None, help="Code from redirect URL for browser flow"),
):
    runtime = _resolve_runtime(api_url, api_key)
    payload = {"session_id": session_id, "authorization_code": authorization_code}
    result = _post(runtime["api_url"], "/api/auth-sessions/complete", runtime["api_key"], payload)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def auth_cancel(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    session_id: str = typer.Option(..., help="Session id from auth-start"),
):
    runtime = _resolve_runtime(api_url, api_key)
    result = _post(runtime["api_url"], "/api/auth-sessions/cancel", runtime["api_key"], {"session_id": session_id})
    typer.echo(json.dumps(result, indent=2))


@app.command()
def auth_login(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    provider: str | None = typer.Option(None, help="Provider, e.g. google or gemini"),
    profile: str | None = typer.Option(None, help="Credential profile"),
    mode: str = typer.Option("device", help="Login mode: device or browser"),
    redirect_uri: str | None = typer.Option(None, help="Redirect URI for browser mode"),
    poll_seconds: int = typer.Option(5, help="Polling interval in seconds"),
    timeout_seconds: int = typer.Option(300, help="How long to poll before giving up"),
):
    """Guided login. Device mode is best for remote servers; browser mode supports paste-back callback URL."""
    runtime = _resolve_runtime(api_url, api_key, profile=profile, provider=provider, redirect_uri=redirect_uri)
    if mode not in {"device", "browser"}:
        typer.echo("mode must be one of: device, browser")
        raise typer.Exit(code=2)

    started = _post(
        runtime["api_url"],
        "/api/auth-sessions/start",
        runtime["api_key"],
        {
            "provider": runtime["provider"] or "google",
            "profile": runtime["profile"],
            "flow": mode,
            "redirect_uri": runtime["redirect_uri"],
        },
    )
    session_id = started["id"]
    effective_mode = (started.get("flow") or mode).strip().lower()

    if effective_mode == "browser":
        typer.echo("\nSTEP 1: Paste this URL in a browser and sign in:")
        typer.echo(started.get("verification_uri") or "<missing verification_uri>")
        typer.echo("\nSTEP 2: After login, copy the FULL redirected URL and paste it below.")
        pasted = typer.prompt("Paste redirected URL (or just code)")

        code = pasted.strip()
        if "?" in code or "code=" in code:
            parsed = urlparse(code)
            query = parse_qs(parsed.query)
            code = (query.get("code") or [""])[0]
        if not code:
            typer.echo("No authorization code detected.")
            raise typer.Exit(code=1)

        completed = _post(
            runtime["api_url"],
            "/api/auth-sessions/complete",
            runtime["api_key"],
            {"session_id": session_id, "authorization_code": code},
        )
        typer.echo("Done. Authorization complete and credential stored.")
        typer.echo(json.dumps(completed, indent=2))
        return

    typer.echo("\nOpen this URL in a browser:")
    typer.echo(started.get("verification_uri") or "<missing verification_uri>")
    typer.echo("\nEnter this code:")
    typer.echo(started.get("user_code") or "<missing user_code>")
    typer.echo(f"\nSession ID: {session_id}\n")

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        polled = _post(runtime["api_url"], "/api/auth-sessions/poll", runtime["api_key"], {"session_id": session_id})
        status = polled.get("status")
        typer.echo(f"status={status}")

        if status == "authorized":
            typer.echo("Done. Authorization complete and credential stored.")
            typer.echo(json.dumps(polled, indent=2))
            return
        if status in {"failed", "expired", "canceled"}:
            typer.echo(json.dumps(polled, indent=2))
            raise typer.Exit(code=1)

        time.sleep(max(1, poll_seconds))

    typer.echo("Timed out waiting for authorization. You can continue with auth-poll later.")
    raise typer.Exit(code=1)


@app.command()
def models(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
):
    runtime = _resolve_runtime(api_url, api_key)
    result = _get(runtime["api_url"], "/v1/models", runtime["api_key"])
    typer.echo(json.dumps(result, indent=2))


@app.command()
def slash(
    api_url: str | None = typer.Option(None, help="Base API URL"),
    api_key: str | None = typer.Option(None, help="Authorization Station API key"),
    command_text: str = typer.Argument(..., help="Slash command text, e.g. '/set-model gpt-4.1-mini'"),
    profile: str | None = typer.Option(None, help="Profile to modify"),
):
    runtime = _resolve_runtime(api_url, api_key, profile=profile)
    cfg = _load_config()
    expanded = command_text
    for ref_type in ("model", "provider", "profile", "redirect"):
        for name, value in (cfg.get("references") or {}).get(ref_type, {}).items():
            expanded = expanded.replace(f"@{ref_type}:{name}", str(value))

    result = _post(
        runtime["api_url"],
        "/api/commands/execute",
        runtime["api_key"],
        {"profile": runtime["profile"], "command_text": expanded},
    )
    typer.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
