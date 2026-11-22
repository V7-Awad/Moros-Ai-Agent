#!/usr/bin/env python3
"""Import a local OpenAPI/Swagger document into Moros endpoint inventory."""

import argparse
import json
from pathlib import Path

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def load_spec(path: Path):
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("YAML input needs PyYAML. Install it with: pip install PyYAML") from exc
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("OpenAPI document must contain a YAML/JSON object")
    return data


def extract_endpoints(spec):
    servers = spec.get("servers") or []
    if servers:
        base_url = servers[0].get("url", "")
    else:  # Swagger 2.0
        schemes = spec.get("schemes") or [""]
        base_url = f"{schemes[0]}://{spec.get('host', '')}{spec.get('basePath', '')}" if spec.get("host") else ""
    global_security = spec.get("security", [])
    endpoints = []
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        shared_params = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = []
            for param in shared_params + operation.get("parameters", []):
                if isinstance(param, dict):
                    schema = param.get("schema") or param
                    params.append({"name": param.get("name"), "in": param.get("in"),
                                   "required": bool(param.get("required")), "type": schema.get("type"),
                                   "description": param.get("description", "")})
            body = operation.get("requestBody", {})
            body_content = sorted((body.get("content") or {}).keys()) if isinstance(body, dict) else []
            if not body_content and any(p.get("in") in {"body", "formData"} for p in operation.get("parameters", []) if isinstance(p, dict)):
                body_content = spec.get("consumes", [])
            body_required = bool(body.get("required")) if isinstance(body, dict) else False
            if not body_required:
                body_required = any(p.get("in") == "body" and p.get("required") for p in operation.get("parameters", []) if isinstance(p, dict))
            endpoints.append({"method": method.upper(), "path": path, "base_url": base_url,
                              "operation_id": operation.get("operationId", ""),
                              "summary": operation.get("summary", ""), "tags": operation.get("tags", []),
                              "parameters": params,
                              "request_body_required": body_required,
                              "request_body_content_types": body_content,
                              "security": operation.get("security", global_security)})
    return endpoints


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, help="Local OpenAPI/Swagger JSON or YAML file")
    parser.add_argument("--output", required=True, help="Output JSON inventory path")
    parser.add_argument("--target", default="", help="Target label stored in output metadata")
    args = parser.parse_args()
    source, output = Path(args.spec).resolve(), Path(args.output).resolve()
    if not source.is_file():
        parser.error(f"spec file not found: {source}")
    try:
        spec = load_spec(source)
        if not isinstance(spec, dict) or not ("openapi" in spec or "swagger" in spec):
            raise ValueError("document does not declare an OpenAPI or Swagger version")
        endpoints = extract_endpoints(spec)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"target": args.target, "source_file": str(source),
                                      "spec_version": spec.get("openapi", spec.get("swagger")),
                                      "total_endpoints": len(endpoints), "endpoints": endpoints},
                                     indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        log_path = output.parent.parent / "logs" / "api-spec-discovery" / "import.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"Imported {len(endpoints)} endpoints from {source}\nOutput: {output}\n",
                            encoding="utf-8")
    except (ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Imported {len(endpoints)} endpoints into {output}")


if __name__ == "__main__":
    main()
