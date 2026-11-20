import os
import socket
import sys
from urllib.parse import urlparse


def main() -> None:
    env_url = os.environ.get("MAKEFUN_ENV_URL", "").strip().rstrip("/")
    if not env_url:
        sys.stderr.write("[cobalt-forge] MAKEFUN_ENV_URL is not set\n")
        sys.exit(1)

    parsed = urlparse(env_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    prefix = (parsed.path or "").rstrip("/")
    host_header = f"{host}:{port}" if parsed.port else host

    # Resolve IPv4 in Python so the static C++ binary never invokes glibc NSS DNS.
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        sys.stderr.write(f"[cobalt-forge] failed to resolve env host {host}\n")
        sys.exit(1)
    env_ip = infos[0][4][0]

    os.environ["MAKEFUN_ENV_IP"] = env_ip
    os.environ["MAKEFUN_ENV_PORT"] = str(port)
    os.environ["MAKEFUN_ENV_HOST"] = host_header
    os.environ["MAKEFUN_ENV_PREFIX"] = prefix

    bin_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "forge")
    os.execv(bin_path, [bin_path, "--env-mode"])


if __name__ == "__main__":
    main()
