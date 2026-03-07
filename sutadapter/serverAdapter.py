#!/usr/bin/env python3

# Code was generated via copilot
"""
Sequential TCP Echo Server (no threading)

Usage:
    python echo_server_sequential.py --host 127.0.0.1 --port 65432

Both --host and --port are optional. Defaults:
    host = 127.0.0.1
    port = 65432
"""

import argparse
import socket
import signal
import sys
from contextlib import closing

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Sequential TCP Echo Server (no threading)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="IP address to bind (default: 127.0.0.1). Use 0.0.0.0 to listen on all IPv4 interfaces.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=65432,
        help="TCP port to listen on (default: 65432).",
    )
    parser.add_argument(
        "--backlog",
        type=int,
        default=5,
        help="Listen backlog (default: 5).",
    )
    parser.add_argument(
        "--reuse-port",
        action="store_true",
        help="Enable SO_REUSEPORT if supported (default: off).",
    )
    return parser.parse_args(argv)

def run_server(host: str, port: int, backlog: int = 5, reuse_addr: bool = True, reuse_port: bool = False):
    """
    Run a sequential echo server. Handles exactly ONE client then exits.
    The process is restarted externally by runSocketAdapter.sh after each client,
    ensuring a fully clean TCP state for every learning query.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server_sock:
        # Make restarts easier during development
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 if reuse_addr else 0)
        if reuse_port and hasattr(socket, "SO_REUSEPORT"):
            try:
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                # Not supported on this platform—ignore
                pass

        server_sock.bind((host, port))
        server_sock.listen(backlog)
        # Set a timeout so Ctrl+C can interrupt even if waiting in accept()
        server_sock.settimeout(0.5)

        bound_host, bound_port = server_sock.getsockname()
        print(f"[*] Echo server (sequential) listening on {bound_host}:{bound_port}")
        print("[*] Press Ctrl+C to stop.")

        # Accept exactly one client, serve it, then exit so the wrapper script
        # (start_server.sh) can restart us with a fully clean OS TCP state.

        conn = None
        while conn is None:
            # Loop only while waiting for a client 
            try:
                conn, addr = server_sock.accept()
            except socket.timeout:
                continue  # no client yet, loop back so Ctrl+C can be caught
            except KeyboardInterrupt:
                print("\n[!] Interrupt received, stopping...")
                return

        try:
            with conn:
                print(f"[+] Connected: {addr}")
                conn.settimeout(60.0)
                while True:
                    data = conn.recv(4096)
                    if not data:
                        # Client closed the connection — exit process
                        break
                    conn.sendall(data)  # Echo back
        except ConnectionResetError:
            print("[!] Connection reset by peer.")
        except socket.timeout:
            print("[!] Connection timed out.")
        except OSError as e:
            print(f"[!] Socket error: {e}")

        print("[*] Client done, exiting for clean restart.")

def main(argv=None):
    args = parse_args(argv)

    # Graceful Ctrl+C handling (SIGINT)
    # On POSIX, also handle SIGTERM for container/service stop
    def _signal_handler(sig, frame):
        # We rely on the accept() timeout loop to exit; just print a hint.
        # The KeyboardInterrupt path will handle clean exit.
        sys.exit(1)
        pass

    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)

    try:
        run_server(
            host=args.host,
            port=args.port,
            backlog=args.backlog,
            reuse_addr=True,
            reuse_port=args.reuse_port,
        )
    except OSError as e:
        print(f"[!] Failed to start server on {args.host}:{args.port} — {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
