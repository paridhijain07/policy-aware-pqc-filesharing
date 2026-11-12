"""
Unified Command-Line Interface and Launcher for Policy-Aware Post-Quantum File Sharing.
Usage:
    python main.py --ui                  # Launches Web Dashboard at http://localhost:8000
    python main.py --benchmark           # Executes benchmarks & generates publication charts
    python main.py --test                # Runs full pytest test suite
    python main.py --server              # Runs standalone file sharing server
    python main.py --client              # Executes a test client transfer
"""

import sys
import os
import argparse
import asyncio
import uvicorn


def main():
    parser = argparse.ArgumentParser(
        description="Policy-Aware Post-Quantum Secure File Sharing Under Network Failures",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--ui", action="store_true", help="Launch interactive Web Dashboard (default)")
    parser.add_argument("--port", type=int, default=8000, help="Web UI port (default: 8000)")
    parser.add_argument("--benchmark", action="store_true", help="Run benchmarks and generate charts")
    parser.add_argument("--test", action="store_true", help="Run pytest verification suite")
    parser.add_argument("--server", action="store_true", help="Run standalone server on port 8765")
    parser.add_argument("--client", action="store_true", help="Run test client file transfer")
    parser.add_argument("--download", type=str, default=None, help="Download specified file from server")
    parser.add_argument("--file", type=str, default=None, help="Target file for client transfer")
    parser.add_argument("--policy", type=str, default="STRICT_HYBRID", choices=["STRICT_HYBRID", "STRICT_PQC", "COMPAT_CLASSICAL", "ALLOW_FALLBACK"], help="Enforcement policy")
    parser.add_argument("--mode", type=str, default=None, choices=["HYBRID_X25519_MLKEM768", "PQC_MLKEM768", "CLASSICAL_X25519"], help="Preferred key-establishment mode")

    args = parser.parse_args()

    # 1. Run Tests
    if args.test:
        print("\n[*] Running complete test suite via pytest...")
        import pytest
        exit_code = pytest.main(["tests", "-v"])
        sys.exit(exit_code)

    # 2. Run Benchmarks
    elif args.benchmark:
        print("\n[*] Executing benchmarks & generating experimental charts...")
        from evaluation.benchmark_crypto import benchmark_primitives
        from evaluation.run_experiments import main as run_exp
        from evaluation.plot_results import plot_all

        benchmark_primitives(iterations=100)
        asyncio.run(run_exp())
        plot_all()
        print("\n[+] Benchmarks complete. Charts saved in results/plots/")
        return

    # 3. Standalone Server
    elif args.server:
        print("\n[*] Starting standalone File Sharing Server on port 8765...")
        from core.server import FileSharingServer
        server = FileSharingServer(host="0.0.0.0", port=8765)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            loop.run_until_complete(server.stop())
        return

    # 4. Standalone Client (Upload or Download)
    elif args.client or args.download:
        from core.client_policy import PolicyAwareClient
        from policy.modes import PolicyLevel, SecurityMode

        pref_mode = SecurityMode(args.mode) if args.mode else None
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=8765,
            policy=PolicyLevel(args.policy),
            preferred_mode=pref_mode
        )

        if args.download:
            download_dir = "storage/client_downloads"
            os.makedirs(download_dir, exist_ok=True)
            print(f"\n[*] Initiating secure download of '{args.download}' with policy '{args.policy}'...")
            res = asyncio.run(client.download_file(file_name=args.download, dest_dir=download_dir))
            print(f"\n[+] Download Result: {res}")
            return

        target_file = args.file
        if not target_file:
            os.makedirs("storage/client_uploads", exist_ok=True)
            target_file = "storage/client_uploads/sample_doc.bin"
            if not os.path.exists(target_file):
                with open(target_file, "wb") as f:
                    f.write(os.urandom(128 * 1024))

        print(f"\n[*] Initiating transfer of '{target_file}' with policy '{args.policy}' (preferred mode: {args.mode or 'Auto'})...")
        res = asyncio.run(client.transfer_file(target_file))
        print(f"\n[+] Transfer Result: {res}")
        return

    # Default: Run Web Dashboard
    print(f"\n========================================================================")
    print(f"🛡️  Policy-Aware Post-Quantum Secure File Sharing Dashboard")
    print(f"========================================================================")
    print(f"[*] Post-Quantum KEM: ML-KEM-768 (NIST FIPS 203 Category 3)")
    print(f"[*] Classical Key Agreement: X25519 (RFC 7748)")
    print(f"[*] Key Combiner: Dual-PRF HKDF-SHA256 (RFC 9954 aligned)")
    print(f"[*] Symmetric Cipher: AES-256-GCM chunked AEAD")
    print(f"\n>>> Web Dashboard running at: http://localhost:{args.port}")
    print(f">>> Press CTRL+C to stop.\n")

    uvicorn.run("ui.app:app", host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

