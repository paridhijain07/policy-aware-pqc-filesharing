"""
Generates publication-quality charts from experimental evaluation datasets.
Produces high-resolution PNG charts in results/plots/
"""

import os
import matplotlib.pyplot as plt
import pandas as pd


def plot_all():
    os.makedirs("results/plots", exist_ok=True)
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    plt.rcParams.update({
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.titlesize": 13,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "figure.titlesize": 14,
    })

    # --- PLOT 1: Unauthorized Downgrade Comparison ---
    sec_csv = "results/security_evaluation.csv"
    if os.path.exists(sec_csv):
        df_sec = pd.read_csv(sec_csv)
        summary = df_sec.groupby("Architecture")["Unauthorized Downgrade"].mean() * 100

        fig, ax = plt.subplots(figsize=(7, 4.5))
        colors = ["#e63946", "#2a9d8f"]
        bars = ax.bar(summary.index, summary.values, color=colors, width=0.45, edgecolor="black", linewidth=1.2)

        ax.set_ylabel("Unauthorized Downgrade Rate (%)", fontweight="bold")
        ax.set_title("Vulnerability Evaluation: Resistance to Induced ML-KEM Drop", fontweight="bold", pad=12)
        ax.set_ylim(0, 115)

        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.1f}%",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 5), textcoords="offset points",
                        ha="center", va="bottom", fontweight="bold", fontsize=12)

        ax.text(0, 50, "SILENT DOWNGRADE\nEXPLOITABLE (SNDL)", ha="center", color="white", fontweight="bold")
        ax.text(1, 10, "STRICT POLICY GUARD\n0% DOWNGRADES", ha="center", color="#1d3557", fontweight="bold")

        plt.tight_layout()
        plt.savefig("results/plots/downgrade_prevention_rate.png", dpi=300)
        plt.close()
        print("[+] Generated: results/plots/downgrade_prevention_rate.png")

    # --- PLOT 2: Cryptographic Computation Time ---
    crypto_csv = "results/crypto_benchmark_results.csv"
    if os.path.exists(crypto_csv):
        df_crypto = pd.read_csv(crypto_csv)
        # Exclude AEAD throughput row for the latency plot
        df_kex = df_crypto[df_crypto["Type"] != "Symmetric Encryption/Auth"].copy()

        fig, ax = plt.subplots(figsize=(8, 4.5))
        bars = ax.barh(df_kex["Primitive"], df_kex["Avg Time (ms)"], color=["#457b9d", "#1d3557", "#2a9d8f"], edgecolor="black")
        ax.set_xlabel("Computation Time (ms)", fontweight="bold")
        ax.set_title("Cryptographic Microbenchmark: Key Agreement Latency", fontweight="bold", pad=12)

        for bar in bars:
            width = bar.get_width()
            ax.annotate(f"{width:.3f} ms",
                        xy=(width, bar.get_y() + bar.get_height() / 2),
                        xytext=(8, 0), textcoords="offset points",
                        ha="left", va="center", fontweight="bold")

        ax.set_xlim(0, max(df_kex["Avg Time (ms)"]) * 1.25)
        plt.tight_layout()
        plt.savefig("results/plots/crypto_latency_benchmark.png", dpi=300)
        plt.close()
        print("[+] Generated: results/plots/crypto_latency_benchmark.png")

    # --- PLOT 3: Handshake Wire Overhead (Public Key + Ciphertext) ---
    if os.path.exists(crypto_csv):
        df_crypto = pd.read_csv(crypto_csv)
        df_kex = df_crypto[df_crypto["Type"] != "Symmetric Encryption/Auth"].copy()

        fig, ax = plt.subplots(figsize=(8, 4.5))
        bars = ax.bar(df_kex["Primitive"], df_kex["Public Key Size (Bytes)"] + df_kex["Ciphertext / Exchange Size (Bytes)"],
                      color=["#a8dadc", "#457b9d", "#e76f51"], width=0.45, edgecolor="black")
        ax.set_ylabel("Total Key Exchange Payload (Bytes)", fontweight="bold")
        ax.set_title("Communication Overhead: Public Key & Ciphertext Exchange", fontweight="bold", pad=12)

        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{int(height)} B",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontweight="bold")

        ax.set_ylim(0, max(bars, key=lambda b: b.get_height()).get_height() * 1.2)
        plt.tight_layout()
        plt.savefig("results/plots/wire_overhead_comparison.png", dpi=300)
        plt.close()
        print("[+] Generated: results/plots/wire_overhead_comparison.png")

    # --- PLOT 4: Resumption Recovery Time ---
    rec_csv = "results/recovery_evaluation.csv"
    if os.path.exists(rec_csv):
        df_rec = pd.read_csv(rec_csv)
        fig, ax = plt.subplots(figsize=(7, 4.5))
        ax.boxplot([df_rec["Total Time (ms)"]], labels=["Stateful Resumption (Midway Severance)"], patch_artist=True,
                    boxprops=dict(facecolor="#2a9d8f", color="black"),
                    medianprops=dict(color="#e63946", linewidth=2))
        ax.set_ylabel("Total Recovery & Completion Time (ms)", fontweight="bold")
        ax.set_title("Recovery Performance: Resumption Under Network Severance", fontweight="bold", pad=12)
        plt.tight_layout()
        plt.savefig("results/plots/recovery_time_analysis.png", dpi=300)
        plt.close()
        print("[+] Generated: results/plots/recovery_time_analysis.png")

    # --- PLOT 5: Throughput Across File Sizes ---
    tp_csv = "results/throughput_evaluation.csv"
    if os.path.exists(tp_csv):
        df_tp = pd.read_csv(tp_csv)
        summary_tp = df_tp.groupby(["File_Size_KB", "Architecture"])["Throughput_MBps"].mean().unstack()
        fig, ax = plt.subplots(figsize=(8, 4.5))
        summary_tp.plot(kind="bar", ax=ax, color=["#457b9d", "#2a9d8f"], edgecolor="black")
        ax.set_xlabel("File Size (KB)", fontweight="bold")
        ax.set_ylabel("Throughput (MB/s)", fontweight="bold")
        ax.set_title("Data Transfer Throughput vs File Size", fontweight="bold", pad=12)
        ax.legend(title="Architecture")
        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig("results/plots/throughput_evaluation.png", dpi=300)
        plt.close()
        print("[+] Generated: results/plots/throughput_evaluation.png")


if __name__ == "__main__":
    plot_all()

