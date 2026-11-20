"""Generates all 4 publication-grade, vector-quality figures for the VANISH IEEE paper.
Engineered to exact IEEE single-column dimensions (width 3.4-3.5 inches),
ensuring high-contrast, crystal-clear typography matching 9-10pt body font.
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

# Global IEEE Typography Settings
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["DejaVu Serif", "Times New Roman", "Computer Modern Roman"],
    "font.size": 8.5,
    "axes.labelsize": 8.5,
    "axes.labelweight": "bold",
    "axes.titlesize": 9.0,
    "axes.titleweight": "bold",
    "xtick.labelsize": 7.8,
    "ytick.labelsize": 7.8,
    "legend.fontsize": 7.5,
    "figure.titlesize": 9.5,
    "lines.linewidth": 1.6,
    "lines.markersize": 5.0,
})

FIG_DIR = Path("paper/figures")
FIG_DIR.mkdir(parents=True, exist_ok=True)


def generate_fig1_architecture(out_path: Path) -> None:
    """Generate high-clarity OS enforcement architecture diagram."""
    fig, ax = plt.subplots(figsize=(3.4, 3.8), dpi=300)
    ax.set_xlim(-0.2, 10.2)
    ax.set_ylim(-0.5, 10.7)
    ax.axis("off")

    color_app = "#f0f7fa"
    color_kernel = "#e8f1f8"
    color_daemon = "#fef6ed"
    color_purge = "#fdf0ed"
    border = "#1e293b"

    box_kw = dict(boxstyle="round,pad=0.22", edgecolor=border, linewidth=1.1)

    # Box 1: Client Apps
    rect1 = patches.FancyBboxPatch((0.5, 8.9), 9.0, 1.2, facecolor=color_app, **box_kw)
    ax.add_patch(rect1)
    ax.text(5.0, 9.68, "User Space / Client Applications", ha="center", va="center", fontsize=8.2, fontweight="bold", color="#0f172a")
    ax.text(5.0, 9.18, "(Files by Google, Nautilus, Shell, Browser)", ha="center", va="center", fontsize=7.2, color="#334155")

    # Arrow 1 -> 2
    ax.annotate("", xy=(3.0, 7.8), xytext=(3.0, 8.9), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#1e293b"))
    ax.text(3.4, 8.35, "Storage Interception", ha="left", va="center", fontsize=7.0, fontstyle="italic", color="#1e293b",
            bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none", alpha=0.9))

    # Box 2: Kernel Ingestion
    rect2 = patches.FancyBboxPatch((0.5, 6.6), 9.0, 1.2, facecolor=color_kernel, **box_kw)
    ax.add_patch(rect2)
    ax.text(5.0, 7.38, "Kernel & Storage Ingestion Layer", ha="center", va="center", fontsize=8.2, fontweight="bold", color="#0f172a")
    ax.text(5.0, 6.88, "(Linux fanotify / AOSP ModernMediaScanner)", ha="center", va="center", fontsize=7.2, color="#334155")

    # Arrow 2 -> 3
    ax.annotate("", xy=(3.0, 5.4), xytext=(3.0, 6.6), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#1e293b"))
    ax.text(3.4, 6.0, "AIDL IPC / fanotify event", ha="left", va="center", fontsize=7.0, fontstyle="italic", color="#1e293b",
            bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none", alpha=0.9))

    # Box 3: Daemon
    rect3 = patches.FancyBboxPatch((0.5, 3.1), 9.0, 2.3, facecolor=color_daemon, **box_kw)
    ax.add_patch(rect3)
    ax.text(5.0, 5.08, "VANISH Lifecycle Enforcement Engine", ha="center", va="center", fontsize=8.2, fontweight="bold", color="#0f172a")
    ax.text(5.0, 4.68, "(Linux vanishd / AOSP VanishManagerService)", ha="center", va="center", fontsize=7.2, color="#1e293b")
    ax.text(5.0, 4.18, "• Thread-Safe Min-Heap Priority Queue", ha="center", va="center", fontsize=7.0, color="#334155")
    ax.text(5.0, 3.78, "• Ed25519 & Canonical CBOR Verification", ha="center", va="center", fontsize=7.0, color="#334155")
    ax.text(5.0, 3.38, "• Doze-Resilient AlarmManager / timerfd", ha="center", va="center", fontsize=7.0, color="#334155")

    # Arrow 3 -> 4
    ax.annotate("", xy=(3.0, 2.2), xytext=(3.0, 3.1), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#b91c1c"))
    ax.text(3.4, 2.65, "t >= t_exp (Deadline Fired)", ha="left", va="center", fontsize=7.0, fontweight="bold", color="#b91c1c",
            bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none", alpha=0.9))

    # Box 4: Purge Engine
    rect4 = patches.FancyBboxPatch((0.5, 0.70), 9.0, 1.5, facecolor=color_purge, **box_kw)
    ax.add_patch(rect4)
    ax.text(5.0, 1.88, "Lifecycle Purge & Shred Engine", ha="center", va="center", fontsize=8.2, fontweight="bold", color="#991b1b")
    ax.text(5.0, 1.48, "• PRNG Multi-Pass Overwriting (Magnetic Media)", ha="center", va="center", fontsize=7.0, color="#334155")
    ax.text(5.0, 1.08, "• Hardware Keystore Key Erasure (Flash Storage)", ha="center", va="center", fontsize=7.0, color="#334155")

    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.10)
    fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight", pad_inches=0.10, dpi=300)
    plt.close()
    print(f"[+] Clean, vector architecture figure generated: {out_path.with_suffix('.pdf')}")


def generate_fig2_latency(out_path: Path) -> None:
    """Generate publication-grade latency vs payload size curve."""
    sizes_kb = [1, 10, 100, 1024, 5120, 20480]
    pack_unenc = [0.93, 0.98, 1.12, 2.60, 10.42, 37.71]
    pack_enc = [0.90, 0.95, 1.12, 2.92, 12.18, 46.49]
    unpack = [0.65, 0.70, 0.81, 2.35, 10.85, 40.22]

    fig, ax = plt.subplots(figsize=(3.4, 2.3), dpi=300)

    ax.plot(sizes_kb, pack_unenc, "o-", label="Pack (Unencrypted)", color="#1a5276", markersize=4.8)
    ax.plot(sizes_kb, pack_enc, "s--", label="Pack (AES-256-GCM)", color="#922b21", markersize=4.8)
    ax.plot(sizes_kb, unpack, "^-.", label="Unpack & Verify", color="#196f3d", markersize=5.2)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Payload Size (KB)", fontweight="bold")
    ax.set_ylabel("Execution Latency (ms)", fontweight="bold")
    ax.set_title("VANISH Latency vs. Payload Size", fontweight="bold", pad=5)
    ax.grid(True, which="major", ls="-", color="#e2e8f0", alpha=0.9, lw=0.6)
    ax.grid(True, which="minor", ls=":", color="#f1f5f9", alpha=0.7, lw=0.5)
    ax.legend(frameon=True, facecolor="white", edgecolor="#cbd5e1", framealpha=0.95, loc="upper left")
    fig.tight_layout(pad=0.4)

    fig.savefig(out_path.with_suffix(".pdf"))
    fig.savefig(out_path.with_suffix(".png"), dpi=300)
    plt.close()
    print(f"[+] Publication-grade Latency figure generated: {out_path.with_suffix('.pdf')}")


def generate_fig3_comparative(out_path: Path) -> None:
    """Generate publication-grade comparative baseline bar chart."""
    systems = ["Raw AES-GCM", "Standard TAR", "Signed Env.", "VANISH (.vfile)"]
    create_ms = [1.26, 0.85, 1.55, 2.92]
    extract_ms = [0.92, 0.90, 1.52, 2.35]

    x = np.arange(len(systems))
    width = 0.35

    fig, ax = plt.subplots(figsize=(3.4, 2.3), dpi=300)

    rects1 = ax.bar(x - width/2, create_ms, width, label="Packaging / Creation", color="#1b4f72", edgecolor="#0f2942", linewidth=0.7)
    rects2 = ax.bar(x + width/2, extract_ms, width, label="Unpack & Verification", color="#196f3d", edgecolor="#0e4324", linewidth=0.7)

    ax.set_ylabel("Latency (ms) for 1MB", fontweight="bold")
    ax.set_title("1MB Payload Baseline Comparison", fontweight="bold", pad=5)
    ax.set_xticks(x)
    ax.set_xticklabels(systems, fontsize=7.2, fontweight="bold")
    ax.legend(frameon=True, facecolor="white", edgecolor="#cbd5e1", framealpha=0.95, loc="upper left")
    ax.grid(axis="y", ls="--", color="#e2e8f0", alpha=0.8, lw=0.6)
    ax.set_ylim(0, 3.65)

    for bar in rects1:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.07, f"{yval:.2f}", ha="center", va="bottom", fontsize=6.8, fontweight="bold")

    for bar in rects2:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.07, f"{yval:.2f}", ha="center", va="bottom", fontsize=6.8, fontweight="bold")

    fig.tight_layout(pad=0.4)
    fig.savefig(out_path.with_suffix(".pdf"))
    fig.savefig(out_path.with_suffix(".png"), dpi=300)
    plt.close()
    print(f"[+] Publication-grade Comparative figure generated: {out_path.with_suffix('.pdf')}")


def generate_fig4_breakdown(out_path: Path) -> None:
    """Generate publication-grade verification breakdown bar chart."""
    stages = ["Parse", "Ed25519", "SHA-256", "Clock"]
    times = [0.37, 0.57, 0.48, 0.0002]
    colors = ["#1f4e78", "#2e7d32", "#c0392b", "#d35400"]

    fig, ax = plt.subplots(figsize=(3.4, 2.1), dpi=300)

    bars = ax.bar(stages, times, color=colors, width=0.46, edgecolor="#1e293b", linewidth=0.7)
    ax.set_ylabel("Latency (ms) for 1MB", fontweight="bold")
    ax.set_title("Verification Sub-Component Breakdown", fontweight="bold", pad=5)
    ax.grid(axis="y", ls="--", color="#e2e8f0", alpha=0.8, lw=0.6)
    ax.set_ylim(0, 0.74)

    for bar in bars:
        yval = bar.get_height()
        label_text = f"{yval:.2f} ms" if yval >= 0.01 else "<0.01 ms"
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.02, label_text, ha="center", va="bottom", fontsize=7.2, fontweight="bold")

    fig.tight_layout(pad=0.4)
    fig.savefig(out_path.with_suffix(".pdf"))
    fig.savefig(out_path.with_suffix(".png"), dpi=300)
    plt.close()
    print(f"[+] Publication-grade Breakdown figure generated: {out_path.with_suffix('.pdf')}")


if __name__ == "__main__":
    generate_fig1_architecture(FIG_DIR / "fig_os_architecture")
    generate_fig2_latency(FIG_DIR / "fig_latency_vs_size")
    generate_fig3_comparative(FIG_DIR / "fig_comparative_baseline")
    generate_fig4_breakdown(FIG_DIR / "fig_verification_breakdown")
    print("[*] All 4 vector figures generated successfully with publication-grade IEEE styling!")
