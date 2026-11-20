"""Generates all 4 publication-grade, vector-quality figures for the VANISH IEEE paper.
Engineered to exact IEEE single-column dimensions, ensuring high-contrast, crystal-clear typography,
zero text collision, zero label overlap, and pristine publication aesthetics.
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

FIG_DIR = Path("paper/figures")
FIG_DIR.mkdir(parents=True, exist_ok=True)

# Academic serif typography for plots matching IEEE conference body text
SERIF_RC = {
    "font.family": "serif",
    "font.serif": ["DejaVu Serif", "Times New Roman", "Computer Modern Roman"],
    "font.size": 8.0,
    "axes.labelsize": 8.5,
    "axes.labelweight": "bold",
    "axes.titlesize": 9.0,
    "axes.titleweight": "bold",
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5,
    "legend.fontsize": 7.2,
}


def generate_fig1_architecture(out_path: Path) -> None:
    """Generate high-clarity OS enforcement architecture diagram.
    Uses clean sans-serif typography with generous internal padding so text never touches borders.
    """
    fig, ax = plt.subplots(figsize=(3.4, 4.0), dpi=300)
    ax.set_xlim(-0.2, 10.2)
    ax.set_ylim(-0.35, 10.6)
    ax.axis("off")

    sans_font = {"fontfamily": "DejaVu Sans"}

    color_app = "#f0f7fa"
    color_kernel = "#e8f1f8"
    color_daemon = "#fef6ed"
    color_purge = "#fdf0ed"
    border_col = "#334155"
    kw = dict(boxstyle="round,pad=0.22", edgecolor=border_col, linewidth=1.1)

    # Box 1: User Space Apps
    rect1 = patches.FancyBboxPatch((0.5, 8.90), 9.0, 1.25, facecolor=color_app, **kw)
    ax.add_patch(rect1)
    ax.text(5.0, 9.72, "User Space / Client Applications", ha="center", va="center", fontsize=7.6, fontweight="bold", color="#0f172a", **sans_font)
    ax.text(5.0, 9.24, "(Files by Google, Nautilus, Shell, Browser)", ha="center", va="center", fontsize=6.3, color="#475569", **sans_font)

    # Arrow 1 -> 2
    ax.annotate("", xy=(3.0, 7.65), xytext=(3.0, 8.90), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#334155"))
    ax.text(3.3, 8.28, "Storage Interception", ha="left", va="center", fontsize=6.3, fontstyle="italic", color="#334155",
            bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="#cbd5e1", lw=0.6), **sans_font)

    # Box 2: Kernel Ingestion
    rect2 = patches.FancyBboxPatch((0.5, 6.40), 9.0, 1.25, facecolor=color_kernel, **kw)
    ax.add_patch(rect2)
    ax.text(5.0, 7.22, "Kernel & Storage Ingestion Layer", ha="center", va="center", fontsize=7.6, fontweight="bold", color="#0f172a", **sans_font)
    ax.text(5.0, 6.74, "(Linux fanotify / AOSP ModernMediaScanner)", ha="center", va="center", fontsize=6.3, color="#475569", **sans_font)

    # Arrow 2 -> 3
    ax.annotate("", xy=(3.0, 5.15), xytext=(3.0, 6.40), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#334155"))
    ax.text(3.3, 5.78, "AIDL IPC / fanotify event", ha="left", va="center", fontsize=6.3, fontstyle="italic", color="#334155",
            bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="#cbd5e1", lw=0.6), **sans_font)

    # Box 3: Daemon Engine
    rect3 = patches.FancyBboxPatch((0.5, 2.60), 9.0, 2.55, facecolor=color_daemon, **kw)
    ax.add_patch(rect3)
    ax.text(5.0, 4.75, "VANISH Lifecycle Enforcement Engine", ha="center", va="center", fontsize=7.3, fontweight="bold", color="#0f172a", **sans_font)
    ax.text(5.0, 4.35, "(Linux vanishd / AOSP VanishManagerService)", ha="center", va="center", fontsize=6.2, color="#1e293b", **sans_font)
    ax.text(5.0, 3.82, "• Min-Heap Deadline Priority Queue", ha="center", va="center", fontsize=6.0, color="#334155", **sans_font)
    ax.text(5.0, 3.42, "• Ed25519 & Canonical CBOR Verification", ha="center", va="center", fontsize=6.0, color="#334155", **sans_font)
    ax.text(5.0, 3.02, "• Doze-Resilient AlarmManager / timerfd", ha="center", va="center", fontsize=6.0, color="#334155", **sans_font)

    # Arrow 3 -> 4
    ax.annotate("", xy=(3.0, 1.35), xytext=(3.0, 2.60), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#b91c1c"))
    ax.text(3.3, 1.98, "t \u2265 t_exp (Deadline Fired)", ha="left", va="center", fontsize=6.4, fontweight="bold", color="#b91c1c",
            bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="#fecaca", lw=0.6), **sans_font)

    # Box 4: Purge & Shred Engine
    rect4 = patches.FancyBboxPatch((0.5, -0.05), 9.0, 1.40, facecolor=color_purge, **kw)
    ax.add_patch(rect4)
    ax.text(5.0, 1.00, "Lifecycle Purge & Shred Engine", ha="center", va="center", fontsize=7.4, fontweight="bold", color="#991b1b", **sans_font)
    ax.text(5.0, 0.62, "• PRNG Multi-Pass Shred (Magnetic Disk)", ha="center", va="center", fontsize=6.0, color="#334155", **sans_font)
    ax.text(5.0, 0.26, "• Hardware Keystore Key Erasure (Flash)", ha="center", va="center", fontsize=6.0, color="#334155", **sans_font)

    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.10)
    fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight", pad_inches=0.10, dpi=300)
    plt.close()
    print(f"[+] Architecture figure generated: {out_path.with_suffix('.pdf')}")


def generate_fig2_latency(out_path: Path) -> None:
    """Generate publication-grade latency vs payload size curve."""
    plt.rcParams.update(SERIF_RC)
    sizes_kb = [1, 10, 100, 1024, 5120, 20480]
    pack_unenc = [0.93, 0.98, 1.12, 2.60, 10.42, 37.71]
    pack_enc = [0.90, 0.95, 1.12, 2.92, 12.18, 46.49]
    unpack = [0.65, 0.70, 0.81, 2.35, 10.85, 40.22]

    fig, ax = plt.subplots(figsize=(3.5, 2.5), dpi=300)
    ax.set_axisbelow(True)

    ax.plot(sizes_kb, pack_unenc, "o-", label="Pack (Unencrypted)", color="#1e40af", linewidth=1.6, markersize=4.8)
    ax.plot(sizes_kb, pack_enc, "s--", label="Pack (AES-256-GCM)", color="#b91c1c", linewidth=1.6, markersize=4.8)
    ax.plot(sizes_kb, unpack, "^-.", label="Unpack & Verify", color="#047857", linewidth=1.6, markersize=5.2)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Payload Size (KB)")
    ax.set_ylabel("Execution Latency (ms)")
    ax.set_title("VANISH Latency vs. Payload Size", pad=6)
    ax.grid(True, which="major", ls="-", color="#e2e8f0", alpha=0.9, lw=0.6)
    ax.grid(True, which="minor", ls=":", color="#f1f5f9", alpha=0.7, lw=0.5)
    ax.legend(frameon=True, facecolor="white", edgecolor="#cbd5e1", framealpha=0.95, loc="upper left")

    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.08)
    fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight", pad_inches=0.08, dpi=300)
    plt.close()
    print(f"[+] Latency figure generated: {out_path.with_suffix('.pdf')}")


def generate_fig3_comparative(out_path: Path) -> None:
    """Generate publication-grade comparative baseline bar chart with multi-line labels."""
    plt.rcParams.update(SERIF_RC)
    systems = ["Raw\nAES-GCM", "Standard\nTAR", "Signed\nEnvelope", "VANISH\n(.vfile)"]
    create_ms = [1.26, 0.85, 1.55, 2.92]
    extract_ms = [0.92, 0.90, 1.52, 2.35]

    x = np.arange(len(systems))
    width = 0.26
    offset = 0.16

    fig, ax = plt.subplots(figsize=(3.5, 2.5), dpi=300)
    ax.set_axisbelow(True)

    rects1 = ax.bar(x - offset, create_ms, width, label="Packaging / Creation", color="#1a365d", edgecolor="#0f172a", linewidth=0.8)
    rects2 = ax.bar(x + offset, extract_ms, width, label="Unpack & Verify", color="#065f46", edgecolor="#022c22", linewidth=0.8)

    ax.set_ylabel("Latency (ms) for 1MB Payload")
    ax.set_title("1MB Payload Baseline Comparison", pad=6)
    ax.set_xticks(x)
    ax.set_xticklabels(systems, fontweight="bold")
    ax.legend(frameon=True, facecolor="white", edgecolor="#cbd5e1", framealpha=0.95, loc="upper left")
    ax.grid(axis="y", ls="--", color="#e2e8f0", alpha=0.8, lw=0.6)
    ax.set_ylim(0, 3.8)

    for bar in rects1:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.08, f"{yval:.2f}", ha="center", va="bottom", fontsize=7.0,
                bbox=dict(boxstyle="square,pad=0.08", fc="white", ec="none", alpha=0.9))

    for bar in rects2:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.08, f"{yval:.2f}", ha="center", va="bottom", fontsize=7.0,
                bbox=dict(boxstyle="square,pad=0.08", fc="white", ec="none", alpha=0.9))

    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.08)
    fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight", pad_inches=0.08, dpi=300)
    plt.close()
    print(f"[+] Comparative figure generated: {out_path.with_suffix('.pdf')}")


def generate_fig4_breakdown(out_path: Path) -> None:
    """Generate publication-grade verification breakdown bar chart with multi-line labels."""
    plt.rcParams.update(SERIF_RC)
    stages = ["CBOR\nParse", "Ed25519\nVerify", "SHA-256\nPayload", "Clock\nCheck"]
    times = [0.37, 0.57, 0.48, 0.0002]
    display_times = [0.37, 0.57, 0.48, 0.022]
    colors = ["#1e3a8a", "#0d9488", "#be123c", "#d97706"]

    fig, ax = plt.subplots(figsize=(3.5, 2.3), dpi=300)
    ax.set_axisbelow(True)

    bars = ax.bar(stages, display_times, color=colors, width=0.45, edgecolor="#1e293b", linewidth=0.8)
    ax.set_ylabel("Latency (ms) for 1MB Container")
    ax.set_title("Verification Sub-Component Breakdown", pad=6)
    ax.grid(axis="y", ls="--", color="#e2e8f0", alpha=0.8, lw=0.6)
    ax.set_ylim(0, 0.75)
    ax.set_xticks(range(len(stages)))
    ax.set_xticklabels(stages, fontweight="bold")

    for idx, bar in enumerate(bars):
        actual = times[idx]
        label_text = f"{actual:.2f} ms" if actual >= 0.01 else "<0.01 ms"
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.02, label_text, ha="center", va="bottom", fontsize=7.0, fontweight="bold",
                bbox=dict(boxstyle="square,pad=0.08", fc="white", ec="none", alpha=0.9))

    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.08)
    fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight", pad_inches=0.08, dpi=300)
    plt.close()
    print(f"[+] Breakdown figure generated: {out_path.with_suffix('.pdf')}")


if __name__ == "__main__":
    generate_fig1_architecture(FIG_DIR / "fig_os_architecture")
    generate_fig2_latency(FIG_DIR / "fig_latency_vs_size")
    generate_fig3_comparative(FIG_DIR / "fig_comparative_baseline")
    generate_fig4_breakdown(FIG_DIR / "fig_verification_breakdown")
    print("[*] All 4 vector figures generated successfully with publication-grade IEEE styling!")
