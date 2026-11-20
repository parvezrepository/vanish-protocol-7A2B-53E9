"""Generates a publication-quality architecture diagram for the VANISH OS enforcement subsystem.
Outputs both PDF (vector) and PNG (high-res raster) into paper/figures/.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from pathlib import Path

def draw_architecture_diagram(out_path: Path) -> None:
    # 3.5 inches wide by 4.2 inches high (standard single column IEEEtran)
    fig, ax = plt.subplots(figsize=(3.5, 4.4), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 11)
    ax.axis("off")

    # Color Palette (IEEE standard subtle tones)
    color_app = "#e8f4f8"
    color_kernel = "#dbe9f6"
    color_daemon = "#fef2e4"
    color_purge = "#fbeae9"
    border_color = "#2c3e50"

    box_style = dict(boxstyle="round,pad=0.4", edgecolor=border_color, linewidth=1.2)

    # Layer 1: Client Applications
    rect1 = patches.FancyBboxPatch((0.5, 9.2), 9.0, 1.4, facecolor=color_app, **box_style)
    ax.add_patch(rect1)
    ax.text(5.0, 10.1, "User Space / Client Applications", ha="center", va="center", fontsize=8.5, fontweight="bold", color="#1a252f")
    ax.text(5.0, 9.6, "(Files by Google, Nautilus, Shell, Browser)", ha="center", va="center", fontsize=7.2, color="#475569")

    # Arrow 1 -> 2
    ax.annotate("", xy=(5.0, 8.2), xytext=(5.0, 9.2), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#334155"))
    ax.text(5.2, 8.7, "Storage Interception", ha="left", va="center", fontsize=6.8, fontstyle="italic", color="#334155")

    # Layer 2: Kernel / OS Ingestion
    rect2 = patches.FancyBboxPatch((0.5, 6.8), 9.0, 1.4, facecolor=color_kernel, **box_style)
    ax.add_patch(rect2)
    ax.text(5.0, 7.7, "Kernel & Storage Ingestion Layer", ha="center", va="center", fontsize=8.5, fontweight="bold", color="#1a252f")
    ax.text(5.0, 7.2, "(Linux fanotify / AOSP ModernMediaScanner)", ha="center", va="center", fontsize=7.2, color="#475569")

    # Arrow 2 -> 3
    ax.annotate("", xy=(5.0, 5.8), xytext=(5.0, 6.8), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#334155"))
    ax.text(5.2, 6.3, "AIDL IPC / fanotify event", ha="left", va="center", fontsize=6.8, fontstyle="italic", color="#334155")

    # Layer 3: VANISH Lifecycle Daemon
    rect3 = patches.FancyBboxPatch((0.5, 3.4), 9.0, 2.4, facecolor=color_daemon, **box_style)
    ax.add_patch(rect3)
    ax.text(5.0, 5.3, "VANISH Lifecycle Enforcement Engine", ha="center", va="center", fontsize=8.5, fontweight="bold", color="#1a252f")
    ax.text(5.0, 4.8, "(Linux vanishd / AOSP VanishManagerService)", ha="center", va="center", fontsize=7.5, color="#1e293b")
    ax.text(5.0, 4.3, "• Thread-Safe Min-Heap Priority Queue", ha="center", va="center", fontsize=7.0, color="#334155")
    ax.text(5.0, 3.9, "• Ed25519 / CBOR Cryptographic Verifier", ha="center", va="center", fontsize=7.0, color="#334155")
    ax.text(5.0, 3.5, "• Doze-Resilient AlarmManager / timerfd", ha="center", va="center", fontsize=7.0, color="#334155")

    # Arrow 3 -> 4
    ax.annotate("", xy=(5.0, 2.3), xytext=(5.0, 3.4), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#b91c1c"))
    ax.text(5.2, 2.85, "t >= t_exp (Deadline Fired)", ha="left", va="center", fontsize=6.8, fontweight="bold", color="#b91c1c")

    # Layer 4: Lifecycle Purge & Shred Engine
    rect4 = patches.FancyBboxPatch((0.5, 0.5), 9.0, 1.8, facecolor=color_purge, **box_style)
    ax.add_patch(rect4)
    ax.text(5.0, 1.8, "Lifecycle Purge & Shred Engine", ha="center", va="center", fontsize=8.5, fontweight="bold", color="#991b1b")
    ax.text(5.0, 1.3, "• Multi-Pass Block Overwriting (SECURE_SHRED)", ha="center", va="center", fontsize=7.0, color="#334155")
    ax.text(5.0, 0.9, "• Keystore AES-256 Key Erasure (Crypto-Shred)", ha="center", va="center", fontsize=7.0, color="#334155")
    ax.text(5.0, 0.5, "• Atomic Filesystem Inode Unlink (System UID)", ha="center", va="center", fontsize=7.0, color="#334155")

    plt.tight_layout()
    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight", dpi=300)
    plt.close()
    print(f"[+] Architecture figure generated at: {out_path.with_suffix('.pdf')}")

if __name__ == "__main__":
    out_dir = Path("paper/figures")
    out_dir.mkdir(parents=True, exist_ok=True)
    draw_architecture_diagram(out_dir / "fig_os_architecture")
