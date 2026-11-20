"""Generates a clean, compact, collision-free architecture diagram for VANISH.
Ensures labels never collide with arrows or boxes, and height is compact (3.4 in)
to maintain the strict 6-page IEEE paper budget.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from pathlib import Path

def draw_compact_architecture(out_path: Path) -> None:
    # 3.4 inches wide by 3.5 inches high (compact for IEEE single column)
    fig, ax = plt.subplots(figsize=(3.4, 3.5), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")

    color_app = "#f0f7fa"
    color_kernel = "#e8f1f8"
    color_daemon = "#fef6ed"
    color_purge = "#fdf0ed"
    border = "#334155"

    box_kw = dict(boxstyle="round,pad=0.25", edgecolor=border, linewidth=1.0)

    # Box 1: Client Apps (y: 8.4 to 9.6)
    rect1 = patches.FancyBboxPatch((0.5, 8.4), 9.0, 1.2, facecolor=color_app, **box_kw)
    ax.add_patch(rect1)
    ax.text(5.0, 9.15, "User Space / Client Applications", ha="center", va="center", fontsize=8.0, fontweight="bold", color="#0f172a")
    ax.text(5.0, 8.65, "(Files by Google, Nautilus, Shell, Browser)", ha="center", va="center", fontsize=6.8, color="#475569")

    # Arrow 1 -> 2 (from y=8.4 to y=7.4)
    ax.annotate("", xy=(3.0, 7.4), xytext=(3.0, 8.4), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#334155"))
    ax.text(3.4, 7.9, "Storage Interception", ha="left", va="center", fontsize=6.5, fontstyle="italic", color="#334155",
            bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none", alpha=0.9))

    # Box 2: Kernel Ingestion (y: 6.2 to 7.4)
    rect2 = patches.FancyBboxPatch((0.5, 6.2), 9.0, 1.2, facecolor=color_kernel, **box_kw)
    ax.add_patch(rect2)
    ax.text(5.0, 6.95, "Kernel & Storage Ingestion Layer", ha="center", va="center", fontsize=8.0, fontweight="bold", color="#0f172a")
    ax.text(5.0, 6.45, "(Linux fanotify / AOSP ModernMediaScanner)", ha="center", va="center", fontsize=6.8, color="#475569")

    # Arrow 2 -> 3 (from y=6.2 to y=5.0)
    ax.annotate("", xy=(3.0, 5.0), xytext=(3.0, 6.2), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#334155"))
    ax.text(3.4, 5.6, "AIDL IPC / fanotify event", ha="left", va="center", fontsize=6.5, fontstyle="italic", color="#334155",
            bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none", alpha=0.9))

    # Box 3: Daemon (y: 2.8 to 5.0)
    rect3 = patches.FancyBboxPatch((0.5, 2.8), 9.0, 2.2, facecolor=color_daemon, **box_kw)
    ax.add_patch(rect3)
    ax.text(5.0, 4.65, "VANISH Lifecycle Enforcement Engine", ha="center", va="center", fontsize=8.0, fontweight="bold", color="#0f172a")
    ax.text(5.0, 4.25, "(Linux vanishd / AOSP VanishManagerService)", ha="center", va="center", fontsize=7.0, color="#1e293b")
    ax.text(5.0, 3.75, "• Thread-Safe Min-Heap Priority Queue", ha="center", va="center", fontsize=6.6, color="#334155")
    ax.text(5.0, 3.35, "• Ed25519 & Canonical CBOR Verification", ha="center", va="center", fontsize=6.6, color="#334155")
    ax.text(5.0, 2.95, "• Doze-Resilient AlarmManager / timerfd", ha="center", va="center", fontsize=6.6, color="#334155")

    # Arrow 3 -> 4 (from y=2.8 to y=1.6)
    ax.annotate("", xy=(3.0, 1.6), xytext=(3.0, 2.8), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#b91c1c"))
    ax.text(3.4, 2.2, "t >= t_exp (Deadline Fired)", ha="left", va="center", fontsize=6.5, fontweight="bold", color="#b91c1c",
            bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none", alpha=0.9))

    # Box 4: Purge Engine (y: 0.2 to 1.6)
    rect4 = patches.FancyBboxPatch((0.5, 0.2), 9.0, 1.4, facecolor=color_purge, **box_kw)
    ax.add_patch(rect4)
    ax.text(5.0, 1.25, "Lifecycle Purge & Shred Engine", ha="center", va="center", fontsize=8.0, fontweight="bold", color="#991b1b")
    ax.text(5.0, 0.85, "• Multi-Pass Overwriting (SECURE_SHRED)", ha="center", va="center", fontsize=6.6, color="#334155")
    ax.text(5.0, 0.50, "• Keystore AES Key Erasure & Inode Unlink", ha="center", va="center", fontsize=6.6, color="#334155")

    plt.tight_layout()
    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight", dpi=300)
    plt.close()
    print(f"[+] Clean, compact architecture figure generated at: {out_path.with_suffix('.pdf')}")

if __name__ == "__main__":
    out_dir = Path("paper/figures")
    out_dir.mkdir(parents=True, exist_ok=True)
    draw_compact_architecture(out_dir / "fig_os_architecture")
