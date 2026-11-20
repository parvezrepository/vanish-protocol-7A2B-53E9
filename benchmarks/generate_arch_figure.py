"""Generates a clean, compact, collision-free architecture diagram for VANISH.
Ensures labels never collide with arrows or boxes, and borders are fully padded
to prevent any clipping at the bottom border.
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches


def draw_compact_architecture(out_path: Path) -> None:
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


if __name__ == "__main__":
    out_dir = Path("paper/figures")
    out_dir.mkdir(parents=True, exist_ok=True)
    draw_compact_architecture(out_dir / "fig_os_architecture")
