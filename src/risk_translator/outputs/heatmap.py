"""Draw the 5 x 5 heat map: likelihood up the side, impact along the bottom.

Each cell shows how many risks fall in it, coloured by band. Each band also has
its own hatching pattern and letter, so the chart still reads when printed in
black and white.
"""

from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # draw to a file; no screen needed

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch, Rectangle  # noqa: E402

from risk_translator.models import Risk  # noqa: E402
from risk_translator.outputs.register import BAND_COLOURS  # noqa: E402
from risk_translator.scoring import BAND_ORDER, band_for  # noqa: E402

BAND_HATCHES = {"Low": "", "Medium": "..", "High": "//", "Critical": "xx"}


def count_cells(risks: list[Risk]) -> Counter[tuple[int, int]]:
    """Return the number of risks in each (likelihood, impact) cell."""
    return Counter((risk.likelihood, risk.impact) for risk in risks)


def write_heatmap(risks: list[Risk], path: Path) -> None:
    """Save the heat map as a PNG."""
    counts = count_cells(risks)
    figure, axes = plt.subplots(figsize=(7.5, 6.5))
    for likelihood in range(1, 6):
        for impact in range(1, 6):
            band = band_for(likelihood * impact)
            axes.add_patch(
                Rectangle(
                    (impact - 0.5, likelihood - 0.5),
                    1,
                    1,
                    facecolor=f"#{BAND_COLOURS[band]}",
                    edgecolor="black",
                    hatch=BAND_HATCHES[band],
                    linewidth=1,
                )
            )
            count = counts.get((likelihood, impact), 0)
            axes.text(
                impact,
                likelihood + 0.05,
                str(count) if count else "",
                ha="center",
                va="center",
                fontsize=18,
                fontweight="bold",
                bbox={"boxstyle": "round,pad=0.25", "facecolor": "white", "edgecolor": "black"}
                if count
                else None,
            )
            axes.text(
                impact + 0.42,
                likelihood - 0.42,
                band[0],
                ha="right",
                va="bottom",
                fontsize=8,
                bbox={"boxstyle": "square,pad=0.15", "facecolor": "white", "linewidth": 0},
            )

    axes.set_xlim(0.5, 5.5)
    axes.set_ylim(0.5, 5.5)
    axes.set_xticks(range(1, 6))
    axes.set_yticks(range(1, 6))
    axes.set_xlabel("Impact (1 = minor, 5 = severe)")
    axes.set_ylabel("Likelihood (1 = rare, 5 = being exploited now)")
    axes.set_title(f"Risk heat map: {len(risks)} risk(s)")
    axes.set_aspect("equal")
    legend = [
        Patch(
            facecolor=f"#{BAND_COLOURS[band]}",
            edgecolor="black",
            hatch=BAND_HATCHES[band],
            label=f"{band} ({band[0]})",
        )
        for band in BAND_ORDER
    ]
    axes.legend(handles=legend, loc="upper left", bbox_to_anchor=(1.02, 1), title="Band")
    figure.tight_layout()
    figure.savefig(path, dpi=200)
    plt.close(figure)
