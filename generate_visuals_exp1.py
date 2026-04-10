"""
generate_visuals_exp1.py

Generates visualizations for Experiment 1: Ransomware Data Exfiltration.
This script reads the monte-carlo simulation results and produces:
1. Plot 1 (Trade-off): Exfiltration Recall vs. Collateral PHI Exposure.
2. Plot 2 (Cost Model): Triage Overhead vs Storage Exposure.
"""
import json
import os
import matplotlib.pyplot as plt
import numpy as np

def set_grayscale_style():
    """
    Applies a grayscale color palette and sans-serif font for publication-ready figures.
    """
    plt.rcParams["axes.prop_cycle"] = plt.cycler(
        color=["#000000", "#555555", "#888888", "#AAAAAA"]
    )
    plt.rcParams["font.family"] = "sans-serif"

def main():
    """
    Main function to read experiment 1 results and generate visualization plots.
    """
    set_grayscale_style()
    os.makedirs("figures", exist_ok=True)

    with open("results/results_exp1_advanced.json", "r") as f:
        data = json.load(f)

    base = data["baseline_N30"]
    labels = ["Bulk (A)", "Indicator (B)", "No Escalation (C)", "Proposed"]
    keys = ["Baseline_A", "Baseline_B", "Baseline_C_NoEscal", "Proposed"]

    # =========================================================================
    # --- Plot 1: Core Trade-off (Irrelevant PHI vs Recall) ---
    # =========================================================================
    irrelevant_phi_mean = np.array(
        [base[k]["irrelevant_phi_exposure"]["mean"] for k in keys]
    )
    irrelevant_phi_std = np.array(
        [base[k]["irrelevant_phi_exposure"]["std"] for k in keys]
    )

    exfil_recall_mean = np.array(
        [base[k]["exfil_record_recall"]["mean"] * 100 for k in keys]
    )
    exfil_recall_std = np.array(
        [base[k]["exfil_record_recall"]["std"] * 100 for k in keys]
    )

    fig, ax1 = plt.subplots(figsize=(10, 6))

    color_bar = "#666666"
    color_line = "#000000"

    ax1.set_xlabel("Forensic Investigation Workflow", fontsize=12, fontweight="bold")
    ax1.set_ylabel(
        "Irrelevant PHI Exposed (Count)",
        color=color_bar,
        fontsize=12,
        fontweight="bold",
    )

    x_pos = np.arange(len(labels))

    # Bar Plot for Irrelevant PHI
    ax1.set_yscale("symlog")
    bars = ax1.bar(
        x_pos,
        irrelevant_phi_mean,
        color=color_bar,
        alpha=0.8,
        yerr=irrelevant_phi_std,
        capsize=5,
        ecolor="#333333",
        label="Irrelevant PHI Exposed",
    )
    ax1.tick_params(axis="y", labelcolor="#333333")

    # Text Annotation for Zero values
    for i, v in enumerate(irrelevant_phi_mean):
        if v < 1:
            ax1.text(
                x_pos[i],
                1.5,
                "0",
                ha="center",
                va="bottom",
                fontsize=11,
                fontweight="bold",
                color="#333333",
            )

    # Line Plot for Recall
    ax2 = ax1.twinx()
    ax2.set_ylabel(
        "Exfiltrated Record Recall (%)",
        color=color_line,
        fontsize=12,
        fontweight="bold",
    )
    lines = ax2.errorbar(
        x_pos,
        exfil_recall_mean,
        yerr=exfil_recall_std,
        color=color_line,
        marker="D",
        markersize=8,
        linewidth=2,
        linestyle="--",
        capsize=5,
        label="Recall (%)",
    )
    ax2.tick_params(axis="y", labelcolor=color_line)
    ax2.set_ylim(-5, 105)

    # Note on line graph values
    for i, v in enumerate(exfil_recall_mean):
        ax2.text(
            x_pos[i],
            v + 4,
            f"{v:.1f}%",
            color=color_line,
            ha="center",
            fontweight="bold",
        )

    plt.xticks(x_pos, labels)
    plt.title(
        "Trade-off: Exfiltration Recall vs. Collateral PHI Exposure",
        fontsize=14,
        fontweight="bold",
    )
    fig.tight_layout()
    plt.savefig("figures/exp1_ablation_core.png", dpi=300)
    plt.close()

    # =========================================================================
    # --- Plot 2: Cost Model (Acquisition Size vs Triage Time) ---
    # =========================================================================
    acq_size_mean = [base[k]["acquisition_size_mb"]["mean"] for k in keys]
    acq_size_std = [base[k]["acquisition_size_mb"]["std"] for k in keys]

    time_mean = [
        base[k]["time_to_initial_triage"]["mean"] / 60 for k in keys
    ]  # in minutes
    time_std = [base[k]["time_to_initial_triage"]["std"] / 60 for k in keys]

    escalations = [base[k]["escalation_count"]["mean"] for k in keys]

    plt.figure(figsize=(9, 6))

    # Standard Grayscale styling markers
    markers = ["o", "s", "^", "D"]

    for i in range(len(keys)):
        msize = 200

        plt.scatter(
            time_mean[i],
            acq_size_mean[i],
            s=msize,
            color="#AAAAAA",
            edgecolors="black",
            linewidths=1.5,
            marker=markers[i],
            label=labels[i],
        )

        # Add error bars to scatter points
        plt.errorbar(
            time_mean[i],
            acq_size_mean[i],
            xerr=time_std[i],
            yerr=acq_size_std[i],
            ecolor="black",
            capsize=4,
            fmt="none",
            zorder=-1,
        )

        # Annotate
        plt.text(
            time_mean[i] * 1.05 + 5,
            acq_size_mean[i] * 1.05,
            labels[i],
            fontsize=11,
            verticalalignment="center",
        )

    plt.yscale("log")
    plt.xscale("log")
    plt.xlabel("Time to Initial Triage (Minutes, Log Scale)", fontweight="bold")
    plt.ylabel("Acquisition Size (MB, Log Scale)", fontweight="bold")
    plt.title(
        "Cost of Investigation: Triage Overhead vs Storage Exposure", fontweight="bold"
    )

    plt.grid(True, linestyle="--", color="#CCCCCC", alpha=0.7)
    plt.tight_layout()
    plt.savefig("figures/exp1_cost_model.png", dpi=300)
    plt.close()

    print("Exp1 visuals generated successfully in figures/")


if __name__ == "__main__":
    main()
