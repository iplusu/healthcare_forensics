import subprocess
import sys
import os

def run_script(script_name):
    print(f"[{script_name}] Started...")
    try:
        subprocess.run([sys.executable, script_name], check=True)
        print(f"[{script_name}] Finished successfully.\n")
    except subprocess.CalledProcessError as e:
        print(f"[{script_name}] Failed with error code {e.returncode}.\n")

if __name__ == "__main__":
    print("==========================================")
    print(" Running FSI DI Experiments & Visuals ")
    print("==========================================\n")
    
    # Run simulation experiments
    # Will generate output in 'results/'
    run_script("exp1_ransomware.py")
    run_script("exp2_insider.py")
    run_script("exp3_integrity.py")
    
    # Run visualization generation
    # Will generate plots in 'figures/'
    run_script("generate_visuals_exp1.py")
    run_script("generate_visuals_exp2.py")
    run_script("generate_visuals_exp3.py")
    
    print("All tasks completed. Check the 'results/' and 'figures/' directories.")
