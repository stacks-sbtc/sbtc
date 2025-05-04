import subprocess
import re

output_file = "deposit_txids.txt"

# Clear the output file
with open(output_file, "w") as f:
    f.write("")

for i in range(1, 51):
    print(f"[{i}/50] Running ./signers.sh demo...")

    try:
        # Run the script and get output
        result = subprocess.run(["./signers.sh", "demo"], capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr

        # Find all 'Transaction sent:' TXIDs
        matches = re.findall(r"Transaction sent:\s*([a-fA-F0-9]{64})", output)

        if len(matches) >= 2:
            txid = matches[1]  # Second occurrence
            with open(output_file, "a") as f:
                f.write(txid + "\n")
            print(f"✓ Saved TXID: {txid}")
        else:
            print("⚠  Second 'Transaction sent:' not found.")

    except subprocess.TimeoutExpired:
        print(f"⏱  Timeout on iteration {i}. Skipping.")

print(f"\n✅ Done. TXIDs saved to {output_file}")
