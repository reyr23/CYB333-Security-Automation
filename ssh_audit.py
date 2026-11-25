import json

# Open the saved SSH audit results
with open('ssh_audit_results.json', 'r') as file:
    audit_data = json.load(file)

# Display basic information about the SSH server
print("SSH Audit Results")
print("Server", audit_data["banner"]["software"])
print("Protocol", audit_data["banner"]["protocol"])

# Count the encryption and key exchange algorithms
print("Encryption algorithms:", len(audit_data["enc"]))
print("Key exchange algorithms:", len(audit_data["kex"]))
print("First encryption entry:", audit_data["enc"][0])

# Check encryption algorithms for security warnings
for algorithm in audit_data["enc"]:
    name = algorithm["algorithm"]
    notes = algorithm.get("notes", {})

    if notes.get("warn") or notes.get("fail"):
        print("Security finding:", name, notes)

# check key exchange algorithms for security warnings
for algorithm in audit_data["kex"]:
    name = algorithm["algorithm"]
    notes = algorithm.get("notes", {})

    if notes.get("warn") or notes.get("fail"):
        print("Key exchange finding:", name, notes)

# Save security findings to a text report
with open("ssh_security_report.txt", "w") as report:
    report.write("SSH Security Audit Report\n")
    report.write("=========================\n")
    report.write(f"Server: {audit_data['banner']['software']}\n") 
    report.write(f"Protocol: {audit_data['banner']['protocol']}\n\n")

    report.write("Key Exchange Security Findings:\n")
    for algorithm in audit_data["kex"]:
        notes = algorithm.get("notes", {})

        if notes.get("warn") or notes.get("fail"):
            report.write(f"\nAlgorithm: {algorithm['algorithm']}\n")

            for warning in notes.get("warn", []) + notes.get("fail", []):
                report.write(f"Finding: {warning}\n")
            