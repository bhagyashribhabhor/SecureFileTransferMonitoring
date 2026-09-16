import csv
import os
from datetime import datetime


# ==========================================================
# SECURITY REPORT GENERATOR
# ==========================================================

project_folder = os.path.abspath(".")

log_file = os.path.join(
    project_folder,
    "audit_log.csv"
)

report_file = os.path.join(
    project_folder,
    "security_report.txt"
)


# ==========================================================
# CHECK AUDIT LOG
# ==========================================================

if not os.path.exists(log_file):

    print("ERROR: audit_log.csv not found.")
    exit()


# ==========================================================
# STATISTICS
# ==========================================================

total_events = 0
sensitive_events = 0

high_risk_events = 0
medium_risk_events = 0
low_risk_events = 0

integrity_failures = 0
unauthorized_transfers = 0

file_created = 0
file_modified = 0
file_deleted = 0
file_moved = 0

users = set()


# ==========================================================
# READ AUDIT LOG
# ==========================================================

try:

    with open(
        log_file,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            # ----------------------------------------------
            # Ignore completely empty rows
            # ----------------------------------------------

            if not row:
                continue

            total_events += 1

            # ----------------------------------------------
            # USER
            # ----------------------------------------------

            user = row.get("User") or ""

            if user.strip():

                users.add(user.strip())

            # ----------------------------------------------
            # EVENT
            # ----------------------------------------------

            event = row.get("Event") or ""

            event_upper = event.upper()

            if "CREATED" in event_upper:

                file_created += 1

            elif "MODIFIED" in event_upper:

                file_modified += 1

            elif "DELETED" in event_upper:

                file_deleted += 1

            elif "MOVED" in event_upper:

                file_moved += 1

            # ----------------------------------------------
            # SENSITIVE
            # ----------------------------------------------

            sensitive = row.get(
                "Sensitive"
            ) or ""

            sensitive = sensitive.upper()

            if sensitive == "YES":

                sensitive_events += 1

            # ----------------------------------------------
            # SEVERITY
            # ----------------------------------------------

            severity = row.get(
                "Severity"
            ) or ""

            severity = severity.upper()

            if severity == "HIGH":

                high_risk_events += 1

            elif severity == "MEDIUM":

                medium_risk_events += 1

            elif severity == "LOW":

                low_risk_events += 1

            # ----------------------------------------------
            # UNAUTHORIZED TRANSFER
            # ----------------------------------------------

            if (
                "UNAUTHORIZED" in event_upper
                or "TRANSFER / COPY" in event_upper
            ):

                unauthorized_transfers += 1

            # ----------------------------------------------
            # INTEGRITY FAILURE
            # ----------------------------------------------

            risk_score = row.get(
                "Risk Score"
            ) or "0"

            try:

                risk_score = int(
                    str(risk_score).strip()
                )

            except ValueError:

                risk_score = 0

            # A high-risk modification can indicate
            # an integrity-related security event

            if (
                "MODIFIED" in event_upper
                and risk_score >= 70
            ):

                integrity_failures += 1


except Exception as error:

    print(
        "ERROR reading audit_log.csv:"
    )

    print(error)

    exit()


# ==========================================================
# SECURITY STATUS
# ==========================================================

if unauthorized_transfers > 0:

    security_status = (
        "HIGH RISK ACTIVITY DETECTED"
    )

elif high_risk_events > 0:

    security_status = (
        "HIGH RISK EVENTS DETECTED"
    )

elif medium_risk_events > 0:

    security_status = (
        "ACTIVITY REQUIRES ATTENTION"
    )

else:

    security_status = (
        "NO HIGH-RISK ACTIVITY"
    )


# ==========================================================
# GENERATE REPORT
# ==========================================================

report_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)

report = []


report.append(
    "=" * 65
)

report.append(
    "        SECURE FILE TRANSFER MONITOR"
)

report.append(
    "             SECURITY REPORT"
)

report.append(
    "=" * 65
)

report.append("")

report.append(
    "Report Generated: "
    + report_time
)

report.append(
    "Monitoring User(s): "
    + (
        ", ".join(sorted(users))
        if users
        else "N/A"
    )
)

report.append("")


# ==========================================================
# ACTIVITY SUMMARY
# ==========================================================

report.append(
    "-" * 65
)

report.append(
    "ACTIVITY SUMMARY"
)

report.append(
    "-" * 65
)

report.append(
    "Total Events              : "
    + str(total_events)
)

report.append(
    "Files Created             : "
    + str(file_created)
)

report.append(
    "Files Modified            : "
    + str(file_modified)
)

report.append(
    "Files Deleted             : "
    + str(file_deleted)
)

report.append(
    "Files Moved               : "
    + str(file_moved)
)

report.append("")


# ==========================================================
# SECURITY ANALYSIS
# ==========================================================

report.append(
    "-" * 65
)

report.append(
    "SECURITY ANALYSIS"
)

report.append(
    "-" * 65
)

report.append(
    "Sensitive File Events     : "
    + str(sensitive_events)
)

report.append(
    "High Risk Events          : "
    + str(high_risk_events)
)

report.append(
    "Medium Risk Events        : "
    + str(medium_risk_events)
)

report.append(
    "Low Risk Events           : "
    + str(low_risk_events)
)

report.append(
    "Unauthorized Transfers    : "
    + str(unauthorized_transfers)
)

report.append(
    "Integrity Alerts          : "
    + str(integrity_failures)
)

report.append("")


# ==========================================================
# SECURITY STATUS
# ==========================================================

report.append(
    "-" * 65
)

report.append(
    "SECURITY STATUS"
)

report.append(
    "-" * 65
)

report.append(
    "STATUS: "
    + security_status
)

report.append("")


report.append(
    "=" * 65
)

report.append(
    "End of Security Report"
)

report.append(
    "=" * 65
)


# ==========================================================
# SAVE REPORT
# ==========================================================

try:

    with open(
        report_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "\n".join(report)
        )

except Exception as error:

    print(
        "ERROR creating security report:"
    )

    print(error)

    exit()


# ==========================================================
# DISPLAY REPORT
# ==========================================================

print()

print(
    "\n".join(report)
)

print()

print(
    "Security report generated successfully."
)

print(
    "Report saved at:"
)

print(
    report_file
)