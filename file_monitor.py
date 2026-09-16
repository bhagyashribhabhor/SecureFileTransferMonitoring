from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import time
import os
import hashlib
import csv
import getpass
from datetime import datetime


class FileMonitor(FileSystemEventHandler):

    def __init__(self):
        super().__init__()

        # ==================================================
        # PROJECT FOLDER
        # ==================================================

        self.project_folder = os.path.abspath(".")

        # ==================================================
        # SENSITIVE FILE KEYWORDS
        # ==================================================

        self.sensitive_keywords = {
            "confidential",
            "password",
            "secret",
            "credentials",
            "private"
        }

        # Sensitive folder
        self.sensitive_folder = "sensitive_files"

        # ==================================================
        # SUSPICIOUS DESTINATION FOLDERS
        # ==================================================

        self.suspicious_destinations = {
            "usb",
            "external",
            "cloud",
            "network",
            "shared",
            "downloads",
            "transfer"
        }

        # ==================================================
        # SHA-256 HASH BASELINE
        # ==================================================

        self.file_hashes = {}

        # Newly created files
        self.recently_created_files = {}

        # Time allowed for initial file saving
        self.new_file_grace_period = 30

        # ==================================================
        # EVENT COOLDOWN
        # ==================================================

        self.event_times = {}
        self.cooldown_seconds = 1.5

        # ==================================================
        # AUDIT LOG
        # ==================================================

        self.log_file = os.path.join(
            self.project_folder,
            "audit_log.csv"
        )

        self.create_log_file()

        # Create hash baseline for existing files
        self.create_hash_baseline()

    # ======================================================
    # IGNORE AUDIT LOG FILES
    # ======================================================

    def is_log_file(self, file_path):

        file_name = os.path.basename(
            file_path
        ).lower()

        return file_name in {
            "audit_log.csv",
            "audit_log.txt",
            "audit_log_backup.csv"
        }

    # ======================================================
    # EVENT COOLDOWN
    # ======================================================

    def should_process_event(
        self,
        event_type,
        file_path
    ):

        key = (
            event_type,
            os.path.abspath(file_path)
        )

        current_time = time.monotonic()

        last_time = self.event_times.get(
            key,
            0
        )

        if current_time - last_time < self.cooldown_seconds:
            return False

        self.event_times[key] = current_time

        return True

    # ======================================================
    # CREATE AUDIT LOG
    # ======================================================

    def create_log_file(self):

        headers = [
            "Timestamp",
            "User",
            "Event",
            "Source",
            "Destination",
            "Sensitive",
            "SHA256",
            "Risk Score",
            "Severity"
        ]

        if not os.path.exists(self.log_file):

            with open(
                self.log_file,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)
                writer.writerow(headers)

        elif os.path.getsize(self.log_file) == 0:

            with open(
                self.log_file,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)
                writer.writerow(headers)

    # ======================================================
    # CREATE HASH BASELINE
    # ======================================================

    def create_hash_baseline(self):

        for root, dirs, files in os.walk(
            self.project_folder
        ):

            # Ignore Python cache
            dirs[:] = [
                directory
                for directory in dirs
                if directory != "__pycache__"
            ]

            for file_name in files:

                file_path = os.path.join(
                    root,
                    file_name
                )

                if self.is_log_file(file_path):
                    continue

                file_hash = self.calculate_hash(
                    file_path
                )

                if file_hash:

                    self.file_hashes[
                        os.path.abspath(file_path)
                    ] = file_hash

    # ======================================================
    # CHECK SENSITIVE FILE
    # ======================================================

    def is_sensitive(self, file_path):

        file_name = os.path.basename(
            file_path
        ).lower()

        full_path = os.path.abspath(
            file_path
        ).lower()

        # Check filename keywords
        for keyword in self.sensitive_keywords:

            if keyword in file_name:
                return True

        # Check sensitive folder
        path_parts = full_path.split(
            os.sep
        )

        if self.sensitive_folder.lower() in path_parts:
            return True

        return False

    # ======================================================
    # CHECK SUSPICIOUS DESTINATION
    # ======================================================

    def is_suspicious_destination(
        self,
        file_path
    ):

        try:

            project = os.path.abspath(
                self.project_folder
            )

            target = os.path.abspath(
                file_path
            )

            # Check if outside project folder
            try:

                common_path = os.path.commonpath(
                    [
                        project,
                        target
                    ]
                )

                if common_path != project:
                    return True

            except ValueError:

                return True

            # Relative path
            relative_path = os.path.relpath(
                target,
                project
            ).lower()

            parts = relative_path.split(
                os.sep
            )

            # Check only folders, not filename
            for folder in parts[:-1]:

                if folder in self.suspicious_destinations:
                    return True

            return False

        except Exception:

            return False

    # ======================================================
    # CALCULATE SHA-256
    # ======================================================

    def calculate_hash(self, file_path):

        sha256 = hashlib.sha256()

        try:

            with open(
                file_path,
                "rb"
            ) as file:

                while True:

                    data = file.read(4096)

                    if not data:
                        break

                    sha256.update(data)

            return sha256.hexdigest()

        except (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError
        ):

            return None

    # ======================================================
    # CALCULATE RISK
    # ======================================================

    def calculate_risk(
        self,
        sensitive=False,
        suspicious_destination=False,
        integrity_failure=False,
        event="NORMAL"
    ):

        score = 0

        # Sensitive file
        if sensitive:
            score += 40

        # Suspicious destination
        if suspicious_destination:
            score += 40

        # Integrity failure
        if integrity_failure:
            score += 30

        # Deleted file
        if event == "FILE DELETED":
            score += 10

        # Moved file
        if event == "FILE MOVED":
            score += 10

        if score > 100:
            score = 100

        # Severity
        if score >= 70:
            severity = "HIGH"

        elif score >= 40:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        return score, severity

    # ======================================================
    # WRITE AUDIT LOG
    # ======================================================

    def write_audit_log(
        self,
        event,
        source,
        destination="",
        sensitive=False,
        file_hash="",
        risk_score=0,
        severity="LOW"
    ):

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        user = getpass.getuser()

        try:

            with open(
                self.log_file,
                "a",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow([
                    timestamp,
                    user,
                    event,
                    source,
                    destination,
                    "YES" if sensitive else "NO",
                    file_hash,
                    risk_score,
                    severity
                ])

        except PermissionError:

            print(
                "WARNING: Unable to write audit log."
            )

    # ======================================================
    # DISPLAY SECURITY RESULT
    # ======================================================

    def print_security_result(
        self,
        event,
        source,
        destination="",
        sensitive=False,
        suspicious=False,
        file_hash=None,
        risk_score=0,
        severity="LOW"
    ):

        print()
        print("=" * 65)

        print(
            "       SECURE FILE TRANSFER MONITOR"
        )

        print("=" * 65)

        print(
            "Event:",
            event
        )

        print(
            "Source:",
            source
        )

        if destination:

            print(
                "Destination:",
                destination
            )

        print(
            "User:",
            getpass.getuser()
        )

        print(
            "Sensitive:",
            "YES" if sensitive else "NO"
        )

        print(
            "Suspicious Destination:",
            "YES" if suspicious else "NO"
        )

        if file_hash:

            print(
                "SHA-256:",
                file_hash
            )

        print(
            "Risk Score:",
            str(risk_score) + "/100"
        )

        print(
            "Severity:",
            severity
        )

        # ==================================================
        # ALERTS
        # ==================================================

        if sensitive and suspicious:

            print()
            print(
                "🚨 UNAUTHORIZED TRANSFER ALERT!"
            )

            print(
                "Sensitive file detected in suspicious destination."
            )

        elif event == "INTEGRITY FAILURE":

            print()
            print(
                "🚨 INTEGRITY FAILURE DETECTED!"
            )

            print(
                "File content has changed from the stored SHA-256 baseline."
            )

        elif severity == "HIGH":

            print()
            print(
                "🚨 SECURITY ALERT!"
            )

            print(
                "Possible suspicious activity detected."
            )

        elif severity == "MEDIUM":

            print()
            print(
                "⚠️ WARNING!"
            )

            print(
                "Activity requires attention."
            )

        else:

            print()
            print(
                "✔ Normal activity."
            )

        print("=" * 65)

    # ======================================================
    # FILE CREATED
    # ======================================================

    def on_created(self, event):

        if event.is_directory:
            return

        if self.is_log_file(event.src_path):
            return

        if not self.should_process_event(
            "CREATED",
            event.src_path
        ):
            return

        file_path = os.path.abspath(
            event.src_path
        )

        # Calculate hash
        file_hash = self.calculate_hash(
            event.src_path
        )

        # Security checks
        sensitive = self.is_sensitive(
            event.src_path
        )

        suspicious = self.is_suspicious_destination(
            event.src_path
        )

        # Store initial hash
        if file_hash:

            self.file_hashes[
                file_path
            ] = file_hash

        # Mark as newly created
        # Store creation time
        self.recently_created_files[
            file_path
        ] = time.monotonic()

        # Event name
        if sensitive and suspicious:

            event_name = (
                "FILE TRANSFER / COPY DETECTED"
            )

        else:

            event_name = "FILE CREATED"

        # Risk
        risk_score, severity = self.calculate_risk(
            sensitive=sensitive,
            suspicious_destination=suspicious,
            event="FILE CREATED"
        )

        # Display
        self.print_security_result(
            event_name,
            event.src_path,
            sensitive=sensitive,
            suspicious=suspicious,
            file_hash=file_hash,
            risk_score=risk_score,
            severity=severity
        )

        # Log
        self.write_audit_log(
            event_name,
            event.src_path,
            sensitive=sensitive,
            file_hash=file_hash or "",
            risk_score=risk_score,
            severity=severity
        )

    # ======================================================
    # FILE MODIFIED
    # ======================================================

    def on_modified(self, event):

        if event.is_directory:
            return

        if self.is_log_file(event.src_path):
            return

        if not self.should_process_event(
            "MODIFIED",
            event.src_path
        ):
            return

        file_path = os.path.abspath(
            event.src_path
        )

        # Calculate current hash
        new_hash = self.calculate_hash(
            event.src_path
        )

        if not new_hash:
            return

        # ==================================================
        # NEW FILE INITIAL SAVE
        # ==================================================

        if file_path in self.recently_created_files:

            created_time = (
                self.recently_created_files[
                    file_path
                ]
            )

            elapsed_time = (
                time.monotonic()
                - created_time
            )

            # During initial save period,
            # update baseline without alert.
            if elapsed_time < self.new_file_grace_period:

                self.file_hashes[
                    file_path
                ] = new_hash

                return

            # Initial save period finished
            self.recently_created_files.pop(
                file_path,
                None
            )

        # ==================================================
        # GET OLD HASH
        # ==================================================

        old_hash = self.file_hashes.get(
            file_path
        )

        # ==================================================
        # CHECK INTEGRITY
        # ==================================================

        integrity_failure = False

        if old_hash and old_hash != new_hash:

            integrity_failure = True

        # ==================================================
        # SECURITY CHECKS
        # ==================================================

        sensitive = self.is_sensitive(
            event.src_path
        )

        suspicious = self.is_suspicious_destination(
            event.src_path
        )

        # ==================================================
        # INTEGRITY FAILURE
        # ==================================================

        if integrity_failure:

            risk_score, severity = self.calculate_risk(
                sensitive=sensitive,
                suspicious_destination=suspicious,
                integrity_failure=True,
                event="NORMAL"
            )

            self.print_security_result(
                "INTEGRITY FAILURE",
                event.src_path,
                sensitive=sensitive,
                suspicious=suspicious,
                file_hash=new_hash,
                risk_score=risk_score,
                severity=severity
            )

            self.write_audit_log(
                "INTEGRITY FAILURE",
                event.src_path,
                sensitive=sensitive,
                file_hash=new_hash,
                risk_score=risk_score,
                severity=severity
            )

        # ==================================================
        # NORMAL MODIFICATION
        # ==================================================

        else:

            risk_score, severity = self.calculate_risk(
                sensitive=sensitive,
                suspicious_destination=suspicious,
                event="FILE MODIFIED"
            )

            self.write_audit_log(
                "FILE MODIFIED",
                event.src_path,
                sensitive=sensitive,
                file_hash=new_hash,
                risk_score=risk_score,
                severity=severity
            )

            print(
                "FILE MODIFIED:",
                event.src_path
            )

        # Update baseline
        self.file_hashes[
            file_path
        ] = new_hash

    # ======================================================
    # FILE DELETED
    # ======================================================

    def on_deleted(self, event):

        if event.is_directory:
            return

        if self.is_log_file(event.src_path):
            return

        if not self.should_process_event(
            "DELETED",
            event.src_path
        ):
            return

        file_path = os.path.abspath(
            event.src_path
        )

        sensitive = self.is_sensitive(
            event.src_path
        )

        # Remove hash
        self.file_hashes.pop(
            file_path,
            None
        )

        # Remove new-file information
        self.recently_created_files.pop(
            file_path,
            None
        )

        # Risk
        risk_score, severity = self.calculate_risk(
            sensitive=sensitive,
            event="FILE DELETED"
        )

        # Display
        self.print_security_result(
            "FILE DELETED",
            event.src_path,
            sensitive=sensitive,
            suspicious=False,
            risk_score=risk_score,
            severity=severity
        )

        # Log
        self.write_audit_log(
            "FILE DELETED",
            event.src_path,
            sensitive=sensitive,
            risk_score=risk_score,
            severity=severity
        )

    # ======================================================
    # FILE MOVED
    # ======================================================

    def on_moved(self, event):

        if event.is_directory:
            return

        if self.is_log_file(event.src_path):
            return

        if self.is_log_file(event.dest_path):
            return

        if not self.should_process_event(
            "MOVED",
            event.dest_path
        ):
            return

        source = event.src_path
        destination = event.dest_path

        # Source sensitivity
        sensitive = self.is_sensitive(
            source
        )

        # Destination check
        suspicious = self.is_suspicious_destination(
            destination
        )

        # Calculate hash
        file_hash = self.calculate_hash(
            destination
        )

        # Risk
        risk_score, severity = self.calculate_risk(
            sensitive=sensitive,
            suspicious_destination=suspicious,
            event="FILE MOVED"
        )

        # Event name
        if sensitive and suspicious:

            event_name = (
                "UNAUTHORIZED FILE TRANSFER"
            )

        else:

            event_name = "FILE MOVED"

        # Display
        self.print_security_result(
            event_name,
            source,
            destination,
            sensitive=sensitive,
            suspicious=suspicious,
            file_hash=file_hash,
            risk_score=risk_score,
            severity=severity
        )

        # Log
        self.write_audit_log(
            event_name,
            source,
            destination,
            sensitive=sensitive,
            file_hash=file_hash or "",
            risk_score=risk_score,
            severity=severity
        )

        # Update hash location
        source_path = os.path.abspath(
            source
        )

        destination_path = os.path.abspath(
            destination
        )

        old_hash = self.file_hashes.pop(
            source_path,
            None
        )

        if file_hash:

            self.file_hashes[
                destination_path
            ] = file_hash

        elif old_hash:

            self.file_hashes[
                destination_path
            ] = old_hash

        # Remove new-file information
        self.recently_created_files.pop(
            source_path,
            None
        )


# ==========================================================
# START MONITORING
# ==========================================================

folder_to_monitor = "."

event_handler = FileMonitor()

observer = Observer()

observer.schedule(
    event_handler,
    folder_to_monitor,
    recursive=True
)

observer.start()


# ==========================================================
# STARTUP INFORMATION
# ==========================================================

print()

print("=" * 65)

print(
    "🔐 SECURE FILE TRANSFER MONITOR STARTED"
)

print("=" * 65)

print(
    "Monitoring folder:",
    os.path.abspath(
        folder_to_monitor
    )
)

print(
    "User:",
    getpass.getuser()
)

print()

print(
    "Sensitive keywords:"
)

for keyword in sorted(
    event_handler.sensitive_keywords
):

    print(
        "  •",
        keyword
    )

print()

print(
    "Suspicious destinations:"
)

for destination in sorted(
    event_handler.suspicious_destinations
):

    print(
        "  •",
        destination
    )

print("=" * 65)

print(
    "Monitoring file activity..."
)

print(
    "Press Ctrl+C to stop."
)

print("=" * 65)


# ==========================================================
# KEEP MONITOR RUNNING
# ==========================================================

try:

    while True:

        time.sleep(1)

except KeyboardInterrupt:

    print()
    print(
        "Stopping monitor..."
    )

    observer.stop()

observer.join()

print(
    "Monitoring stopped."
)