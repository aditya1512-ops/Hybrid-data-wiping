import subprocess
import shlex

class HardwareWipeSystem(DataWipeSystem):
    def ata_secure_erase(self, device_path):
        """Real ATA Secure Erase (requires root)"""
        try:
            # Set password
            cmd = f"hdparm --security-set-pass Eins {device_path}"
            subprocess.run(shlex.split(cmd), check=True)
            
            # Perform erase
            cmd = f"hdparm --security-erase Eins {device_path}"
            subprocess.run(shlex.split(cmd), check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"ATA Secure Erase failed: {e}")
            return False
    
    def nvme_format(self, device_path):
        """Real NVMe Format (requires root)"""
        try:
            cmd = f"nvme format {device_path} --ses=1"  # Crypto erase
            subprocess.run(shlex.split(cmd), check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"NVMe Format failed: {e}")
            return False
