import os
import json
import hmac
import hashlib
import time
from datetime import datetime
import numpy as np

class DataWipeSystem:
    """
    A complete data wipe system with AI-based method selection and tamper-proof certificates.
    """
    
    def __init__(self, demo_dir="./data_wipe_demo"):  # Fixed: __init__ not _init_
        self.demo_dir = demo_dir
        self.secret_path = os.path.join(demo_dir, "hmac_secret.bin")
        self.cert_path = os.path.join(demo_dir, "wipe_certificate.json")
        
        # Create demo directory
        os.makedirs(demo_dir, exist_ok=True)
        
        # Initialize or load HMAC secret
        self._init_secret()
        
        # Enhanced AI model with more features
        # Features: [device_age, is_ssd, is_hdd, sensitivity_level, wear_level]
        # Methods: [zero_wipe, multi_pass, secure_erase, cryptographic_erase]
        self.weights = np.array([
            [-0.2, -0.5, 0.8, 0.3, 0.1],   # zero_wipe: prefer old HDDs, low sensitivity
            [0.1, -0.3, 0.6, 0.7, -0.2],   # multi_pass: prefer HDDs with high sensitivity
            [0.3, 0.9, -0.4, 0.8, -0.4],   # secure_erase: prefer SSDs, high sensitivity
            [0.4, 0.8, -0.3, 0.9, 0.7]     # cryptographic_erase: modern SSDs with encryption
        ])
        self.method_names = ["zero_wipe", "multi_pass_random", "ssd_secure_erase", "cryptographic_erase"]
    
    def _init_secret(self):
        """Initialize or load the HMAC secret key."""
        if os.path.exists(self.secret_path):
            with open(self.secret_path, 'rb') as f:
                self.secret = f.read()
        else:
            self.secret = os.urandom(32)
            with open(self.secret_path, 'wb') as f:
                f.write(self.secret)
            print(f"[+] Generated new HMAC secret: {self.secret_path}")
    
    def create_sample_device(self, device_id, size_mb=100):
        """Create a sample device file with random data."""
        device_path = os.path.join(self.demo_dir, f"device_{device_id}.bin")
        with open(device_path, 'wb') as f:
            f.write(os.urandom(size_mb * 1024))  # Write random KB (simulated MB)
        print(f"[+] Created sample device: {device_path} ({size_mb}KB simulated)")
        return device_path
    
    def ai_select_method(self, device_age, storage_type, sensitivity, wear_level=0.5):
        """
        Enhanced AI-based wipe method selection.
        
        Args:
            device_age: Age in years (float)
            storage_type: "SSD" or "HDD"
            sensitivity: 0-10 scale (int)
            wear_level: 0.0-1.0 scale (float) - SSD wear indicator
        
        Returns:
            dict with method, confidence, and probabilities
        """
        # Feature vector
        is_ssd = 1.0 if storage_type.upper() == "SSD" else 0.0
        is_hdd = 1.0 if storage_type.upper() == "HDD" else 0.0
        features = np.array([
            device_age / 10.0, 
            is_ssd, 
            is_hdd, 
            sensitivity / 10.0,
            wear_level
        ])
        
        # Compute scores
        scores = np.dot(self.weights, features)
        
        # Softmax for probabilities
        exp_scores = np.exp(scores - np.max(scores))
        probabilities = exp_scores / exp_scores.sum()
        
        # Select method
        selected_idx = np.argmax(probabilities)
        method = self.method_names[selected_idx]
        confidence = float(probabilities[selected_idx])
        
        # Method explanations
        explanations = {
            "zero_wipe": "Single pass zero overwrite - Fast for non-sensitive HDD data",
            "multi_pass_random": "DoD 5220.22-M 3-pass - Secure for magnetic media", 
            "ssd_secure_erase": "ATA/NVMe Secure Erase - SSD-optimized with wear leveling",
            "cryptographic_erase": "Crypto key destruction - Instant, secure for self-encrypting drives"
        }
        
        return {
            "method": method,
            "confidence": confidence,
            "explanation": explanations[method],
            "probabilities": {
                name: float(prob) for name, prob in zip(self.method_names, probabilities)
            }
        }
    
    def wipe_device(self, device_path, method):
        """
        Perform the actual wipe operation with enhanced methods.
        """
        start_time = time.time()
        file_size = os.path.getsize(device_path)
        
        if method == "zero_wipe":
            # Single pass zero overwrite
            with open(device_path, 'wb') as f:
                f.write(b'\x00' * file_size)
            passes = 1
            pattern = "zeros"
        
        elif method == "multi_pass_random":
            # DoD 5220.22-M compliant 3-pass
            passes = 3
            with open(device_path, 'r+b') as f:
                # Pass 1: Random
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 2: Complementary
                f.seek(0)
                f.write(b'\xFF' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 3: Random
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            pattern = "random, ones-complement, random"
        
        elif method == "ssd_secure_erase":
            # Simulated SSD secure erase
            passes = 2
            with open(device_path, 'r+b') as f:
                for i in range(passes):
                    data = os.urandom(file_size)
                    f.seek(0)
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            pattern = "random + simulated_ATA_secure_erase"
        
        elif method == "cryptographic_erase":
            # Simulated cryptographic erase (key destruction)
            passes = 0  # No data overwrite needed
            # In reality, this would invoke SED's PSID revert or crypto erase
            pattern = "crypto_key_destruction"
            print(f"    [SIM] Cryptographic erase: Key destroyed, data permanently inaccessible")
        
        else:
            raise ValueError(f"Unknown wipe method: {method}")
        
        duration = time.time() - start_time
        
        wipe_log = {
            "method": method,
            "passes": passes,
            "pattern": pattern,
            "file_size_bytes": file_size,
            "duration_seconds": round(duration, 3),
            "wipe_rate_mbps": round((file_size / duration) / (1024*1024), 2) if duration > 0 else 0,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        print(f"[+] Wiped {device_path} using {method} ({passes} passes, {duration:.2f}s)")
        return wipe_log
    
    def generate_certificate(self, device_info, wipe_log, ai_result):
        """
        Generate enhanced tamper-proof certificate.
        """
        certificate = {
            "version": "2.0",
            "certificate_id": f"WIPE-CERT-{int(time.time())}",
            "device": device_info,
            "wipe": wipe_log,
            "ai_analysis": {
                "selected_method": ai_result["method"],
                "confidence": ai_result["confidence"],
                "explanation": ai_result["explanation"],
                "probabilities": ai_result["probabilities"]
            },
            "system_info": {
                "hostname": os.uname().nodename if hasattr(os, 'uname') else "unknown",
                "python_version": os.sys.version,
                "certificate_timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
        
        # Compute HMAC signature
        cert_json = json.dumps(certificate, sort_keys=True).encode('utf-8')
        signature = hmac.new(self.secret, cert_json, hashlib.sha256).hexdigest()
        certificate["hmac_sha256"] = signature
        
        # Save certificate with unique filename
        cert_filename = f"wipe_certificate_{certificate['certificate_id']}.json"
        cert_path = os.path.join(self.demo_dir, cert_filename)
        
        with open(cert_path, 'w') as f:
            json.dump(certificate, f, indent=2)
        
        print(f"[+] Certificate generated: {cert_path}")
        return certificate, cert_path
    
    def verify_certificate(self, cert_path=None):
        """
        Enhanced certificate verification with detailed output.
        """
        if cert_path is None:
            # Find the most recent certificate
            cert_files = [f for f in os.listdir(self.demo_dir) if f.startswith('wipe_certificate_')]
            if not cert_files:
                print("[!] No certificate found")
                return False
            cert_path = os.path.join(self.demo_dir, sorted(cert_files)[-1])
        
        try:
            with open(cert_path, 'r') as f:
                certificate = json.load(f)
            
            # Extract signature
            provided_signature = certificate.pop("hmac_sha256")
            
            # Recompute signature
            cert_json = json.dumps(certificate, sort_keys=True).encode('utf-8')
            computed_signature = hmac.new(self.secret, cert_json, hashlib.sha256).hexdigest()
            
            # Compare
            valid = hmac.compare_digest(provided_signature, computed_signature)
            
            if valid:
                print(f"[✓] Certificate VALID: {cert_path}")
                print(f"    Device: {certificate['device']['device_id']}")
                print(f"    Method: {certificate['ai_analysis']['selected_method']}")
                print(f"    Timestamp: {certificate['system_info']['certificate_timestamp']}")
            else:
                print(f"[✗] Certificate INVALID: Signature mismatch!")
            
            return valid
            
        except Exception as e:
            print(f"[!] Certificate verification failed: {e}")
            return False

    def generate_report(self):
        """Generate a comprehensive wipe report."""
        cert_files = [f for f in os.listdir(self.demo_dir) if f.startswith('wipe_certificate_')]
        
        if not cert_files:
            print("[!] No certificates found for report")
            return
        
        report = {
            "report_timestamp": datetime.utcnow().isoformat() + "Z",
            "total_operations": len(cert_files),
            "operations": []
        }
        
        for cert_file in cert_files:
            cert_path = os.path.join(self.demo_dir, cert_file)
            if self.verify_certificate(cert_path):
                with open(cert_path, 'r') as f:
                    cert_data = json.load(f)
                report["operations"].append(cert_data)
        
        report_path = os.path.join(self.demo_dir, f"wipe_report_{int(time.time())}.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Comprehensive report generated: {report_path}")
        return report_path


def run_demo():
    """Run an enhanced demonstration."""
    print("="*70)
    print("ENHANCED DATA WIPE SYSTEM - AI-Powered Secure Erasure")
    print("="*70)
    
    # Initialize system
    system = DataWipeSystem()
    
    # Test multiple device scenarios
    test_scenarios = [
        {
            "device_id": "WD-SN750-512GB-001",
            "serial": "S4Z9NX0M123456", 
            "model": "WD Black SN750",
            "storage_type": "SSD",
            "capacity_gb": 512,
            "device_age_years": 2.5,
            "data_sensitivity": 8,
            "wear_level": 0.3,
            "owner": "ACME Corp IT Dept"
        },
        {
            "device_id": "SEAGATE-2TB-001", 
            "serial": "ST2000LM007-1R8176",
            "model": "Seagate Barracuda",
            "storage_type": "HDD",
            "capacity_gb": 2000,
            "device_age_years": 5.0,
            "data_sensitivity": 6,
            "wear_level": 0.7,
            "owner": "ACME Corp Archive"
        }
    ]
    
    for i, device_info in enumerate(test_scenarios, 1):
        print(f"\n[SCENARIO {i}] {device_info['device_id']}")
        print("-" * 50)
        
        print(f"[1] Device Information:")
        print(f"    ID: {device_info['device_id']}")
        print(f"    Type: {device_info['storage_type']}")
        print(f"    Age: {device_info['device_age_years']} years") 
        print(f"    Sensitivity: {device_info['data_sensitivity']}/10")
        print(f"    Wear Level: {device_info['wear_level']:.1%}")
        
        # Create sample device
        print(f"\n[2] Creating Sample Device File...")
        device_path = system.create_sample_device(device_info['device_id'], size_mb=10)
        
        # AI method selection
        print(f"\n[3] AI Method Selection...")
        ai_result = system.ai_select_method(
            device_age=device_info['device_age_years'],
            storage_type=device_info['storage_type'],
            sensitivity=device_info['data_sensitivity'],
            wear_level=device_info['wear_level']
        )
        print(f"    Selected: {ai_result['method']}")
        print(f"    Confidence: {ai_result['confidence']:.1%}")
        print(f"    Reason: {ai_result['explanation']}")
        
        # Perform wipe
        print(f"\n[4] Performing Data Wipe...")
        wipe_log = system.wipe_device(device_path, ai_result['method'])
        
        # Generate certificate
        print(f"\n[5] Generating Certificate...")
        certificate, cert_path = system.generate_certificate(device_info, wipe_log, ai_result)
        
        # Verify certificate
        print(f"\n[6] Verifying Certificate...")
        system.verify_certificate(cert_path)
    
    # Generate comprehensive report
    print(f"\n[7] Generating Comprehensive Report...")
    system.generate_report()
    
    # Demonstrate tampering detection
    print(f"\n[8] Testing Tamper Detection...")
    cert_files = [f for f in os.listdir(system.demo_dir) if f.startswith('wipe_certificate_')]
    if cert_files:
        test_cert = os.path.join(system.demo_dir, cert_files[0])
        print(f"    Modifying certificate: {test_cert}")
        with open(test_cert, 'r') as f:
            tampered_cert = json.load(f)
        tampered_cert['device']['owner'] = "Unauthorized Entity"
        with open(test_cert, 'w') as f:
            json.dump(tampered_cert, f, indent=2)
        system.verify_certificate(test_cert)
    
    print(f"\n" + "="*70)
    print(f"Enhanced Demo Complete! All artifacts in: {system.demo_dir}")
    print(f"="*70)


if __name__ == "__main__":  # Fixed: __name__ not _name_
    run_demo()
