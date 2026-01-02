import math
import boto3
import argparse
import sys
import logging
import json
import csv
from datetime import datetime
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon Entropy of a string."""
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    # Character frequency map
    counts = {char: data.count(char) for char in set(data)}
    
    for char in counts:
        p_x = counts[char] / length
        entropy -= p_x * math.log2(p_x)
        
    return entropy

class S3Scanner:
    def __init__(self, bucket_name: str, threshold: float, threads: int = 10, export_format: str = None):
        self.bucket_name = bucket_name
        self.threshold = threshold
        self.threads = threads
        self.export_format = export_format
        self.s3 = boto3.client('s3')
        self.results = []

    def scan_object(self, key: str):
        """Downloads and scans a single S3 object."""
        findings = []
        try:
            # Skip common binary formats to reduce noise
            if any(key.lower().endswith(ext) for ext in ['.png', '.jpg', '.pdf', '.exe', '.zip', '.gz', '.tar']):
                return findings

            response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
            # Read first 1MB to avoid memory blow-up on huge log files
            body = response['Body'].read(1024 * 1024)
            content = body.decode('utf-8', errors='ignore')
            
            for line_no, line in enumerate(content.splitlines(), 1):
                clean_line = line.strip()
                if not clean_line or len(clean_line) < 10:
                    continue

                entropy = calculate_shannon_entropy(clean_line)
                if entropy > self.threshold:
                    finding = {
                        "key": key,
                        "line": line_no,
                        "entropy": round(entropy, 2),
                        "data_preview": clean_line[:15] + "...",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    findings.append(finding)
                    logger.warning(f"[!] POSITIVE | {key}:{line_no} | Entropy: {entropy:.2f}")

        except Exception as e:
            logger.debug(f"[X] Error scanning {key}: {str(e)}")
        
        return findings

    def export_results(self):
        if not self.export_format or not self.results:
            return

        filename = f"findings_{self.bucket_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if self.export_format == 'json':
            with open(f"{filename}.json", "w") as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"[*] Exported {len(self.results)} findings to {filename}.json")
        
        elif self.export_format == 'csv':
            keys = self.results[0].keys()
            with open(f"{filename}.csv", "w", newline='') as f:
                dict_writer = csv.DictWriter(f, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(self.results)
            logger.info(f"[*] Exported {len(self.results)} findings to {filename}.csv")

    def run(self):
        """Initiates parallel scan using boto3 paginator."""
        paginator = self.s3.get_paginator('list_objects_v2')
        
        logger.info(f"[*] Starting scan on {self.bucket_name}")
        logger.info(f"[*] Entropy Threshold: {self.threshold}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for page in paginator.paginate(Bucket=self.bucket_name):
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    futures.append(executor.submit(self.scan_object, obj['Key']))
            
            for future in as_completed(futures):
                self.results.extend(future.result())

        self.export_results()
        logger.info(f"[*] Scan complete. Total Findings: {len(self.results)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Architectural Entropy Scanner for S3")
    parser.add_argument("--bucket", required=True, help="Target S3 bucket name")
    parser.add_argument("--threshold", type=float, default=4.5, help="Entropy threshold (default 4.5)")
    parser.add_argument("--threads", type=int, default=10, help="Parallel threads")
    parser.add_argument("--export", choices=['json', 'csv'], help="Export format")
    
    args = parser.parse_args()
    
    try:
        scanner = S3Scanner(args.bucket, args.threshold, args.threads, args.export)
        scanner.run()
    except Exception as e:
        logger.error(f"[FATAL] Scanner failed: {str(e)}")
        sys.exit(1)
