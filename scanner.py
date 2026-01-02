import math
import boto3
import argparse
import sys
import logging
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
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
    def __init__(self, bucket_name: str, threshold: float, threads: int = 10):
        self.bucket_name = bucket_name
        self.threshold = threshold
        self.threads = threads
        self.s3 = boto3.client('s3')

    def scan_object(self, key: str):
        """Downloads and scans a single S3 object."""
        try:
            # Skip common binary formats to reduce noise
            if any(key.endswith(ext) for ext in ['.png', '.jpg', '.pdf', '.exe', '.zip']):
                return

            response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
            content = response['Body'].read().decode('utf-8')
            
            for line_no, line in enumerate(content.splitlines(), 1):
                clean_line = line.strip()
                if not clean_line or len(clean_line) < 10:
                    continue

                entropy = calculate_shannon_entropy(clean_line)
                if entropy > self.threshold:
                    logger.warning(f"[!] POSITIVE | {key}:{line_no} | Entropy: {entropy:.2f} | Data: {clean_line[:12]}...")

        except (UnicodeDecodeError, ClientError) as e:
            # Handle binary files that weren't caught by extension check
            return
        except Exception as e:
            logger.error(f"[X] Error scanning {key}: {str(e)}")

    def run(self):
        """Initiates parallel scan using boto3 paginator."""
        paginator = self.s3.get_paginator('list_objects_v2')
        
        logger.info(f"[*] Starting scan on {self.bucket_name}")
        logger.info(f"[*] Entropy Threshold: {self.threshold}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for page in paginator.paginate(Bucket=self.bucket_name):
                if 'Contents' not in page:
                    continue
                
                keys = [obj['Key'] for obj in page['Contents']]
                executor.map(self.scan_object, keys)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Architectural Entropy Scanner for S3")
    parser.add_argument("--bucket", required=True, help="Target S3 bucket name")
    parser.add_argument("--threshold", type=float, default=4.5, help="Entropy threshold (default 4.5)")
    parser.add_argument("--threads", type=int, default=10, help="Parallel threads")
    
    args = parser.parse_args()
    
    scanner = S3Scanner(args.bucket, args.threshold, args.threads)
    scanner.run()
