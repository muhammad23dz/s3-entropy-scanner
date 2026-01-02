import pytest
import boto3
from moto import mock_aws
from scanner import S3Scanner, calculate_shannon_entropy

def test_entropy_calculation():
    # Known high entropy (random string)
    assert calculate_shannon_entropy("AQw923kf0239slk2309slk23") > 4.0
    # Known low entropy (repeating string)
    assert calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa") < 1.0

@mock_aws
def test_scanner_findings():
    bucket_name = "test-bucket"
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=bucket_name)
    
    # Upload a "clean" file and a "sensitive" file
    s3.put_object(Bucket=bucket_name, Key="clean.txt", Body="This is a normal text file.")
    s3.put_object(Bucket=bucket_name, Key="secret.txt", Body="export AWS_SECRET_ACCESS_KEY=AQw923kf0239slk2309slk23")
    
    scanner = S3Scanner(bucket_name, threshold=4.0)
    scanner.run()
    
    assert len(scanner.results) >= 1
    assert scanner.results[0]['key'] == "secret.txt"

@mock_aws
def test_binary_skipping():
    bucket_name = "test-bucket"
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=bucket_name)
    
    s3.put_object(Bucket=bucket_name, Key="image.png", Body=b"\x89PNG\r\n\x1a\n")
    
    scanner = S3Scanner(bucket_name, threshold=1.0)
    scanner.run()
    
    # Should skip .png extension
    assert len(scanner.results) == 0
