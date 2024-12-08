import re
import csv
from collections import Counter
import streamlit as st
from io import StringIO


def count_requests_per_ip(log_file_path):
    """
    Analyzes the log file to count requests per IP address.
    
    Args:
        log_file_path (str): Path to the log file.
    Returns:
        log_data (list): List of log file lines.
        sorted_ip_count (list): List of tuples (IP Address, Request Count).
    """
    try:
        with open(log_file_path, 'r') as file:
            log_data = file.readlines()
        
        # Regular expression to extract IP addresses
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ip_addresses = [ip_pattern.search(line).group() for line in log_data if ip_pattern.search(line)]
        
        # Count the occurrences of each IP address
        ip_count = Counter(ip_addresses)
        
        # Sort the IP addresses by request count in descending order
        sorted_ip_count = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
        
        # Display results
        print(f"{'IP Address':<20} {'Request Count'}")
        print("-" * 35)
        for ip, count in sorted_ip_count:
            print(f"{ip:<20} {count}")
        
        return log_data, sorted_ip_count

    except FileNotFoundError:
        print("Error: Log file not found.")
        return None, None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None, None


def most_frequent_endpoint(log_data):
    """
    Identifies the most frequently accessed endpoint from the log data.
    
    Args:
        log_data (list): List of log entries.
    Returns:
        tuple: (Most Frequent Endpoint, Access Count)
    """
    try:
        # Regular expression to extract endpoints
        endpoint_pattern = re.compile(r'\"(?:GET|POST) (\S+) HTTP')
        endpoints = [endpoint_pattern.search(line).group(1) for line in log_data if endpoint_pattern.search(line)]
        
        # Count the occurrences of each endpoint
        endpoint_count = Counter(endpoints)
        
        # Identify the most frequently accessed endpoint
        most_frequent = max(endpoint_count.items(), key=lambda x: x[1])
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_frequent[0]} (Accessed {most_frequent[1]} times)")
        
        return most_frequent

    except Exception as e:
        print(f"An error occurred while analyzing endpoints: {e}")
        return None, None


def detect_suspicious_activity(log_data, threshold=10):
    """
    Detects suspicious activity by identifying IPs with excessive failed login attempts.
    
    Args:
        log_data (list): List of log entries.
        threshold (int): Threshold for flagging suspicious IPs.
    Returns:
        list: List of tuples (IP Address, Failed Login Count).
    """
    try:
        # Regular expression to extract failed login attempts
        failed_login_pattern = re.compile(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b).*401|Invalid credentials')
        
        # Extract IPs with failed login attempts
        failed_attempts = [failed_login_pattern.search(line).group(1) for line in log_data if failed_login_pattern.search(line)]
        
        # Count the occurrences of failed attempts per IP
        failed_attempt_count = Counter(failed_attempts)
        
        # Filter IPs exceeding the threshold
        suspicious_ips = [(ip, count) for ip, count in failed_attempt_count.items() if count > threshold]
        
        # Display results
        print("\nSuspicious Activity Detected:")
        if suspicious_ips:
            print(f"{'IP Address':<20} {'Failed Login Attempts'}")
            print("-" * 40)
            for ip, count in suspicious_ips:
                print(f"{ip:<20} {count}")
        else:
            print("No suspicious activity detected.")
        
        return suspicious_ips

    except Exception as e:
        print(f"An error occurred while detecting suspicious activity: {e}")
        return []


def save_results_to_csv(ip_data, endpoint_data, suspicious_data):
    """
    Saves the results to a CSV file.

    Args:
        ip_data (list): List of tuples (IP Address, Request Count).
        endpoint_data (tuple): (Most Frequent Endpoint, Access Count).
        suspicious_data (list): List of tuples (IP Address, Failed Login Count).
    """
    try:
        with open('log_analysis_results.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write IP Request Counts
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            writer.writerows(ip_data)
            writer.writerow([])

            # Write Most Accessed Endpoint
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(endpoint_data)
            writer.writerow([])

            # Write Suspicious Activity
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            writer.writerows(suspicious_data)
        
        print("\nResults saved to 'log_analysis_results.csv'.")

    except Exception as e:
        print(f"An error occurred while saving results to CSV: {e}")


if __name__ == "__main__":
    log_file_path = "sample.log"  # Update this path if needed
    print("Analyzing log file...")
    
    log_data, ip_data = count_requests_per_ip(log_file_path)

    if log_data and ip_data:
        endpoint_data = most_frequent_endpoint(log_data)
        suspicious_data = detect_suspicious_activity(log_data, threshold=10)
        save_results_to_csv(ip_data, endpoint_data, suspicious_data)




