# VRV Security Assignment

## Overview

This repository contains a Python-based log analyzer designed to analyze web server logs. The program processes log files to perform the following tasks:

1. **Count requests per IP**: Counts how many requests each IP address has made.
2. **Identify the most frequently accessed endpoint**: Determines the endpoint that is accessed the most frequently.
3. **Detect suspicious activity**: Identifies IP addresses with failed login attempts exceeding a given threshold, which could indicate brute-force login attempts.
4. **Save results to a CSV file**: Saves the analysis results into a CSV file for further review.

## Features

- **Request Count by IP**: Identifies which IP addresses are making the most requests.
- **Most Accessed Endpoint**: Finds the endpoint most accessed by users based on the log data.
- **Suspicious Activity Detection**: Flags IP addresses that have more than 10 failed login attempts (default threshold).
- **CSV Export**: Outputs the analysis results into a CSV file for easy review.

## Prerequisites

This project requires Python 3.x and several standard libraries. There are no external dependencies for this particular implementation.


