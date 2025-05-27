#!/usr/bin/env python3
"""
URL Extractor Script
Extracts URLs from various file types (txt, json, csv, etc.) with encoding support
Supports file picker and saves URLs line by line to a new text file
"""

import re
import json
import csv
import os
import sys
from pathlib import Path
import chardet
from tkinter import filedialog, messagebox
import tkinter as tk


class URLExtractor:
    def __init__(self):
        # Comprehensive URL regex pattern
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?',
            re.IGNORECASE
        )

        # Alternative patterns for different URL formats
        self.alternative_patterns = [
            re.compile(r'URL:\s*(https?://[^\s\n\r]+)', re.IGNORECASE),
            re.compile(r'"url":\s*"(https?://[^"]+)"', re.IGNORECASE),
            re.compile(r'url=([^&\s]+)', re.IGNORECASE),
            re.compile(r'href=["\']?(https?://[^"\'>\s]+)["\']?', re.IGNORECASE),
        ]

    def detect_encoding(self, file_path):
        """Detect file encoding using chardet"""
        try:
            with open(file_path, 'rb') as file:
                raw_data = file.read(10000)  # Read first 10KB for detection
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                confidence = result['confidence']

                print(f"Detected encoding: {encoding} (confidence: {confidence:.2f})")

                # Fallback encodings if confidence is low
                if confidence < 0.7:
                    fallback_encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
                    for enc in fallback_encodings:
                        try:
                            with open(file_path, 'r', encoding=enc) as test_file:
                                test_file.read(1000)
                            print(f"Using fallback encoding: {enc}")
                            return enc
                        except UnicodeDecodeError:
                            continue

                return encoding or 'utf-8'
        except Exception as e:
            print(f"Error detecting encoding: {e}")
            return 'utf-8'

    def read_file_content(self, file_path, encoding):
        """Read file content with specified encoding"""
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                return file.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return None

    def extract_urls_from_text(self, content):
        """Extract URLs from plain text content"""
        urls = set()

        # Try main URL pattern
        urls.update(self.url_pattern.findall(content))

        # Try alternative patterns
        for pattern in self.alternative_patterns:
            urls.update(pattern.findall(content))

        return list(urls)

    def extract_urls_from_json(self, content):
        """Extract URLs from JSON content"""
        urls = set()

        try:
            # First try to parse as JSON
            data = json.loads(content)
            urls.update(self._extract_urls_from_dict(data))
        except json.JSONDecodeError:
            pass

        # Also extract URLs from raw content
        urls.update(self.extract_urls_from_text(content))

        return list(urls)

    def _extract_urls_from_dict(self, data):
        """Recursively extract URLs from dictionary/list structures"""
        urls = set()

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and self.url_pattern.match(value):
                    urls.add(value)
                elif isinstance(value, (dict, list)):
                    urls.update(self._extract_urls_from_dict(value))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str) and self.url_pattern.match(item):
                    urls.add(item)
                elif isinstance(item, (dict, list)):
                    urls.update(self._extract_urls_from_dict(item))

        return urls

    def extract_urls_from_csv(self, content, file_path):
        """Extract URLs from CSV content"""
        urls = set()

        try:
            # Try to parse as CSV
            csv_reader = csv.reader(content.splitlines())
            for row in csv_reader:
                for cell in row:
                    if isinstance(cell, str):
                        cell_urls = self.url_pattern.findall(cell)
                        urls.update(cell_urls)
        except Exception as e:
            print(f"Error parsing CSV: {e}")

        # Also extract URLs from raw content
        urls.update(self.extract_urls_from_text(content))

        return list(urls)

    def extract_urls_from_file(self, file_path):
        """Main method to extract URLs from any file type"""
        print(f"Processing file: {file_path}")

        # Detect encoding
        encoding = self.detect_encoding(file_path)

        # Read file content
        content = self.read_file_content(file_path, encoding)
        if content is None:
            return []

        # Get file extension
        file_ext = Path(file_path).suffix.lower()

        # Extract URLs based on file type
        if file_ext == '.json':
            urls = self.extract_urls_from_json(content)
        elif file_ext == '.csv':
            urls = self.extract_urls_from_csv(content, file_path)
        else:
            # Default to text extraction for all other formats
            urls = self.extract_urls_from_text(content)

        # Remove duplicates and clean URLs
        unique_urls = list(set(url.strip() for url in urls if url.strip()))

        print(f"Found {len(unique_urls)} unique URLs")
        return unique_urls

    def save_urls_to_file(self, urls, output_file):
        """Save URLs to output file, one per line"""
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                for url in urls:
                    file.write(url + '\n')
            print(f"URLs saved to: {output_file}")
            return True
        except Exception as e:
            print(f"Error saving URLs: {e}")
            return False

    def select_file(self):
        """Open file picker dialog"""
        root = tk.Tk()
        root.withdraw()  # Hide the main window

        file_path = filedialog.askopenfilename(
            title="Select file to extract URLs from",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("Log files", "*.log"),
                ("All files", "*.*")
            ]
        )

        root.destroy()
        return file_path

    def get_output_filename(self, input_file):
        """Generate output filename based on input file"""
        input_path = Path(input_file)
        output_file = input_path.parent / f"{input_path.stem}_extracted_urls.txt"
        return str(output_file)

    def run(self):
        """Main execution method"""
        print("URL Extractor - Extract URLs from various file types")
        print("=" * 50)

        # Get input file
        if len(sys.argv) > 1:
            input_file = sys.argv[1]
        else:
            print("Opening file picker...")
            input_file = self.select_file()

        if not input_file or not os.path.exists(input_file):
            print("No file selected or file doesn't exist.")
            return

        # Extract URLs
        urls = self.extract_urls_from_file(input_file)

        if not urls:
            print("No URLs found in the file.")
            return

        # Get output filename
        output_file = self.get_output_filename(input_file)

        # Save URLs
        if self.save_urls_to_file(urls, output_file):
            print(f"\nExtraction completed successfully!")
            print(f"Input file: {input_file}")
            print(f"Output file: {output_file}")
            print(f"Total URLs extracted: {len(urls)}")

            # Show first few URLs as preview
            print("\nFirst few URLs:")
            for i, url in enumerate(urls[:5]):
                print(f"  {i + 1}. {url}")
            if len(urls) > 5:
                print(f"  ... and {len(urls) - 5} more")
        else:
            print("Failed to save URLs to file.")


def main():
    """Main function"""
    try:
        extractor = URLExtractor()
        extractor.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()