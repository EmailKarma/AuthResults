import os
import re
import csv
from datetime import datetime
from email.parser import BytesParser

def extract_auth_results(email_message):
    """
    Extracts Authentication-Results header values from an email message.

    Args:
        email_message (email.message.Message): The email message to extract values from.

    Returns:
        dict: A dictionary containing the extracted values.
    """
    auth_results = {
        'header.from': '',
        'spfdomain': '',
        'dkim1': '',
        'dkdomain1': '',
        'header.i1': '',
        'header.s1': '',
        'dkim2': '',
        'dkdomain2': '',
        'header.i2': '',
        'header.s2': '',
        'dmarc_p': '',
        'dmarc_sp': '',
        'dmarc_dis': '',
        'arc_spf': '',
        'arc_spfdomain': '',
        'arc_dkim1': '',
        'arc_dkdomain1': '',
        'arc_dkim2': '',
        'arc_dkdomain2': '',
        'arc_dmarc': '',
        'arc_fromdomain': '',
    }

    auth_header = email_message.get('Authentication-Results')
    if auth_header:
        # Extract header.from
        header_from_match = re.search(r'header\.from=([^ ;]+)', auth_header)
        auth_results['header.from'] = header_from_match.group(1) if header_from_match else ''

        # Extract SPF domain (refined regex to avoid semicolons and quotes)
        spf_match = re.search(r'spf=pass \(.*domain of .*@([^\s;"]+)', auth_header)
        auth_results['spfdomain'] = spf_match.group(1).split('@')[-1].strip() if spf_match else ''

        # Extract DMARC values
        dmarc_match = re.search(r'dmarc=pass \(p=([^ ]+) sp=([^ ]+) dis=([^ ]+)\)', auth_header)
        if dmarc_match:
            auth_results['dmarc_p'] = dmarc_match.group(1)
            auth_results['dmarc_sp'] = dmarc_match.group(2)
            auth_results['dmarc_dis'] = dmarc_match.group(3)

        # Extract ARC values
        arc_match = re.search(r'arc=pass \(i=\d+ spf=([^ ]+) spfdomain=([^ ]+) dkim=([^ ]+) dkdomain=([^ ]+) dkim=([^ ]+) dkdomain=([^ ]+) dmarc=([^ ]+) fromdomain=([^ ]+)\)', auth_header)
        if arc_match:
            auth_results['arc_spf'] = arc_match.group(1)
            auth_results['arc_spfdomain'] = arc_match.group(2)
            auth_results['arc_dkim1'] = arc_match.group(3)
            auth_results['arc_dkdomain1'] = arc_match.group(4)
            auth_results['arc_dkim2'] = arc_match.group(5)
            auth_results['arc_dkdomain2'] = arc_match.group(6)
            auth_results['arc_dmarc'] = arc_match.group(7)
            auth_results['arc_fromdomain'] = arc_match.group(8)

        # Extract DKIM values with associated headers
        dkim_matches = re.finditer(r'dkim=pass header\.i=@?([^ ]+) header\.s=([^ ]+)', auth_header)
        for i, match in enumerate(dkim_matches, start=1):
            auth_results[f'dkim{i}'] = 'pass'
            auth_results[f'header.i{i}'] = match.group(1)
            auth_results[f'header.s{i}'] = match.group(2)

            # Extract DKIM domain (assuming it's part of the header.i value)
            dkim_domain = match.group(1).split('@')[-1] if '@' in match.group(1) else ''
            auth_results[f'dkdomain{i}'] = dkim_domain

    return auth_results

def process_emails(directory):
    """
    Processes all email files in a directory and extracts Authentication-Results header values.

    Args:
        directory (str): The path to the directory containing email files.

    Returns:
        list: A list of dictionaries containing the extracted values.
    """
    results = []
    for filename in os.listdir(directory):
        if filename.endswith('.eml'):
            file_path = os.path.join(directory, filename)
            with open(file_path, 'rb') as f:
                msg = BytesParser().parse(f)
                auth_results = extract_auth_results(msg)
                if any(auth_results.values()):  # Check if any values were extracted
                    results.append(auth_results)
    return results

def save_to_csv(results, directory):
    """
    Saves the extracted Authentication-Results header values to a CSV file.

    Args:
        results (list): A list of dictionaries containing the extracted values.
        directory (str): The path to the directory where the CSV file will be saved.
    """
    csv_filename = f'{datetime.now().strftime("%Y-%m-%d")}-authresults.csv'
    csv_path = os.path.join(directory, csv_filename)
    fieldnames = [
        'header.from', 'spfdomain',
        'dkim1', 'dkdomain1', 'header.i1', 'header.s1',
        'dkim2', 'dkdomain2', 'header.i2', 'header.s2',
        'dmarc_p', 'dmarc_sp', 'dmarc_dis',
        'arc_spf', 'arc_spfdomain', 'arc_dkim1', 'arc_dkdomain1',
        'arc_dkim2', 'arc_dkdomain2', 'arc_dmarc', 'arc_fromdomain'
    ]

    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    directory = input('Enter the directory to scan: ')
    if not os.path.isdir(directory):
        print('Invalid directory')
    else:
        results = process_emails(directory)
        save_to_csv(results, directory)
        print(f'Results saved to {os.path.join(directory, f"{datetime.now().strftime("%Y-%m-%d")}-authresults.csv")}')
