from bs4 import BeautifulSoup, Tag # Import Tag explicitly from bs4
import pandas as pd
import re
import os

def parse_cis_report(html_content):
    """
    Parses the CIS benchmark report HTML content to extract rule details.

    Args:
        html_content (str): The raw HTML content of the CIS benchmark report.

    Returns:
        tuple: A tuple containing:
            - str: The detected report type ("Domain Controller", "Member Server", or "Unknown").
            - list: A list of dictionaries, where each dictionary represents a rule
                    and its extracted information, including the detected report type.
            - str: The extracted Target IP Address.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_data = []
    report_type = "Unknown"
    target_ip_address = "N/A" # Initialize IP address

    # --- Determine Report Type ---
    profile_li = soup.find(lambda tag: tag.name == 'li' and 'level' in tag.get_text().lower() and ('member server' in tag.get_text().lower() or 'domain controller' in tag.get_text().lower()))
    if profile_li:
        profile_text = profile_li.get_text(strip=True).lower()
        if "domain controller" in profile_text:
            report_type = "Domain Controller"
        elif "member server" in profile_text:
            report_type = "Member Server"
    else:
        summary_profile_td = soup.find('td', class_='summaryHeading', string='Profile:')
        if summary_profile_td:
            profile_value_td = summary_profile_td.find_next_sibling('td', class_='summaryData')
            if profile_value_td:
                profile_text = profile_value_td.get_text(strip=True).lower()
                if "domain controller" in profile_text:
                    report_type = "Domain Controller"
                elif "member server" in profile_text:
                    report_type = "Member Server"
                else:
                    title_tag = soup.find('title')
                    if title_tag and "Domain Controller" in title_tag.get_text():
                        report_type = "Domain Controller"
                    elif title_tag and "Member Server" in title_tag.get_text():
                        report_type = "Member Server"

    if report_type == "Unknown":
        if soup.find(string=re.compile(r"Domain Controller", re.IGNORECASE)):
            report_type = "Domain Controller (Inferred)"
        elif soup.find(string=re.compile(r"Member Server", re.IGNORECASE)):
            report_type = "Member Server (Inferred)"

    # --- Extract Target IP Address ---
    ip_address_li = soup.find(lambda tag: tag.name == 'li' and 'Target IP Address:' in tag.get_text())
    if ip_address_li:
        ip_text = ip_address_li.get_text(strip=True)
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?', ip_text) # IPv4
        if ip_match:
            target_ip_address = ip_match.group(0)
        else:
            ipv6_match = re.search(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', ip_text)
            if ipv6_match:
                target_ip_address = ipv6_match.group(0)
            else:
                parts = ip_text.split(':')
                if len(parts) > 1:
                    target_ip_address = parts[-1].strip()

    # --- Extract Rule Information ---
    rule_sections = soup.find_all('h3', class_='ruleTitle')
    print(f"DEBUG: Found {len(rule_sections)} 'h3.ruleTitle' sections.")

    for i, rule_h3 in enumerate(rule_sections):
        cis_recommendation = "N/A"
        title = "N/A"
        recommended_state = "N/A"
        assessment_evidence = []
        
        full_title_text = rule_h3.get_text(strip=True)
        rec_match = re.match(r'(\d+(?:\.\d+)+(?:\s+\(L\d+\))?)\s*(.*)', full_title_text)
        if rec_match:
            cis_recommendation = rec_match.group(1).strip()
            title = rec_match.group(2).strip()
        else:
            cis_recommendation = full_title_text.split(' ')[0] if full_title_text else "N/A"
            title = ' '.join(full_title_text.split(' ')[1:]) if len(full_title_text.split(' ')) > 1 else full_title_text

        full_rule_id_from_attr = rule_h3.get('title')
        if full_rule_id_from_attr:
            rule_id_match_from_attr = re.search(r'_rule_(\d+(?:\.\d+)+)', full_rule_id_from_attr)
            if rule_id_match_from_attr:
                cis_recommendation = rule_id_match_from_attr.group(1)

        # --- Extract Recommended State ---
        # Search all elements after rule_h3 until the next rule_h3 for the recommended state span
        current_element_for_state = rule_h3.next_sibling
        while current_element_for_state and not (current_element_for_state.name == 'h3' and 'ruleTitle' in current_element_for_state.get('class', [])):
            if isinstance(current_element_for_state, Tag): # Corrected from BeautifulSoup.Tag
                # Check for recommended state within <p> tags in the description div
                if current_element_for_state.name == 'div' and 'description' in current_element_for_state.get('class', []):
                    # Look for the specific pattern: "The recommended state for this setting is: <span class='inline_block'>VALUE</span>"
                    for p_tag in current_element_for_state.find_all('p'):
                        if "the recommended state for this setting is:" in p_tag.get_text().lower() or "the recommended state for this setting is to include:" in p_tag.get_text().lower():
                            recommended_state_span = p_tag.find('span', class_='inline_block')
                            if recommended_state_span:
                                recommended_state = recommended_state_span.get_text(strip=True)
                                break # Found it, no need to search further within this rule for Recommended State
                    if recommended_state != "N/A": # If found in description, break outer loop too
                        break
            current_element_for_state = current_element_for_state.next_sibling

        # --- Collect Assessment Evidence from the specific 'check' div ---
        # The ID for the evidence div is consistently "detail-d1eXXXX_evidence"
        # We need to find the rule's parent div to construct the correct ID.
        rule_parent_div = rule_h3.find_parent('div', class_='Rule')
        if rule_parent_div and 'id' in rule_parent_div.attrs:
            # The structure is <div id="detail-d1eXXXX"> ... <div class="check"> <div id="detail-d1eXXXX_evidence">
            # So, we can get the ID from the parent div's 'id' attribute, remove 'detail-', and append '_evidence'
            base_id = rule_parent_div['id'].replace('detail-', '')
            evidence_div_id = f"{base_id}_evidence"
            
            evidence_container_div = rule_parent_div.find('div', id=evidence_div_id)

            if evidence_container_div:
                # Find all *direct children* tables that are evidence tables
                # This prevents picking up tables from nested structures like the XML display.
                # We also need to be careful with tables that might have different classes like 'evidence-sep'
                for table in evidence_container_div.find_all('table', class_=['evidence', 'evidence-sep'], recursive=False):
                    # Only process tables that are direct children of the evidence_container_div
                    # and are not within the XML result block
                    if table.parent == evidence_container_div:
                        for row in table.select('tbody tr'):
                            cols = row.find_all('td')
                            row_data = [col.get_text(strip=True) for col in cols]
                            if len(row_data) >= 4: # Assuming Name, Type, Status, Value
                                name = row_data[0]
                                value = row_data[3] # Assuming value is always in the 4th column (index 3)
                                assessment_evidence.append(f"{name}: {value}")
                            elif row_data: # If fewer than 4 columns but still has data, just join them
                                assessment_evidence.append(": ".join(row_data))
            
        # Remove duplicates from assessment_evidence while preserving order (using set and then list conversion)
        assessment_evidence = list(dict.fromkeys(assessment_evidence))
        assessment_evidence_str = "; ".join(assessment_evidence) if assessment_evidence else "N/A"
            
        if cis_recommendation != "N/A" or title != "N/A":
            rule_data = {
                "CIS Recommendation #": cis_recommendation,
                "Title": title,
                "Recommended State": recommended_state,
                "Assessment Evidence": assessment_evidence_str,
                "Report Type": report_type
            }
            extracted_data.append(rule_data)

    return extracted_data, target_ip_address

# --- Main execution block for user input (remains the same) ---
if __name__ == "__main__":
    output_excel_file = "combined_cis_reports.xlsx"
    file_paths = []

    print("Enter the paths to your CIS benchmark HTML report files, one by one.")
    print("Press Enter on an empty line when you are finished.")

    while True:
        path = input(f"Enter path for report {len(file_paths) + 1} (or press Enter to finish): ").strip()
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
            
        if not path:
            break
        file_paths.append(path)

    if not file_paths:
        print("No files entered. Exiting.")
    else:
        if not os.path.exists(output_excel_file):
            try:
                print(f"'{output_excel_file}' does not exist. Creating a new, empty Excel file with a default sheet...")
                # Create a dummy DataFrame to ensure a valid Excel structure is written
                dummy_df = pd.DataFrame()
                with pd.ExcelWriter(output_excel_file, engine='openpyxl', mode='w') as writer:
                    # Write an empty DataFrame to a temporary sheet.
                    # This ensures the file is created with all necessary XML parts.
                    dummy_df.to_excel(writer, sheet_name='TempSheet', index=False)
                print(f"Successfully created initial Excel file: '{output_excel_file}'")
            except Exception as e:
                print(f"Error creating initial Excel file '{output_excel_file}': {e}")
                exit()
        try:
            with pd.ExcelWriter(output_excel_file, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
                for i, html_file_path in enumerate(file_paths):
                    print(f"\nAttempting to process file: '{html_file_path}'")
                    if not os.path.exists(html_file_path):
                        print(f"Skipping: File not found at {html_file_path}. Please check the path and try again.")
                        continue
                    elif not html_file_path.lower().endswith(('.html', '.htm')):
                        print(f"Skipping: The provided file is not an HTML file: {html_file_path}.")
                        continue

                    try:
                        with open(html_file_path, "r", encoding="utf-8") as f:
                            html_content = f.read()
                        print(f"DEBUG: Successfully read {len(html_content)} characters from '{html_file_path}'.")

                        #temp_soup = BeautifulSoup(html_content, 'html.parser')
                        #if temp_soup.body:
                        #    print(f"DEBUG: First 500 chars of parsed body:\n{str(temp_soup.body.prettify())[:500]}...")
                        #else:
                        #    print("DEBUG: No <body> tag found in the parsed HTML.")

                        extracted_data, target_ip = parse_cis_report(html_content)

                        df = pd.DataFrame(extracted_data)
                        print(f"DEBUG: DataFrame created with {len(df)} rows.")

                        if df.empty:
                            print(f"WARNING: No data extracted from '{html_file_path}'. This sheet will be empty and not added.")
                            continue

                        sheet_name = target_ip
                        if sheet_name == "N/A":
                            base_name = os.path.splitext(os.path.basename(html_file_path))[0]
                            sheet_name = base_name
                            print(f"WARNING: Target IP Address not found. Using base filename '{base_name}' for sheet name.")
                        
                        sheet_name = re.sub(r'[\\/?*\[\]:]', '', sheet_name)
                        if len(sheet_name) > 31:
                            sheet_name = sheet_name[:31]
                            print(f"WARNING: Sheet name truncated to '{sheet_name}' due to length limit.")

                        detected_report_type_for_print = df['Report Type'].iloc[0] if not df.empty else 'Unknown'
                        print(f"\nProcessing '{html_file_path}' (Detected type: {detected_report_type_for_print})")

                        df.to_excel(writer, sheet_name=sheet_name, index=False)
                        print(f"Successfully wrote data to sheet: '{sheet_name}'")

                    except Exception as e:
                        print(f"An error occurred while processing '{html_file_path}': {e}")
            
            print(f"\nAll processed data saved to a single Excel file: {output_excel_file}")

        except Exception as e:
            print(f"An error occurred while creating or writing to the Excel file: {e}.")