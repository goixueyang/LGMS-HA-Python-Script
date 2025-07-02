from bs4 import BeautifulSoup, Tag # Import Tag explicitly from bs4
import pandas as pd
import re
import os
import numpy as np
import traceback
import sys

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

def clean_cis_recommendation_id(cis_id):
    """
    Cleans the 'CIS Recommendation #' by removing ' (Domain Controller only)'
    and ' (Refer to evidence)' and stripping whitespace.
    """
    if isinstance(cis_id, str):
        cleaned_id = cis_id.replace(' (Domain Controller only)', '').strip()
        cleaned_id = cleaned_id.replace(' (Refer to evidence)', '').strip()
        return cleaned_id
    return cis_id

def convert_to_seconds(value_str, debug_flag=False):
    """
    Converts a string representation of time (e.g., '180', '3 minutes', '1 hour', '3 or more minutes')
    into its equivalent in seconds. Returns a tuple (converted_value, is_min_value_required).
    is_min_value_required is True if the original string implied "X or more".
    Returns (None, False) if conversion is not possible or irrelevant.
    """
    if pd.isna(value_str):
        if debug_flag:
            print(f"      DEBUG: convert_to_seconds: Input '{value_str}' is NaN. Returning (None, False).")
        return None, False

    s = str(value_str).strip().lower()
    converted_value = None
    is_min_value_required = False

    # Check for "or more" phrase
    if 'or more' in s:
        is_min_value_required = True
        s = s.replace('or more', '').strip()
    
    # Check for "or fewer" or "less than or equal to" phrases
    if 'or fewer' in s:
        is_max_value_required = True
        s = s.replace('or fewer', '').strip()
    elif 'less than or equal to' in s:
        is_max_value_required = True
        s = s.replace('less than or equal to', '').strip()
    elif 'less than' in s: # Consider strict 'less than' as well
        is_max_value_required = True
        s = s.replace('less than', '').strip()

    # Try direct conversion to float first (assumes value is already in seconds)
    try:
        converted_value = float(s)
        if debug_flag:
            print(f"      DEBUG: convert_to_seconds: Input '{value_str}' directly converted to {converted_value}s (min_value_required={is_min_value_required}).")
        return converted_value, is_min_value_required
    except ValueError:
        pass # Not a simple number, proceed to parse units

    # Regex to extract number and unit
    match = re.search(r'(\d+)\s*(second|minute|hour|day)s?', s)
    if match:
        num = int(match.group(1))
        unit = match.group(2)
        if unit == 'second':
            converted_value = float(num)
        elif unit == 'minute':
            converted_value = float(num * 60)
        elif unit == 'hour':
            converted_value = float(num * 3600)
        elif unit == 'day':
            converted_value = float(num * 86400)
            
        if debug_flag:
            print(f"      DEBUG: convert_to_seconds: Input '{value_str}' parsed as {num} {unit}(s), converted to {converted_value}s (min_value_required={is_min_value_required}).")
        return converted_value, is_min_value_required
    
    # Handle values that might imply 0 seconds, like "disabled" in a time context
    if s in ['0', 'none', 'not applicable', 'no limit']:
        converted_value = 0.0
        if debug_flag:
            print(f"      DEBUG: convert_to_seconds: Input '{value_str}' implies 0 seconds. Returning {converted_value}s (min_value_required={is_min_value_required}).")
        return converted_value, is_min_value_required

    if debug_flag:
        print(f"      DEBUG: convert_to_seconds: Input '{value_str}' could not be converted to seconds. Returning (None, False).")
    return None, False


def check_assessment_evidence(cimb_value, assessment_evidence, settings_checklist_value, title_ip_value, cis_rec_checklist_raw, debug_flag=False):
    debug_flag = False
    """
    Checks if the assessment evidence aligns with the CIMB value criteria.
    This function handles direct matches, unit conversions (seconds),
    numeric values (including "X or more" logic), and keyword-based checks for 'configured' status.
    It also attempts to extract relevant values from structured assessment evidence.
    """
    if debug_flag:
        print(f"    DEBUG: In check_assessment_evidence: CIMB Value='{cimb_value}' (type: {type(cimb_value)}), Assessment Evidence='{assessment_evidence}' (type: {type(assessment_evidence)}), Settings='{settings_checklist_value}', Title_IP='{title_ip_value}', CIS_Rec_Checklist='{cis_rec_checklist_raw}'")

    #if cis_rec_checklist_raw == '18.5.1':
    #    print(f"\n--- DEBUG: check_assessment_evidence called for CIS: {cis_rec_checklist_raw} ---")
    #    print(f"    CIMB Value (raw): '{cimb_value}'")
    #    print(f"    Assessment Evidence (raw): '{assessment_evidence}'")
    #    print(f"    Settings Checklist Value: '{settings_checklist_value}'")
    #    print(f"    Title IP Value: '{title_ip_value}'")
    #    debug_flag = True

    cimb_value_lower = str(cimb_value).strip().lower() #
    original_assessment_evidence_str = str(assessment_evidence).strip()
    assessment_evidence_lower = str(assessment_evidence).strip().lower() #
    
    # NEW RULE: Handle reg_multi_sz type for multiple 'Value:' entries
    if "type: reg_multi_sz" in assessment_evidence_lower:
        # Parse CIMB Value into a set of paths (for order-independent comparison)
        cimb_paths = {path.strip() for path in str(cimb_value).split('\n') if path.strip()}

        # Extract all 'Value:' entries from the ORIGINAL assessment evidence string
        # This regex finds "Value:" followed by content, stopping at the next semicolon,
        # newline, or end of string.
        extracted_evidence_paths_raw = re.findall(r'Value:\s*(.*?)(?:;|$|\n)', original_assessment_evidence_str, re.IGNORECASE)
        # Filter out empty strings AND explicitly exclude 'No Value'
        extracted_evidence_paths = {
            path.strip() for path in extracted_evidence_paths_raw
            if path.strip() and path.strip().lower() != 'no value' # <-- Add this condition
        }

        if debug_flag:
            print(f"      DEBUG: reg_multi_sz check: CIMB paths from '{cimb_value}': {cimb_paths}")
            print(f"      DEBUG: reg_multi_sz check: Extracted evidence paths from '{original_assessment_evidence_str}': {extracted_evidence_paths}")
            
        # Compare the sets of paths
        if cimb_paths == extracted_evidence_paths:
            if debug_flag:
                print(f"      DEBUG: reg_multi_sz specific rule: CIMB paths exactly match extracted evidence paths. Returning True.")
            return True # Values match, so it's configured
            
    # Specific rule for 'Classic – local users authenticate as themselves' or CIMB '4.5.2.1' '4.5.6.1' '4.6.6.1' '4.6.14.1.1'
    if cimb_value_lower == 'classic – local users authenticate as themselves' or cis_rec_checklist_raw == '18.9.4.1' or cis_rec_checklist_raw == '18.9.23.1' or cis_rec_checklist_raw == '18.10.15.1' or cis_rec_checklist_raw == '18.10.58.2':
        # Look for 'Value: 0' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '0' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '0' were part of another number (e.g., '10').
        if re.search(r'value:\s*0(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Specific rule for 'Classic': Found 'Value: 0'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: Specific rule for 'Classic': 'Value: 0' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for 'Negotiate signing' or CIMB '4.6.2.2' '4.6.12.5.1' '4.6.12.5.2'
    if cimb_value_lower == 'negotiate signing' or cis_rec_checklist_raw == '18.10.7.2' or cis_rec_checklist_raw == '18.10.56.3.11.1' or cis_rec_checklist_raw == '18.10.56.3.11.2':
        # Look for 'Value: 1' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '1' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '1' were part of another number (e.g., '10').
        if re.search(r'value:\s*1(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Specific rule for 'Negotiate Signing': Found 'Value: 1'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: Specific rule for 'Negotiate Signing': 'Value: 1' not found or did not match pattern. Continuing other checks.")
    
    # Specific rule for 'Users can't add or log on with Microsoft accounts' or CIMB '2.3.13.3' '4.4.6.1' '4.5.4.1' '4.6.12.3.5'
    if cimb_value_lower == "users can't add or log on with microsoft accounts" or cis_rec_checklist_raw == '2.3.17.3' or cis_rec_checklist_raw == '18.6.21.1' or cis_rec_checklist_raw == '18.9.13.1' or cis_rec_checklist_raw == '18.10.56.3.9.5':
        # Look for 'Value: 3' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '3' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '3' were part of another number (e.g., '10').
        if re.search(r'value:\s*3(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Specific rule for 'Negotiate Signing': Found 'Value: 3'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: Specific rule for 'Negotiate Signing': 'Value: 3' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for 'Always' or 'Require signing' or CIMB '4.6.12.3.3'
    if cimb_value_lower == 'always' or cimb_value_lower == 'require signing' or cis_rec_checklist_raw == '18.10.56.3.9.3':
        # Look for 'Value: 2' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '2' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '2' were part of another number (e.g., '10').
        if re.search(r'value:\s*2(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Specific rule for 'Negotiate Signing': Found 'Value: 2'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: Specific rule for 'Negotiate Signing': 'Value: 2' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for 'Send NTLMv2 response only. Refuse LM & NTLM' or CIMB '2.3.13.2'
    if cimb_value_lower == 'send ntlmv2 response only. refuse lm & ntlm' or cis_rec_checklist_raw == '2.3.17.2':
        # Look for 'Value: 5' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '5' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '5' were part of another number (e.g., '10').
        if re.search(r'value:\s*5(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Specific rule for 'Send NTLMv2 response only. Refuse LM & NTLM': Found 'Value: 5'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: Specific rule for 'Send NTLMv2 response only. Refuse LM & NTLM': 'Value: 5' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for CIMB '2.3.6.4'
    if cis_rec_checklist_raw == '2.3.7.4':
        if re.search(r'value:\s*this system is restricted to cimb authorised users only. illegal and/or unauthorised', assessment_evidence_lower):
            return True
            
    # Specific rule for CIMB '2.3.6.5'
    if cis_rec_checklist_raw == '2.3.7.5':
        if re.search(r'value:\s*warning!(?=[;\n]|$)', assessment_evidence_lower):
            return True
            
    # Specific rule for CIMB '2.3.9.7'
    if cis_rec_checklist_raw == '2.3.10.7':
        # Look for 'Value: No Value' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures 'No Value' is followed by a semicolon, newline, or end of string,
        # preventing false positives if 'No Value' were part of another number (e.g., '10').
        if re.search(r'value:\s*no value(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Specific rule for '2.3.9.7': Found 'Value: No Value'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: Specific rule for '2.3.9.7': 'Value: No Value' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for CIMB '2.3.10.9' and '2.3.10.10'
    if cis_rec_checklist_raw == '2.3.11.9' or cis_rec_checklist_raw == '2.3.11.10':
        # Look for 'Value: 537395200' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '537395200' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '537395200' were part of another number (e.g., '10').
        if re.search(r'value:\s*537395200(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Specific rule for '2.3.10.9' and '2.3.10.10': Found 'Value: 537395200'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: Specific rule for '2.3.10.9' and '2.3.10.10': 'Value: 537395200' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for CIMB '4.6.2.3'
    if cis_rec_checklist_raw == '18.10.7.3':
        # Look for 'Value: 255' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '255' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '255' were part of another number (e.g., '10').
        if re.search(r'value:\s*255(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Found 'Value: 255'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: 'Value: 255' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for CIMB '4.6.7.1.2' '4.6.7.2.2' '4.6.7.3.2' '4.6.7.4.2'
    if cis_rec_checklist_raw == '18.10.25.1.2' or cis_rec_checklist_raw == '18.10.25.2.2' or cis_rec_checklist_raw == '18.10.25.3.2' or cis_rec_checklist_raw == '18.10.25.4.2':
        # Look for 'Value: 100032' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '100032' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '100032' were part of another number (e.g., '10').
        if re.search(r'value:\s*100032(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Found 'Value: 100032'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: 'Value: 100032' not found or did not match pattern. Continuing other checks.")

    # Specific rule for CIMB '4.6.12.4.1'
    if cis_rec_checklist_raw == '18.10.56.3.10.1':
        # Look for 'Value: 900000' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '900000' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '900000' were part of another number (e.g., '10').
        if re.search(r'value:\s*900000(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Found 'Value: 900000'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: 'Value: 900000' not found or did not match pattern. Continuing other checks.")

    # Specific rule for CIMB '4.6.15.1.1'
    if cis_rec_checklist_raw == '18.10.75.2.1':
        # Look for 'Value: Block' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures 'Block' is followed by a semicolon, newline, or end of string,
        # preventing false positives if 'Block' were part of another number (e.g., '10').
        if re.search(r'value:\s*block(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Found 'Value: Block'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: 'Value: Block' not found or did not match pattern. Continuing other checks.")
            
    # Specific rule for CIMB '2.3.10.4'
    if cis_rec_checklist_raw == '2.3.11.4':
        # Look for 'Value: 2147483640' in the original assessment evidence string (case-insensitive for 'Value:')
        # The regex `(?=[;\n]|$)` ensures '2147483640' is followed by a semicolon, newline, or end of string,
        # preventing false positives if '2147483640' were part of another number (e.g., '10').
        if re.search(r'value:\s*2147483640(?=[;\n]|$)', assessment_evidence_lower):
            if debug_flag:
                print(f"      DEBUG: Found 'Value: 2147483640'. Returning True.")
            return True
        elif debug_flag:
            print(f"      DEBUG: 'Value: 2147483640' not found or did not match pattern. Continuing other checks.")

    # --- Specific Rule for "No one" / "None exist" ---
    if cimb_value_lower == 'no one' or cimb_value_lower == '' or cimb_value_lower == '<blank>' or cimb_value_lower == 'not configured': 
        if 'not defined' in assessment_evidence_lower or            'no entries found' in assessment_evidence_lower or            'none' in assessment_evidence_lower or            'not configured' in assessment_evidence_lower: #
            if debug_flag:
                print("    DEBUG: 'No one' CIMB value with 'none exist' evidence. Returning 'configured'.") #
            return True # Consistent return type. It should return True for configured.

    # --- EXISTING SPECIAL CASE: CIMB Value is "no one" and Assessment Evidence is 'nan' OR 'n/a' ---
    # The variable assessment_evidence_for_check is not defined here. Assuming it should be assessment_evidence_lower
    if (cimb_value_lower == 'no one' or cimb_value_lower == '' or cimb_value_lower == '<blank>' or cimb_value_lower == 'not configured') and (pd.isna(assessment_evidence) or assessment_evidence_lower == 'n/a'):
        if debug_flag:
            print(f"    DEBUG: Special case: CIMB Value is 'no one' and Assessment Evidence is NaN/N/A. Assuming 'configured'. Returning True.")
        return True # Consistent return type

    # Handle general missing values now (after the specific NaN/no one checks above)
    if pd.isna(cimb_value) or pd.isna(assessment_evidence):
        if debug_flag:
            print(f"    DEBUG: check_assessment_evidence: Missing value detected (not special case). Returning False.")
        return False # Consistent return type

    cimb_value_str = str(cimb_value).strip()
    assessment_evidence_str = str(assessment_evidence).strip()

    # --- Attempt to extract specific value from structured Assessment Evidence (using Title as key source) ---
    extracted_evidence_value = None
    if ';' in assessment_evidence_str or ':' in assessment_evidence_str:
        title_key_match = re.search(r"'([^']+)'", title_ip_value)
        
        if title_key_match:
            search_key_from_title = title_key_match.group(1).strip().lower()
            if debug_flag:
                print(f"    DEBUG: Derived search key from Title_IP: '{search_key_from_title}'.")
            
            key_aliases = {
                'account lockout duration': 'lockout duration',
                'reset account lockout counter after': 'lockout observation window',
                'password must meet complexity requirements': 'password complexity'
            }
            effective_search_key = key_aliases.get(search_key_from_title, search_key_from_title)

            if debug_flag:
                print(f"    DEBUG: Using effective search key for evidence extraction: '{effective_search_key}'.")

            pairs = assessment_evidence_str.split(';')
            for pair in pairs:
                if ':' in pair:
                    key, value = pair.split(':', 1)
                    if key.strip().lower() == effective_search_key:
                        extracted_evidence_value = value.strip()
                        if debug_flag:
                            print(f"        DEBUG: Extracted specific evidence value: '{extracted_evidence_value}' for key '{effective_search_key}'.")
                        break
        else:
            if debug_flag:
                print(f"    DEBUG: Could not extract key from Title_IP: '{title_ip_value}'.")
            
     # Fallback: Directly extract "Value: X" from assessment_evidence_str if not already extracted
    if extracted_evidence_value is None:
        value_match = re.search(r"value:\s*([^;]+)", assessment_evidence_str, re.IGNORECASE)
        if value_match:
            extracted_evidence_value = value_match.group(1).strip()
            if debug_flag:
                print(f"        DEBUG: Fallback: Extracted 'Value: {extracted_evidence_value}' directly from evidence string.")

    if extracted_evidence_value is not None:
        assessment_evidence_str = extracted_evidence_value
        if debug_flag:
            print(f"    DEBUG: Updated Assessment Evidence to extracted value: '{assessment_evidence_str}'.")
            
            
    cimb_value_lower = cimb_value_str.lower()
    assessment_evidence_for_keyword_check = assessment_evidence_str.lower()
    
    # NEW SPECIFIC RULE: Handle CIMB "X unit(s)" vs Evidence "X" where X is a direct number
    # This rule assumes the user wants '15 minutes' to match '15' if the numbers are identical.

    cimb_numeric_part_with_unit_match = re.search(r'^(\d+(\.\d+)?)\s*(second|minute|hour|day)s?$', cimb_value_lower)
    evidence_pure_numeric_match = re.search(r'^(\d+(\.\d+)?)$', assessment_evidence_for_keyword_check)

    if cimb_numeric_part_with_unit_match and evidence_pure_numeric_match:
        cimb_num = float(cimb_numeric_part_with_unit_match.group(1))
        evidence_num = float(evidence_pure_numeric_match.group(1))
        
        if cimb_num == evidence_num:
            if debug_flag:
                print(f"      DEBUG: Specific rule: CIMB '{cimb_value_str}' (number {cimb_num} with unit) matches evidence '{assessment_evidence_str}' (pure number {evidence_num}). Returning True.")
            return True
    
    # Specific Rule for optional '*sql built-in service id’s' and '*system built-in iis apppool ids'
    if cimb_value_lower in ['*sql built-in service id’s', '*system built-in iis apppool ids']:
        if 'not defined' in assessment_evidence_lower or \
           'no entries found' in assessment_evidence_lower or \
           'none' in assessment_evidence_lower or \
           'not configured' in assessment_evidence_lower or \
           pd.isna(assessment_evidence_str) or \
           assessment_evidence_lower == '':
            if debug_flag:
                print(f"    DEBUG: Optional CIMB value '{cimb_value}' and evidence indicates absence. Returning 'configured'.")
            return True # Consistent return type
    
    # Specific rule for CIS ID 18.10.58.2: Check if the last word of evidence is 'Pass'
    if cis_rec_checklist_raw == '18.10.58.2':
        # Use re.findall to extract all "words" at the very end of the string.
        # r'\b(\w+)\s*$' matches one or more word characters (\w+) that are
        # followed by optional whitespace (\s*) and then the end of the string ($).
        # \b ensures it matches a whole word.
        last_word_match = re.findall(r'\b(\w+)\s*$', original_assessment_evidence_str, re.IGNORECASE)

        if last_word_match:
            # Get the last found word from the list of matches and convert it to lowercase for comparison.
            last_word = last_word_match[-1].lower()
            if debug_flag:
                print(f"      DEBUG: CIS ID 18.10.58.2 rule: Last word of evidence: '{last_word}'.")

            # If the last word is 'pass', then it's considered configured.
            if last_word == 'pass':
                if debug_flag:
                    print(f"      DEBUG: CIS ID 18.10.58.2 rule: Last word is 'Pass'. Returning True.")
                return True # This item is configured based on this specific rule
        elif debug_flag:
            print(f"      DEBUG: CIS ID 18.10.58.2 rule: Could not extract a valid last word or it's not a word. Continuing other checks.")

    
    # --- NEW RULE: Specific for CIMB NO. 2.3.1.4 and '<follow CIMB practise>' ---
    if cis_rec_checklist_raw == '2.3.1.4':
        extracted_actual_trustees = set()
        # Adapt extraction logic from your 'NEW Trustee Name Comparison Rule'
        # For simplicity, here's a basic extraction for demonstration.
        # Your script's existing 'NEW Trustee Name Comparison Rule' has more robust parsing.
        if "trustee name:" in assessment_evidence_lower:
            parts = assessment_evidence_lower.split("trustee name:")
            for part in parts[1:]: # Iterate through parts after each "trustee name:"
                # Assuming trustee names are comma-separated or similar
                # You'll need to adapt this to your actual evidence format
                if ";" in part: # Stop at the next section separator
                    current_trustees_str = part.split(";", 1)[0].strip()
                else:
                    current_trustees_str = part.strip()
                
                # Split by comma, newline, etc. and add to set
                for trustee in re.split(r'[,;\n\r]+', current_trustees_str):
                    trustee = trustee.strip().lower()
                    if trustee:
                        extracted_actual_trustees.add(trustee)
        elif "deny log on locally:" in assessment_evidence_lower or "allow log on locally:" in assessment_evidence_lower:
            # Handle allow/deny log on locally as in your existing code for trustee names
            # You'd need to call or replicate the parsing for 'allow log on locally' / 'deny log on locally'
            # For this specific case, focus on finding 'administrator'
            if 'administrator' in assessment_evidence_lower:
                extracted_actual_trustees.add('administrator')

        if 'administrator' in extracted_actual_trustees:
            if debug_flag:
                print(f"      DEBUG: check_assessment_evidence: CIMB 2.3.1.4 with '<follow CIMB practise>'. 'Administrator' trustee found. Returning False (not configured).")
            return False # Administrator found, so 'not configured'
        else:
            if debug_flag:
                print(f"      DEBUG: check_assessment_evidence: CIMB 2.3.1.4 with '<follow CIMB practise>'. 'Administrator' trustee NOT found. Returning True (configured).")
            return True # Administrator not found, so 'configured'
    # --- END NEW RULE ---
    
    # --- NEW RULE: Specific for CIMB NO. 2.3.1.5 and '<follow CIMB practise>' ---
    if cis_rec_checklist_raw == '2.3.1.5':
        extracted_actual_trustees = set()
        # Adapt extraction logic from your 'NEW Trustee Name Comparison Rule'
        # For simplicity, here's a basic extraction for demonstration.
        # Your script's existing 'NEW Trustee Name Comparison Rule' has more robust parsing.
        if "trustee name:" in assessment_evidence_lower:
            parts = assessment_evidence_lower.split("trustee name:")
            for part in parts[1:]: # Iterate through parts after each "trustee name:"
                # Assuming trustee names are comma-separated or similar
                # You'll need to adapt this to your actual evidence format
                if ";" in part: # Stop at the next section separator
                    current_trustees_str = part.split(";", 1)[0].strip()
                else:
                    current_trustees_str = part.strip()
                
                # Split by comma, newline, etc. and add to set
                for trustee in re.split(r'[,;\n\r]+', current_trustees_str):
                    trustee = trustee.strip().lower()
                    if trustee:
                        extracted_actual_trustees.add(trustee)
        elif "deny log on locally:" in assessment_evidence_lower or "allow log on locally:" in assessment_evidence_lower:
            # Handle allow/deny log on locally as in your existing code for trustee names
            # You'd need to call or replicate the parsing for 'allow log on locally' / 'deny log on locally'
            # For this specific case, focus on finding 'guest'
            if 'guest' in assessment_evidence_lower:
                extracted_actual_trustees.add('guest')
                
        if 'guest' in extracted_actual_trustees:
            if debug_flag:
                print(f"      DEBUG: check_assessment_evidence: CIMB 2.3.1.5 with '<follow CIMB practise>'. 'Guest' trustee found. Returning False (not configured).")
            return False # Guest found, so 'not configured'
        else:
            if debug_flag:
                print(f"      DEBUG: check_assessment_evidence: CIMB 2.3.1.5 with '<follow CIMB practise>'. 'Guest' trustee NOT found. Returning True (configured).")
            return True # Guest not found, so 'configured'
    # --- END NEW RULE ---
    
    # --- NEW: Specific rule for CIMB Value 'Success', 'Failure', 'Success and Failure' with Audit Policy in Settings ---
    audit_mapping = {
        'success': 'audit_success',
        'failure': 'audit_failure',
        'success and failure': 'audit_success_failure'
    }

    if cimb_value_lower in audit_mapping:
        expected_audit_value = audit_mapping[cimb_value_lower]
        
        settings_policy_match = re.search(r"'(?:Audit Policy:.*?:\s*)?(?:Audit\s+)?([^']+)'", settings_checklist_value, re.IGNORECASE)

        policy_name_key = None
        if settings_policy_match:
            policy_name_key = settings_policy_match.group(1).strip().lower()
            if debug_flag:
                print(f"      DEBUG: Specific Audit Rule: Extracted policy name from Settings: '{policy_name_key}'")

        if policy_name_key:
            found_evidence_audit_value = None
            
            if ';' in assessment_evidence_str or ':' in assessment_evidence_str:
                pairs = assessment_evidence_str.split(';')
                for pair in pairs:
                    if ':' in pair:
                        key, value = pair.split(':', 1)
                        if key.strip().lower() == policy_name_key:
                            found_evidence_audit_value = value.strip().lower()
                            if debug_flag:
                                print(f"          DEBUG: Specific Audit Rule: Found value '{found_evidence_audit_value}' for key '{policy_name_key}' in structured evidence.")
                            break
            
            if found_evidence_audit_value:
                if found_evidence_audit_value == expected_audit_value:
                    if debug_flag:
                        print(f"      DEBUG: Specific Audit Rule: Match found! CIMB Value '{cimb_value_str}' expected '{expected_audit_value}', found '{found_evidence_audit_value}'. Returning True.")
                    return True # Consistent return type
                else:
                    if debug_flag:
                        print(f"      DEBUG: Specific Audit Rule: Mismatch! CIMB Value '{cimb_value_str}' expected '{expected_audit_value}', found '{found_evidence_audit_value}'. Returning False.")
                    return False # Consistent return type
        else:
            if debug_flag:
                print(f"      DEBUG: Specific Audit Rule: Could not extract policy name from Settings '{settings_checklist_value}'. Skipping this rule.")
                
    # --- NEW RULE: Handle "between X and Y [units]" for numeric CIMB values ---
    between_match = re.search(r'between\s+(\d+)\s+and\s+(\d+)\s*(second|minute|hour|day)s?', cimb_value_lower)
    if between_match:
        min_val_str = between_match.group(1)
        max_val_str = between_match.group(2)
        unit = between_match.group(3)

        # Attempt to extract numeric value from assessment_evidence_str
        evidence_numeric_match = re.search(r'\d+', assessment_evidence_str)
        if evidence_numeric_match:
            extracted_evidence_numeric_str = evidence_numeric_match.group(0)
            
            # Convert extracted evidence value and CIMB range values to seconds
            evidence_val_seconds, _ = convert_to_seconds(f"{extracted_evidence_numeric_str} {unit}", debug_flag) # Assume unit from CIMB
            min_val_seconds, _ = convert_to_seconds(f"{min_val_str} {unit}", debug_flag)
            max_val_seconds, _ = convert_to_seconds(f"{max_val_str} {unit}", debug_flag)

            if evidence_val_seconds is not None and min_val_seconds is not None and max_val_seconds is not None:
                if min_val_seconds <= evidence_val_seconds <= max_val_seconds:
                    if debug_flag:
                        print(f"      DEBUG: check_assessment_evidence: 'Between X and Y' match. CIMB '{cimb_value_str}' range ({min_val_seconds}-{max_val_seconds}s), Evidence '{assessment_evidence_str}' ({evidence_val_seconds}s). Returning True.")
                    return True
                else:
                    if debug_flag:
                        print(f"      DEBUG: check_assessment_evidence: 'Between X and Y' mismatch. CIMB '{cimb_value_str}' range ({min_val_seconds}-{max_val_seconds}s), Evidence '{assessment_evidence_str}' ({evidence_val_seconds}s). Returning False.")
                    return False
        else:
            if debug_flag:
                print(f"      DEBUG: check_assessment_evidence: 'Between X and Y' rule. Could not extract numeric value from assessment evidence '{assessment_evidence_str}'.")
    # --- END NEW RULE: "between X and Y" ---

    # --- Specific Rule 2: Trustee Name Comparison (for list of users/groups) ---
    if "trustee name:" in assessment_evidence_lower or "allow log on locally" in settings_checklist_value.lower() or "deny log on locally" in settings_checklist_value.lower():
        if debug_flag:
            print("    DEBUG: Applying Trustee Name comparison rule.")

        cimb_expected_trustees = set()
        if pd.notna(cimb_value) and isinstance(cimb_value, str):
            cimb_parts = re.split(r'[,;\n]\s*|\s+and\s+|\s+or\s+', cimb_value_lower)
            for part in cimb_parts:
                cleaned_part = part.strip()
                if cleaned_part and cleaned_part != 'not configured':
                    if cleaned_part == 'service':
                        cimb_expected_trustees.add('service')
                        cimb_expected_trustees.add('local service')
                        cimb_expected_trustees.add('network service')
                    else:
                        cimb_expected_trustees.add(cleaned_part)

        if debug_flag:
            print(f"      DEBUG: CIMB Expected Trustees: {cimb_expected_trustees}")

        extracted_trustee_names_from_evidence = set()
        normalized_evidence_trustees = set()

        evidence_parts = assessment_evidence_str.split(';')
        for part in evidence_parts:
            match = re.search(r'trustee name:\s*(.*)', part.strip(), re.IGNORECASE)
            if match:
                extracted_trustee = match.group(1).strip().lower()
                extracted_trustee_names_from_evidence.add(extracted_trustee)

                normalized_evidence_trustees.add(extracted_trustee)
                
                if extracted_trustee == r'mywwbp2ad01\administrators':
                    normalized_evidence_trustees.add('administrators')
                if extracted_trustee.startswith('iis apppool\\') or extracted_trustee.startswith('builtin\\'):
                    normalized_evidence_trustees.add('*system built-in iis apppool ids')
                elif extracted_trustee.startswith('mywbequitecapps\\'):
                    normalized_evidence_trustees.add('*sql built-in service id’s')

        if debug_flag:
            print(f"      DEBUG: Extracted Specific Trustees from Evidence: {extracted_trustee_names_from_evidence}")
            print(f"      DEBUG: Normalized Evidence Trustees (including generics): {normalized_evidence_trustees}")

        optional_trustee_ids = {'*sql built-in service id’s', '*system built-in iis apppool ids'}
        optional_trustee_ids_lower = {id.lower() for id in optional_trustee_ids}

        # IMPORTANT: Refined logic to ensure consistent boolean return
        is_configured = False # Default assumption for this rule

        if not cimb_expected_trustees:
            # If CIMB expects no trustees, and evidence shows 'not defined' (or similar absence)
            if "not configured" in cimb_value_lower and "not defined" in assessment_evidence_lower:
                if debug_flag:
                    print("        DEBUG: Trustee Rule: CIMB is 'not configured' and evidence is 'Not Defined'. Result: True.")
                return True # Consistent return type
            elif "not configured" in cimb_value_lower and "not defined" not in assessment_evidence_lower:
                 if debug_flag:
                    print("        DEBUG: Trustee Rule: CIMB is 'not configured' but evidence is NOT 'Not Defined'. Result: False.")
                 return False # Consistent return type
            elif not extracted_trustee_names_from_evidence: # If no CIMB expected and no evidence, it's configured (e.g. 'no one' expected, 'no entries found')
                 if debug_flag:
                    print("        DEBUG: Trustee Rule: CIMB expects no trustees, and no trustees found in evidence. Result: True.")
                 return True # Consistent return type
            else:
                 if debug_flag:
                    print("        DEBUG: Trustee Rule: CIMB expects no trustees, but trustees found in evidence. Result: False.")
                 return False # Consistent return type


        truly_missing_expected = set()
        for expected_trustee in cimb_expected_trustees:
            if expected_trustee not in normalized_evidence_trustees and expected_trustee not in optional_trustee_ids_lower:
                truly_missing_expected.add(expected_trustee)

        extra_in_evidence = set()
        for evidence_item in extracted_trustee_names_from_evidence:
            is_covered = False
            if evidence_item in cimb_expected_trustees:
                is_covered = True
            elif (evidence_item.startswith('iis apppool\\') or evidence_item.startswith('builtin\\')) and '*system built-in iis apppool ids' in cimb_expected_trustees:
                is_covered = True
            elif evidence_item.startswith('mywbequitecapps\\') and '*sql built-in service id’s' in cimb_expected_trustees:
                is_covered = True
            elif 'service' in cimb_expected_trustees and (evidence_item == 'local service' or evidence_item == 'network service'):
                is_covered = True
            elif 'local service' in cimb_expected_trustees and evidence_item == 'local service':
                is_covered = True
            elif 'network service' in cimb_expected_trustees and evidence_item == 'network service':
                is_covered = True
            elif evidence_item == r'mywwbp2ad01\administrators' and 'administrators' in cimb_expected_trustees:
                is_covered = True

            if not is_covered:
                extra_in_evidence.add(evidence_item)
        
        missing_optional_expected = (cimb_expected_trustees & optional_trustee_ids_lower) - normalized_evidence_trustees

        if not truly_missing_expected and not extra_in_evidence and not missing_optional_expected:
            is_configured = True # All good
            if debug_flag:
                print("        DEBUG: Trustee Rule: All required expected trustees are present, and no unexpected trustees in evidence. Result: True.")
        elif not truly_missing_expected and not extra_in_evidence and missing_optional_expected:
             is_configured = True # Optional items missing are okay for 'configured' status
             if debug_flag:
                 print(f"        DEBUG: Trustee Rule: All required expected trustees are present. Optional expected not found: {sorted(list(missing_optional_expected))}. Result: True.")
        else:
            is_configured = False # Something is wrong (missing required or extra)
            if debug_flag:
                explanation_parts = []
                if truly_missing_expected:
                    explanation_parts.append(f"Missing required expected: {sorted(list(truly_missing_expected))}. ")
                if extra_in_evidence:
                    explanation_parts.append(f"Unexpected in evidence: {sorted(list(extra_in_evidence))}. ")
                if missing_optional_expected:
                    explanation_parts.append(f"Optional expected not found: {sorted(list(missing_optional_expected))}. ")
                print(f"        DEBUG: Trustee Rule: Mismatch. {''.join(explanation_parts)}Result: False.")

        return is_configured # Consistent return type

    # --- END NEW TRUSTEE NAME RULE (Strict) ---

    # Priority 1: Exact string match
    if cimb_value_str == assessment_evidence_str:
        if debug_flag:
            print(f"    DEBUG: check_assessment_evidence: Exact string match. Returning True.")
        return True

    # Priority 2: Unit-aware numerical comparison
    cimb_seconds, cimb_is_min_value_required = convert_to_seconds(cimb_value_str, debug_flag)
    evidence_seconds, _ = convert_to_seconds(assessment_evidence_str, debug_flag)

    if cimb_seconds is not None and evidence_seconds is not None:
        if cimb_is_min_value_required:
            if evidence_seconds >= cimb_seconds:
                if debug_flag:
                    print(f"    DEBUG: check_assessment_evidence: Unit-aware numeric (CIMB 'or more') match. CIMB_Value ({cimb_value_str})={cimb_seconds}s, Evidence ({assessment_evidence_str})={evidence_seconds}s. Returning True.")
                return True
        else:
            if abs(cimb_seconds - evidence_seconds) < 1e-9:
                if debug_flag:
                    print(f"    DEBUG: check_assessment_evidence: Unit-aware numeric match. CIMB_Value ({cimb_value_str})={cimb_seconds}s, Evidence ({assessment_evidence_str})={evidence_seconds}s. Returning True.")
                return True
    
    # Priority 3: Generic numeric comparison
    try:
        is_cimb_numeric = re.fullmatch(r'-?\d+(\.\d+)?', cimb_value_str)
        is_evidence_numeric = re.fullmatch(r'-?\d+(\.\d+)?', assessment_evidence_str)

        if is_cimb_numeric and is_evidence_numeric:
            if float(cimb_value_str) == float(assessment_evidence_str):
                if debug_flag:
                    print(f"    DEBUG: check_assessment_evidence: Generic numeric match. Returning True.")
                return True
    except ValueError:
        pass

    # Priority 4: Case-insensitive substring containment
    # IMPORTANT: First, handle the empty cimb_value_lower case to prevent false positives.
    if not cimb_value_lower:
        if debug_flag:
            print(f"    DEBUG: check_assessment_evidence: cimb_value_lower is empty. Returning False for this check.")
        return False # An empty cimb_value should not match anything

    # Now, extract the relevant part of assessment_evidence_lower
    # We need to find the specific delimiter, which you mentioned is 'existence check'.
    # Let's use 'existence check::' for a more precise match, as seen in your examples.
    delimiter = 'existence check::'
    delimiter_index = assessment_evidence_lower.find(delimiter)

    relevant_evidence_part = ""
    if delimiter_index != -1: # If the delimiter is found
        # Start slicing after the delimiter and its length
        relevant_evidence_part = assessment_evidence_lower[delimiter_index + len(delimiter):].strip()
        if debug_flag:
            print(f"    DEBUG: Extracted relevant_evidence_part: '{relevant_evidence_part}'")
    else:
        # If 'existence check::' is not found, what should happen?
        # Based on your rule, if there's no 'existence check', then the substring
        # cannot be verified as present in the 'relevant' section.
        # So, we might consider this as not found for this specific check.
        if debug_flag:
            print(f"    DEBUG: Delimiter '{delimiter}' not found in assessment_evidence_lower.")
        # For this 'Priority 4' check, if the relevant section can't be identified,
        # it implies the condition for this priority cannot be met.
        # You might want to let other priorities handle it, or explicitly return False for this one.
        # For now, relevant_evidence_part will remain empty if not found,
        # which will correctly lead to 'cimb_value_lower in relevant_evidence_part' being False
        # (unless cimb_value_lower is also empty, which we've already handled).
        pass # Let the next 'if' statement handle it, it will evaluate to false if relevant_evidence_part is empty


    # Now perform the substring containment check on the extracted part
    if cimb_value_lower in relevant_evidence_part:
        if debug_flag:
            print(f"    DEBUG: check_assessment_evidence: Case-insensitive substring containment in relevant part.")
            print(f"        cimb_value_lower: '{cimb_value_lower}'")
            print(f"        relevant_evidence_part: '{relevant_evidence_part}'")
            print(f"        Returning True.")
        return True

# If neither the empty string, nor the substring in relevant part match, this check passes without a match.
# The function would then proceed to lower priority checks or eventually return False if no match is found.

    # Determine the part of assessment_evidence_lower to evaluate based on 'existence check::'
    part_to_check = assessment_evidence_lower
    if "existence check::" in assessment_evidence_lower:
        try:
            part_to_check = assessment_evidence_lower.split("existence check::", 1)[1].strip()
            if debug_flag:
                print(f"      DEBUG: check_assessment_evidence: Checking keywords in part after 'existence check::': '{part_to_check}'")
        except IndexError:
            # Fallback if split doesn't work as expected, though unlikely with 'in' check
            if debug_flag:
                print(f"      DEBUG: check_assessment_evidence: Could not split by 'existence check::'. Using full evidence for keywords.")

    # Priority 5: Keyword-based checks for common 'enabled'/'disabled' states
    enabled_keywords_for_evaluation = ['enabled', 'true', 'yes', 'set to 1', 'configured', 'present', 'pass', '1(?=[;\n]|$)']
    disabled_keywords_for_evaluation = ['disabled', 'false', 'set to 0', 'not configured', 'not present', '0(?=[;\n]|$)', 'not applicable', 'none', 'not defined', 'unrestricted', 'n/a']

    enabled_regex_components = [
        r'\bpass\b',
        r'\b1(?=[;\n]|$)', # This is already a specific regex pattern
        r'\btrue\b'
    ]

    disabled_regex_components = [
        r'\b0(?=[;\n]|$)', # This is already a specific regex pattern
        r'\bnot applicable\b',
        r'\bnone\b(?!\s*exist\b)', # Modified to ignore 'none exist',
        r'\bnot defined\b',
        r'\bunrestricted\b',
        r'\bn/a\b',
        r'\bfalse\b'
    ]

    # Combine the components into a single regex pattern using '|' (OR operator)
    final_enabled_regex_pattern = '|'.join(enabled_regex_components)
    final_disabled_regex_pattern = '|'.join(disabled_regex_components)

    is_cimb_value_enabled_like = cimb_value_lower in ['enabled', 'true', '1', 'yes']
    is_cimb_value_disabled_like = cimb_value_lower in ['disabled', 'false', '0', 'not required', 'no one', 'none', '']

    # --- START OF NEW SPECIAL CASE RULE FOR 18.10.81.2 and 18.10.92.2.1---
    if cis_rec_checklist_raw == '18.10.81.2' or cis_rec_checklist_raw == '18.10.92.2.1':
        # Condition 2: Check if the evidence contains an 'enabled-like' keyword
        if re.search(final_enabled_regex_pattern, part_to_check, re.IGNORECASE):
            if debug_flag:
                print(f"      DEBUG: SPECIAL CASE: CIS ID 18.10.81.2: CIMB 'Disabled' and evidence is 'enabled-like'. Returning True (configured).")
            return True # This specific condition makes it 'configured'
        elif debug_flag:
            print(f"      DEBUG: SPECIAL CASE: CIS ID 18.10.81.2: CIMB 'Disabled' but no 'enabled-like' evidence found. Return False")
        return False
    # --- END OF NEW SPECIAL CASE RULE ---
    
    # --- START OF NEW SPECIAL CASE RULE FOR 18.4.1 ---
    if cis_rec_checklist_raw == '18.4.1':
        # Condition 2: Check if the evidence contains an 'disabled-like' keyword
        if re.search(final_disabled_regex_pattern, part_to_check, re.IGNORECASE):
            if debug_flag:
                matched_text = re.search(final_disabled_regex_pattern, part_to_check, re.IGNORECASE).group(0)
                print(f"      DEBUG: SPECIAL CASE: CIS ID 18.4.1: CIMB 'Enabled' and evidence is 'disabled-like'. Returning True (configured).", matched_text)
            return True # This specific condition makes it 'configured'
        elif debug_flag:
            print(f"      DEBUG: SPECIAL CASE: CIS ID 18.4.1: CIMB 'Enabled' but no 'disabled-like' evidence found. Return False.")
        return False
    # --- END OF NEW SPECIAL CASE RULE ---

    if is_cimb_value_enabled_like:
        # Use re.search with re.IGNORECASE for case-insensitive matching
        if re.search(final_enabled_regex_pattern, part_to_check, re.IGNORECASE):
            if debug_flag:
                # re.search().group(0) gives the actual matched substring
                matched_text = re.search(final_enabled_regex_pattern, part_to_check, re.IGNORECASE).group(0)
                print(f"    DEBUG: Keyword check: CIMB value is enabled-like and found matching enabled keyword '{matched_text}' in evidence.")
            return True
            
    elif is_cimb_value_disabled_like:
        if re.search(final_disabled_regex_pattern, part_to_check, re.IGNORECASE):
            if debug_flag:
                matched_text = re.search(final_disabled_regex_pattern, part_to_check, re.IGNORECASE).group(0)
                print(f"    DEBUG: Keyword check: CIMB value is disabled-like and found matching disabled keyword '{matched_text}' in evidence.")
            return True
        
               # print(f"      DEBUG: check_assessment_evidence: CIMB Value is Disabled-like, '{part_to_check}' contains disabled keyword. Returning True.")
               # print(f"      DEBUG: Rule 14 (Keyword: CIMB Disabled-like, evidence contains disabled keyword). Returning True.")
               # print(f"        Keywords found: {[k for k in disabled_keywords_for_evaluation if k in part_to_check]}") # <-- THIS LINE IS CRITICAL
               # print(f"        relevant_evidence_chunk: '{part_to_check}'")
    
    # Inside your check_assessment_evidence function, for CIS Recommendation # 2.3.10.1:
    if cis_rec_checklist_raw == '2.3.10.1':
        # Find all occurrences of 'Result:' (ONLY single colon) followed by 'True', 'False', 'Pass', or 'Fail'.
        # The regex has been updated to specifically look for 'Result:' and exclude 'Result::'.
        all_results = re.findall(r'Result:\s*(true|false)(?:;|$)?', assessment_evidence_lower, re.IGNORECASE)

        if all_results:
            # Get the very last extracted result from the list of all matches.
            last_extracted_result = all_results[-1].lower()
            if debug_flag:
                print(f"      DEBUG: CIS ID 2.3.10.1 rule: All extracted results (only from 'Result:'): {all_results}. Last extracted Result: '{last_extracted_result}'.")

            # Apply the inverted logic:
            if last_extracted_result == 'false':
                if debug_flag:
                    print(f"      DEBUG: CIS ID 2.3.10.1 rule: Last Result (from 'Result:') is 'False' or 'Fail'. Returning True (configured).")
                return True # 'False' means CONFIGURED for this specific CIS ID
            elif last_extracted_result == 'true':
                if debug_flag:
                    print(f"      DEBUG: CIS ID 2.3.10.1 rule: Last Result (from 'Result:') is 'True' or 'Pass'. Returning False (not configured).")
                return False # 'True' means NOT CONFIGURED for this specific CIS ID
        elif debug_flag:
            print(f"      DEBUG: CIS ID 2.3.10.1 rule: Could not extract any 'Result: True/False' (from 'Result:'). Falling through to other rules for this CIS ID.")

def is_cis_rec_in_range_17_x_x(cis_rec):
    """
    Checks if a CIS Recommendation # is within the 17.x.x range.
    """
    if pd.isna(cis_rec):
        return False
    s = str(cis_rec).strip()
    match = re.match(r'17\.(\d+)\.(\d+)', s)
    if match:
        return True 
    return False


def process_security_reports(combined_cis_reports_file_path):
    """
    Main function to process security assessment reports from a 'Checklist'
    sheet within an Excel file and all IP sheets within a single
    'combined_cis_reports.xlsx' file, then export the combined results to a new Excel file.
    """
    print("\nStarting Security Report Processor (Step 2/3)...")

    # 2. Full path to the Excel file that contains the 'Checklist' sheet.
    checklist_excel_path = input("Please enter the full path to the excel file contain CIMB Checklist (e.g., C:\\path\\to\\Host Configuration Security Assessment-v1.0 (1).xlsx): ")
    # Strip any leading/trailing double quotes from the path
    checklist_excel_path = checklist_excel_path.strip('"')

    # --- Script Logic (DO NOT MODIFY BELOW THIS LINE unless debugging) ---

    # Validate if the combined_cis_reports Excel file exists and is valid
    if not os.path.exists(combined_cis_reports_file_path) or not (combined_cis_reports_file_path.endswith('.xlsx') or combined_cis_reports_file_path.endswith('.xls')):
        print(f"Error: 'combined_cis_reports.xlsx' file not found or not a valid Excel file: '{combined_cis_reports_file_path}'. Please ensure the file exists and update 'combined_cis_reports_file_path' in the script.")
        return None # Return None to indicate failure

    # Validate if the provided Checklist Excel file exists and is valid
    if not os.path.exists(checklist_excel_path) or not (checklist_excel_path.endswith('.xlsx') or checklist_excel_path.endswith('.xls')):
        print(f"Error: Checklist file not found or not a valid Excel file: '{checklist_excel_path}'. Please ensure the file exists and update 'checklist_excel_path' in the script.")
        return None # Return None to indicate failure

    try:
        # --- Load Checklist Data from Excel Sheet ---
        df_checklist = pd.read_excel(checklist_excel_path, sheet_name='Checklist')
        # Clean column names (strip whitespace)
        df_checklist.columns = df_checklist.columns.str.strip()
        print(f"Successfully loaded 'Checklist' sheet from '{checklist_excel_path}'")

        # Validate essential columns in the Checklist DataFrame
        checklist_required_cols = ['CIMB NO.', 'Settings', 'CIMB Value', 'CIS Recommendation #']
        if not all(col in df_checklist.columns for col in checklist_required_cols):
            missing_cols = [col for col in checklist_required_cols if col not in df_checklist.columns]
            print(f"Error: The 'Checklist' sheet is missing required columns: {', '.join(missing_cols)}. Please check the sheet and try again.")
            return None # Return None to indicate failure

        # --- Aggregate CIMB Value for rows with the same CIMB NO. and Settings ---
        # Create a temporary DataFrame for aggregation
        df_checklist_agg = df_checklist.groupby(['CIMB NO.', 'Settings'], as_index=False)['CIMB Value'].agg(
            lambda x: ', '.join(x.dropna().astype(str).tolist())
        ).rename(columns={'CIMB Value': 'CIMB Value Aggregated'})
        
        # Merge the aggregated CIMB Value back to the original checklist, keeping distinct rows based on CIMB NO. and Settings
        df_checklist_processed = pd.merge(
            df_checklist.drop_duplicates(subset=['CIMB NO.', 'Settings']),
            df_checklist_agg,
            on=['CIMB NO.', 'Settings'],
            how='left'
        )


        # --- Setup Output Excel File ---
        output_file_name = 'CIMB HA report.xlsx'
        
        if os.path.exists(output_file_name):
            try:
                os.remove(output_file_name)
                print(f"Removed existing '{output_file_name}' to create a fresh report.")
            except OSError as e:
                print(f"Error removing existing output file '{output_file_name}': {e}. "
                      "Please close the file if it's open and re-run the script.")
                return None # Return None to indicate failure

        writer = pd.ExcelWriter(output_file_name, engine='xlsxwriter')

        # --- Get all sheet names from the combined_cis_reports.xlsx file ---
        try:
            xls = pd.ExcelFile(combined_cis_reports_file_path)
            all_ip_sheet_names = xls.sheet_names
            print(f"\nSheets found in '{combined_cis_reports_file_path}': {all_ip_sheet_names}")
        except Exception as e:
            print(f"Error reading sheet names from '{combined_cis_reports_file_path}': {e}")
            writer.close()
            return None # Return None to indicate failure

        # --- Iterate over each IP sheet ---
        for ip_to_process in all_ip_sheet_names:
            print(f"\nAttempting to process sheet '{ip_to_process}' from '{combined_cis_reports_file_path}'")

            try: # This try block covers loading and processing of one IP sheet
                # Read the specific IP sheet from the combined_cis_reports.xlsx file
                df_ip_report = pd.read_excel(combined_cis_reports_file_path, sheet_name=ip_to_process)
                # Clean column names (strip whitespace)
                df_ip_report.columns = df_ip_report.columns.str.strip()
                print(f"Successfully loaded data for IP: {ip_to_process} from sheet '{ip_to_process}' in '{combined_cis_reports_file_path}'")

                # Validate essential columns in the IP report DataFrame
                ip_report_required_cols = ['CIS Recommendation #', 'Title', 'Recommended State', 'Assessment Evidence', 'Report Type']
                if not all(col in df_ip_report.columns for col in ip_report_required_cols):
                    missing_cols = [col for col in ip_report_required_cols if col not in df_ip_report.columns]
                    print(f"Skipping IP {ip_to_process}: The report sheet is missing required columns: {', '.join(missing_cols)}. "
                          "Please ensure the sheet structure is correct.")
                    continue # Skip to the next IP
                
                # --- Determine if it's a Domain Controller report for this IP ---
                is_domain_controller_for_ip = False
                if 'Report Type' in df_ip_report.columns:
                    # Check if 'Domain Controller' appears in any cell of the 'Report Type' column (case-insensitive)
                    report_type_values = df_ip_report['Report Type'].dropna().astype(str).tolist()
                    if any('domain controller' in val.lower() for val in report_type_values):
                        is_domain_controller_for_ip = True
                        #if should_print_detailed_debug: # should_print_detailed_debug is not defined here
                        print(f"    DEBUG: IP '{ip_to_process}' identified as a Domain Controller.")
                
                processed_rows_for_ip = []

                # --- LIMIT DEBUG OUTPUT FOR CONSOLE ---
                debug_output_count = 0 
                max_debug_output = 10 
                printed_limit_message = False
                # --- END LIMIT DEBUG OUTPUT ---

                for idx, row_checklist in df_checklist_processed.iterrows(): # Iterate over processed checklist
                    should_print_detailed_debug = debug_output_count < max_debug_output

                    if not should_print_detailed_debug and not printed_limit_message:
                        printed_limit_message = True


                    cimb_no = row_checklist['CIMB NO.']
                    settings_checklist = str(row_checklist['Settings']).strip()
                    cimb_value_aggregated = row_checklist['CIMB Value Aggregated'] # Use the aggregated CIMB Value
                    cis_rec_checklist_raw = str(row_checklist['CIS Recommendation #']).strip()
                    
                    # --- NEW LOGIC: Override CIS Recommendation # for Domain Controllers (CIMB 2.2.7) ---
                    # This must happen BEFORE cleaned_cis_rec_checklist is calculated and used
                    if is_domain_controller_for_ip and cimb_no == '2.2.7':
                        if should_print_detailed_debug:
                            print(f"    DEBUG: Overriding CIS Recommendation # for CIMB NO. {cimb_no} (DC report) from '{cis_rec_checklist_raw}' to '2.2.7'.")
                        cis_rec_checklist_raw = '2.2.7'
                        
                    if is_domain_controller_for_ip and cimb_no == '2.2.7':
                        if should_print_detailed_debug:
                            print(f"    DEBUG: Overriding CIS Recommendation # for CIMB NO. {cimb_no} (DC report) from '{cis_rec_checklist_raw}' to '2.2.7'.")
                        cis_rec_checklist_raw = '2.2.7'
                    
                    cleaned_cis_rec_checklist = clean_cis_recommendation_id(cis_rec_checklist_raw) 
                    found_match_for_checklist_item = False
        
                    # --- END NEW LOGIC ---
                    
                    # --- Hardcode 'Manual Grab' for specific CIMB NOs and ranges ---
                    is_manual_grab = False
                    cimb_no_str = str(cimb_no).strip()
                    if cimb_no_str in ['2.1.2', '2.3.3.1', '3.2.2', '5.1.1.1', '5.1.1.2', '5.1.1.3']:
                        is_manual_grab = True
                    elif cimb_no_str.startswith('6.'):
                        is_manual_grab = True
                    elif cimb_no_str.startswith('7.'):
                        is_manual_grab = True

                    if is_manual_grab:
                        current_status = 'Manual Grab'
                        found_match_for_checklist_item = True # Mark as found to ensure it's added
                        # We don't need to search df_ip_report for these, so we can skip the inner loop
                        processed_rows_for_ip.append({
                            'CIMB NO.': cimb_no,
                            'Settings': settings_checklist,
                            'CIMB Value': cimb_value_aggregated,
                            'CIS Recommendation # (Checklist)': cis_rec_checklist_raw, 
                            'CIS Recommendation # (IP Report)': None, 
                            'Cleaned CIS Recommendation # (Checklist)': cleaned_cis_rec_checklist, 
                            'Cleaned CIS Recommendation # (IP Report)': None, 
                            'Title': None,
                            'Recommended State': None,
                            'Assessment Evidence': None, 
                            'Report Type': None,
                            'Current': current_status
                        })
                    
                    # You might want to adjust this specific debug condition or remove it for general processing
                    # if str(cimb_no) == '1.1.6': 
                    #     should_print_detailed_debug = True
                    # else:
                    #     should_print_detailed_debug = debug_output_count < max_debug_output
                    
                    
                    is_checklist_cis_rec_valid = not pd.isna(row_checklist['CIS Recommendation #']) and \
                                                 cis_rec_checklist_raw.lower() != 'nan' and \
                                                 cis_rec_checklist_raw != ''

                    is_cis_17_x_x_range = is_cis_rec_in_range_17_x_x(cleaned_cis_rec_checklist)


                    for _, row_ip in df_ip_report.iterrows():
                        cis_rec_ip_raw = str(row_ip['CIS Recommendation #']).strip()
                        cleaned_cis_rec_ip = clean_cis_recommendation_id(cis_rec_ip_raw) 
                        title_ip = str(row_ip['Title']).strip()
                        recommended_state_ip = row_ip['Recommended State']
                        assessment_evidence_ip = row_ip['Assessment Evidence'] 
                        report_type_ip = str(row_ip['Report Type']).strip()

                        # --- Matching Criteria between Checklist and IP Report Rows ---

                        # 1. Match 'CIS Recommendation #'
                        cis_recommendation_match = False

                        if is_checklist_cis_rec_valid:
                            # Check original string for '(Domain controller only)' specific phrase
                            if '(Domain controller only)' in cis_rec_checklist_raw:
                                if report_type_ip.lower() == 'domain controller' and cleaned_cis_rec_checklist == cleaned_cis_rec_ip:
                                    cis_recommendation_match = True
                            elif cleaned_cis_rec_checklist == cleaned_cis_rec_ip:
                                cis_recommendation_match = True
                        else:
                            cis_recommendation_match = True

                        # 2. Match 'Settings' (Checklist) vs 'Title' (IP Report)
                        settings_title_similarity_match = False
                        
                        if is_cis_17_x_x_range: 
                            settings_title_similarity_match = True
                        else:
                            len_settings = len(settings_checklist)
                            len_title = len(title_ip)
                            compare_length = min(len_settings, len_title, 30)
                            
                            if compare_length > 0 and settings_checklist[:compare_length].lower() == title_ip[:compare_length].lower():
                                settings_title_similarity_match = True
                            elif settings_checklist.lower() == title_ip.lower():
                                settings_title_similarity_match = True

                        if cis_recommendation_match and settings_title_similarity_match:
                            final_cimb_value_for_output = cimb_value_aggregated # *** NOW USING AGGREGATED VALUE ***
                            current_status = 'Configured' if check_assessment_evidence(
                                final_cimb_value_for_output, assessment_evidence_ip, settings_checklist, title_ip, cis_rec_checklist_raw, should_print_detailed_debug
                            ) else 'Not Configured'

                            processed_rows_for_ip.append({
                                'CIMB NO.': cimb_no,
                                'Settings': settings_checklist,
                                'CIMB Value': final_cimb_value_for_output, # *** NOW STORING AGGREGATED VALUE ***
                                'CIS Recommendation # (Checklist)': cis_rec_checklist_raw, 
                                'CIS Recommendation # (IP Report)': cis_rec_ip_raw, 
                                'Cleaned CIS Recommendation # (Checklist)': cleaned_cis_rec_checklist, 
                                'Cleaned CIS Recommendation # (IP Report)': cleaned_cis_rec_ip, 
                                'Title': title_ip,
                                'Recommended State': recommended_state_ip,
                                'Assessment Evidence': assessment_evidence_ip,
                                'Report Type': report_type_ip,
                                'Current': current_status
                            })
                            found_match_for_checklist_item = True
                            break 

                    if not found_match_for_checklist_item:
                        #if should_print_detailed_debug:
                            #print(f"DEBUG: No match found for Checklist Item '{cimb_no}' (CIS Rec: '{cis_rec_checklist_raw}', Settings: '{settings_checklist}') in IP Report '{ip_to_process}'.")
                        
                        current_status_no_match = 'Not Configured'
                        processed_rows_for_ip.append({
                            'CIMB NO.': cimb_no,
                            'Settings': settings_checklist,
                            'CIMB Value': cimb_value_aggregated, # *** ENSURE AGGREGATED VALUE IS USED EVEN IF NO MATCH ***
                            'CIS Recommendation # (Checklist)': cis_rec_checklist_raw, 
                            'CIS Recommendation # (IP Report)': None, 
                            'Cleaned CIS Recommendation # (Checklist)': cleaned_cis_rec_checklist, 
                            'Cleaned CIS Recommendation # (IP Report)': None, 
                            'Title': None,
                            'Recommended State': None,
                            'Assessment Evidence': None, 
                            'Report Type': None,
                            'Current': current_status_no_match
                        })
                    
                    debug_output_count += 1

                df_output_ip = pd.DataFrame(processed_rows_for_ip)

                output_columns_order = [
                    'CIMB NO.', 'Settings', 'CIMB Value', 
                    'CIS Recommendation # (Checklist)', 'Cleaned CIS Recommendation # (Checklist)',
                    'CIS Recommendation # (IP Report)', 'Cleaned CIS Recommendation # (IP Report)',
                    'Title', 'Recommended State', 'Assessment Evidence', 'Report Type', 'Current'
                ]

                for col in output_columns_order:
                    if col not in df_output_ip.columns:
                        df_output_ip[col] = None

                df_output_ip = df_output_ip[output_columns_order]

                for col in df_output_ip.columns:
                    #Only fillna for non-CIMB Value columns, to preserve potential explicit 'None' or empty string
                    if col != 'CIMB Value': 
                        df_output_ip[col] = df_output_ip[col].fillna('N/A')
                
                df_output_ip.to_excel(writer, sheet_name=ip_to_process, index=False)
                print(f"Successfully processed and added sheet for {ip_to_process} to '{output_file_name}'")

            except FileNotFoundError:
                print(f"Error: The 'combined_cis_reports.xlsx' file was not found at '{combined_cis_reports_file_path}'. Please verify the path.")
            except KeyError as ke:
                print(f"Error processing IP '{ip_to_process}': Missing expected column or sheet issue: {ke}. Skipping this IP.")
            except pd.errors.EmptyDataError:
                print(f"Error: The IP report sheet for {ip_to_process} is empty or malformed in '{combined_cis_reports_file_path}'. Skipping this IP.")
            except Exception as e:
                print(f"An unexpected error occurred while processing IP report for {ip_to_process}: {e}. Skipping this IP.")

        writer.close()
        print(f"\nProcessing complete! The combined report is saved to '{output_file_name}'")
        return output_file_name # Return the path to the generated file

    except FileNotFoundError:
        print("Error: The Checklist Excel file was not found at the specified path. Please verify the path.")
    except KeyError:
        print(f"Error: The 'Checklist' sheet was not found in the Excel file '{checklist_excel_path}'. Please ensure the sheet exists and is named 'Checklist'.")
    except pd.errors.EmptyDataError:
        print(f"Error: The 'Checklist' sheet in '{checklist_excel_path}' is empty or malformed.")
    except Exception as e:
        print(f"An unexpected error occurred during the overall process: {e}")
    return None # Return None to indicate failure


def clean_text(text):
    """
    Cleans text by removing specific artifacts and normalizing whitespace.
    Handles non-string inputs robustly.
    """
    if isinstance(text, float):
        if pd.isna(text):
            return ""
        else:
            text = str(text)

    s = str(text)
    if not s.strip() or s.lower() == 'nan' or s.lower() == 'none':
        return ""

    try:
        # Replace _x000D_ with an empty string ('')
        s = s.replace('_x000D_', '')
        s = s.strip() # Still strip overall leading/trailing whitespace
        return s
    except Exception as e:
        return ""

def extract_numerical_prefix(text):
    """
    Extracts the leading numerical prefix from a string.
    e.g., "6.10 Set 'Recovery console..." -> "6.10"
    """
    if not isinstance(text, str):
        return ""
    s = text.strip()
    # Match a sequence of digits and dots, optionally followed by space/comma/semicolon/dash
    # This captures the numerical part like '6.10'
    match = re.match(r"^\s*(\d+(\.\d+)*)\s*(?:[.,;:\-—]\s*)?", s) # Added non-capturing group for separator
    return match.group(1).strip() if match else ""

def create_fuzzy_text_key(text):
    """
    Standardizes text for matching by removing specific prefixes, suffixes, and normalizing.
    This aims to create a 'core' setting string for lookup, explicitly preserving
    content within parentheses for better distinction. It also explicitly removes
    any leading numbering, as that will be handled by extract_numerical_prefix.
    """
    if not isinstance(text, str):
        return ""

    s = clean_text(text) # Use existing clean_text for initial cleaning (removes _x000D_, strips)
    s = s.replace('\n', ' ').replace('\r', ' ') # Ensure newlines become spaces for key creation
    s = re.sub(r'\s{2,}', ' ', s).strip() # Normalize whitespace

    # 1. Remove leading numbering (if any) and any separators following it
    s = re.sub(r"^\s*\d+(\.\d+)*\s*(?:[.,;:\-—]\s*)?", "", s).strip()
    s = re.sub(r'\s{2,}', ' ', s).strip() # Re-normalize spaces after removal

    # 2. Explicitly extract text within the first set of parentheses, and remove from main text temporarily
    parentheses_content = ""
    match_paren = re.search(r'\((.*?)\)', s)
    if match_paren:
        parentheses_content = match_paren.group(1).strip()
        # Replace the full matched parenthesis content with a space to avoid issues, then strip
        s = s.replace(match_paren.group(0), ' ').strip()
        s = re.sub(r'\s{2,}', ' ', s).strip() # Re-normalize spaces after removal

    # 3. Apply the rest of the cleaning to the remaining_text
    match_quoted = re.search(r"['“‘](.*?)[’”']", s)
    if match_quoted:
        core_text = match_quoted.group(1).strip()
    else:
        # This list of leading phrases to remove is tuned based on observed CIMB key behavior.
        core_text = re.sub(r"^(?:configure|ensure|set|enable|disable|turn on|check|verify)\s*", "", s, flags=re.IGNORECASE).strip()

    # 4. Remove common state suffixes (e.g., ": Enabled", "to: Disabled", or just "Enabled")
    core_text = re.sub(r'(?:\s*[:.]?\s*(?:enabled|disabled|not configured|configured|pass|fail|completed|installation|installed|true|false|yes|no))\s*$', '', core_text, flags=re.IGNORECASE).strip()

    # 5. Remove 'to:' or 'is:' at the end if it's left over (common in "Set X to:" or "Ensure X is:")
    core_text = re.sub(r'\s*(?:to|is):?\s*$', '', core_text, flags=re.IGNORECASE).strip()

    # 6. Remove specific common phrases that are not part of the core setting (e.g., "(PAM)", "Installation")
    core_text = re.sub(r'\s*\(pam\)\s*$', '', core_text, flags=re.IGNORECASE).strip()
    core_text = re.sub(r'\s*\(av/am\)\s*$', '', core_text, flags=re.IGNORECASE).strip()
    core_text = re.sub(r'\s*\(edr\)\s*$', '', core_text, flags=re.IGNORECASE).strip()
    core_text = re.sub(r'installation\s*$', '', core_text, flags=re.IGNORECASE).strip()
    core_text = re.sub(r'security baseline\s*$', '', core_text, flags=re.IGNORECASE).strip()

    # General cleanup for core text: replace non-alphanumeric (except space) with space, then normalize
    core_text = re.sub(r'[^a-zA-Z0-9\s]', ' ', core_text).strip()
    core_text = re.sub(r'\s{2,}', ' ', core_text).strip()

    # 7. Assemble the final key for the text part
    final_key_parts = []
    final_key_parts.append(core_text)

    if parentheses_content:
        # Clean the parentheses_content separately to ensure it's standardized
        parentheses_content_cleaned = re.sub(r'[^a-zA-Z0-9\s]', ' ', parentheses_content).strip()
        parentheses_content_cleaned = re.sub(r'\s{2,}', ' ', parentheses_content_cleaned).strip()
        if parentheses_content_cleaned: # Only append if it's not empty after cleaning
            final_key_parts.append("(" + parentheses_content_cleaned + ")")

    final_key = " ".join(part for part in final_key_parts if part).strip()
    return final_key.lower()

def generate_consolidated_report_from_excel(
    cimb_ha_excel_file,
    cimb_ha_sheet_names,
    host_config_template_excel,
    host_config_template_sheet_name,
    output_filename="final_report_by_ip.xlsx"
):
    print(f"\nLoading host configuration template from: {host_config_template_excel}, Sheet: {host_config_template_sheet_name}")
    try:
        template_df = pd.read_excel(
            host_config_template_excel,
            sheet_name=host_config_template_sheet_name,
            header=1,
            dtype={'Settings': str, 'Description': str, 'Value': str},
            engine='openpyxl'
        )
        template_df['Description_Clean'] = template_df['Description'].apply(clean_text)
        template_df['Original_Setting_Raw'] = template_df['Settings'].astype(str).replace(np.nan, "").apply(clean_text)
        
        # Extract numerical prefix for template
        template_df['Numerical_Prefix_Template'] = template_df['Settings'].apply(extract_numerical_prefix)
        # Create fuzzy text key for template, ensuring numbers are removed
        template_df['Fuzzy_Text_Key_Template'] = template_df['Settings'].apply(create_fuzzy_text_key)

        template_df['Recommended_Value_Template'] = template_df['Value'].apply(clean_text)

        template_map = {}
        for idx, row in template_df.iterrows():
            # Composite key for template_map: (Numerical Prefix, Fuzzy Text Key)
            composite_key = (row['Numerical_Prefix_Template'], row['Fuzzy_Text_Key_Template'])
            
            # Ensure at least one part of the composite key is not empty
            if not composite_key[0] and not composite_key[1]:
                continue # Skip if both parts are empty

            entry_data = {
                'original_setting': row['Original_Setting_Raw'],
                'description': row['Description_Clean'] if pd.notna(row['Description_Clean']) else "",
                'recommended_value': row['Recommended_Value_Template'],
                'numerical_prefix': row['Numerical_Prefix_Template'] # Store numerical prefix in entry_data too
            }

            # If there are multiple entries for the exact same composite key in the template,
            # this indicates an ambiguity in the template itself. Concatenate information.
            if composite_key not in template_map:
                template_map[composite_key] = entry_data
            else:
                # Merge information if composite key already exists (e.g., duplicate entries in template)
                existing_entry = template_map[composite_key]
                if entry_data['original_setting'] and entry_data['original_setting'] not in existing_entry['original_setting']:
                    existing_entry['original_setting'] += " | " + entry_data['original_setting']
                if entry_data['description'] and entry_data['description'] not in existing_entry['description']:
                    existing_entry['description'] += " | " + entry_data['description']
                if entry_data['recommended_value'] and entry_data['recommended_value'] not in existing_entry['recommended_value']:
                    existing_entry['recommended_value'] += " | " + entry_data['recommended_value']
        print("Host configuration template loaded and processed.")
    except Exception as e:
        print(f"Error loading or processing host configuration template: {e}")
        raise

    results_by_sheet = {}
    final_columns = ['No.', 'Settings', 'Description', 'Recommended Value', 'Current Configuration']

    col_indices = {col: i for i, col in enumerate(final_columns)}

    column_widths = {
        'No.': 19.89,
        'Settings': 48.89,
        'Description': 69.22,
        'Recommended Value': 33.33,
        'Current Configuration': 38.11
    }

    print(f"Loading CIMB HA reports from Excel file: {cimb_ha_excel_file}")

    for sheet_name in cimb_ha_sheet_names:
        try:
            ip_address = sheet_name
            print(f"\nProcessing sheet (IP): {ip_address} from {cimb_ha_excel_file}")

            cimb_df = pd.read_excel(
                cimb_ha_excel_file,
                sheet_name=sheet_name,
                header=0,
                dtype={'Settings': str, 'Current': str, 'Recommended State': str, 'Report Type': str, 'CIMB NO.': str},
                engine='openpyxl'
            )
            if 'Settings' not in cimb_df.columns or 'Current' not in cimb_df.columns:
                print(f"Warning: Sheet '{ip_address}' from '{cimb_ha_excel_file}' is missing 'Settings' or 'Current' column. Skipping.")
                continue
            if 'Recommended State' not in cimb_df.columns:
                cimb_df['Recommended State'] = ''
            
            # Ensure 'CIMB NO.' column exists for keying
            if 'CIMB NO.' not in cimb_df.columns:
                print(f"Warning: Sheet '{ip_address}' is missing 'CIMB NO.' column. This column is essential for matching. Please ensure it is present or the matching might be inaccurate. Attempting to extract from 'Settings' as fallback.")
                cimb_df['CIMB NO.'] = cimb_df['Settings'].apply(extract_numerical_prefix) # Fallback if missing

            cimb_df['Numerical_Prefix_CIMB'] = cimb_df['CIMB NO.'].astype(str).replace(np.nan, "").apply(clean_text)
            cimb_df['Fuzzy_Text_Key_CIMB'] = cimb_df['Settings'].apply(create_fuzzy_text_key)
            
            not_configured_or_manual_df = cimb_df[
                cimb_df['Current'].astype(str).str.strip().str.lower().isin(['not configured', 'manual grab'])
            ].copy()

            # Hardcoded rule: Remove '3.2.2' if its status is 'Not Configured'
            # This means if '3.2.2' appears as 'Not Configured', it will be dropped.
            # If '3.2.2' appears as 'Manual Grab', it will be kept.
            initial_count_322_not_configured = not_configured_or_manual_df[
                (not_configured_or_manual_df['CIMB NO.'] == '3.2.2') & 
                (not_configured_or_manual_df['Current'].astype(str).str.lower() == 'not configured')
            ].shape[0]

            not_configured_or_manual_df = not_configured_or_manual_df[
                ~((not_configured_or_manual_df['CIMB NO.'] == '3.2.2') & 
                  (not_configured_or_manual_df['Current'].astype(str).str.lower() == 'not configured'))
            ].copy()
            
            report_type = ""
            # Assuming 'Report Type' is a single value for the sheet, find it from a non-empty cell
            if 'Report Type' in cimb_df.columns and not cimb_df['Report Type'].empty:
                # Find the first non-NaN, non-empty string value in the 'Report Type' column
                report_type_series = cimb_df['Report Type'].dropna().astype(str)
                if not report_type_series.empty:
                    report_type = report_type_series.iloc[0].strip()
            print(f"Report Type for sheet '{ip_address}': '{report_type}'")

            if not not_configured_or_manual_df.empty:
                print(f"DEBUG: Found {len(not_configured_or_manual_df)} 'Not Configured' and 'Manual Grab' items in sheet '{ip_address}'.")

                current_sheet_two_row_data = []
                row_number = 1
                for index, row in not_configured_or_manual_df.iterrows():
                    # For filtering, we still use the fuzzy text key, as the (Domain Controller only) is embedded there
                    fuzzy_key_for_filtering = row['Fuzzy_Text_Key_CIMB']
                    should_include = False

                    # Determine if the setting has a specific DC or MS qualifier
                    is_dc_setting = '(domain controller only)' in fuzzy_key_for_filtering
                    is_ms_setting = '(member servers only)' in fuzzy_key_for_filtering

                    # Apply inclusion logic based on report type and setting qualifiers
                    if report_type.lower() == 'domain controller':
                        # For a DC report, include DC specific settings OR general settings
                        if is_dc_setting or (not is_dc_setting and not is_ms_setting):
                            should_include = True
                        else:
                            print(f"Skipping setting for Domain Controller '{ip_address}' due to specific type mismatch: {row.get('Settings')}")
                    elif report_type.lower() == 'member server':
                        # For an MS report, include MS specific settings OR general settings
                        if is_ms_setting or (not is_dc_setting and not is_ms_setting):
                            should_include = True
                        else:
                            print(f"Skipping setting for Member Server '{ip_address}' due to specific type mismatch: {row.get('Settings')}")
                    else: # Handle cases where report_type is not clearly 'domain controller' or 'member server'
                        # If report type is ambiguous, default to including only general settings (no explicit DC/MS qualifier)
                        if not is_dc_setting and not is_ms_setting:
                            should_include = True
                        else:
                            print(f"Skipping specific setting for unknown report type '{report_type}' at '{ip_address}': {row.get('Settings')}")

                    # DEBUG: Print the decision for each row
                    print(f"DEBUG: Processing '{row.get('Settings', 'N/A')}' (CIMB NO: '{row.get('CIMB NO.', 'N/A')}', Fuzzy Key: '{fuzzy_key_for_filtering}'). Report Type: '{report_type}'. IsDC: {is_dc_setting}, IsMS: {is_ms_setting}. Should Include: {should_include}.")


                    if not should_include:
                        continue # Skip to the next row if the item should not be included

                    # Create the composite lookup key using numerical prefix and fuzzy text key
                    lookup_key = (row['Numerical_Prefix_CIMB'], row['Fuzzy_Text_Key_CIMB'])
                    template_info = template_map.get(lookup_key, {})

                    description = template_info.get('description', "Description not found in template")

                    # Prioritize output_setting from template_info if a match was found.
                    if template_info:
                        output_setting = template_info.get('original_setting', '')
                        print(f"DEBUG: Match found for '{lookup_key}'. Using template setting: '{output_setting}'")
                    else:
                        # If no template match, use CIMB HA report's setting, but clean it first
                        raw_cimb_setting = row.get('Settings', '')
                        output_setting = clean_text(raw_cimb_setting) # Apply clean_text here
                        print(f"DEBUG: No template match found for '{lookup_key}'. Using CIMB setting: '{output_setting}'")

                    recommended_value_from_template = template_info.get('recommended_value', '')

                    # Row 1 (Odd Row)
                    row_1_data = {
                        'No.': row_number,
                        'Settings': output_setting,
                        'Description': description,
                        'Recommended Value': recommended_value_from_template,
                        'Current Configuration': row.get('Current', '')
                    }
                    current_sheet_two_row_data.append(row_1_data)

                    # Row 2 (Even Row) - for structural padding for merging
                    row_2_data = {
                        'No.': '',
                        'Settings': '',
                        'Description': '',
                        'Recommended Value': '',
                        'Current Configuration': ''
                    }
                    current_sheet_two_row_data.append(row_2_data)

                    row_number += 1

                if current_sheet_two_row_data:
                    sheet_df = pd.DataFrame(current_sheet_two_row_data, columns=final_columns)
                    results_by_sheet[ip_address] = sheet_df
                else:
                    print(f"DEBUG: No relevant 'Not Configured' items found for sheet '{ip_address}' after filtering. This sheet will not be in the final report.")
            else:
                print(f"DEBUG: No 'Not Configured' items found in sheet '{ip_address}'. This sheet will not be in the final report.")

        except Exception as e:
            print(f"Error processing CIMB HA Excel sheet '{sheet_name}' in file '{cimb_ha_excel_file}': {e}")
            traceback.print_exc()
            continue

    if results_by_sheet:
        logo_path = input("Please enter the full path to the LGMS logo image (e.g., C:\\path\\to\\logo.png): ")
        logo_path = logo_path.strip('"')

        if not os.path.exists(logo_path):
            print(f"Error: Logo image not found at '{logo_path}'. Exiting.")
            sys.exit(1)

        print(f"\nSaving consolidated report to {output_filename} with multiple sheets...")
        try:
            with pd.ExcelWriter(output_filename, engine='xlsxwriter') as writer:
                for sheet_name, df in results_by_sheet.items():
                    sanitized_sheet_name = re.sub(r'[\\/?*\[\]:]', '_', sheet_name)
                    sanitized_sheet_name = sanitized_sheet_name[:31]

                    workbook  = writer.book
                    worksheet = workbook.add_worksheet(sanitized_sheet_name)

                    observations_format = workbook.add_format({
                        'bold': True, 'italic': True, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#4F81BD', 'border': 1
                    })
                    to_be_determined_no_border_format = workbook.add_format({
                        'align': 'left', 'valign': 'top', 'font_size': 12, 'italic': True
                    })
                    results_data_no_border_format = workbook.add_format({
                        'align': 'left', 'valign': 'top', 'font_size': 12
                    })
                    results_data_no_border_format2 = workbook.add_format({
                        'align': 'right', 'valign': 'top', 'font_size': 12
                    })
                    default_text_format = workbook.add_format({
                        'align': 'left', 'valign': 'top', 'border': 1
                    })
                    header_format = workbook.add_format({
                        'bold': True, 'align': 'left', 'valign': 'top', 'bg_color': '#4F81BD', 'border': 1
                    })
                    results_header_format = workbook.add_format({
                        'bold': True, 'align': 'right', 'valign': 'top', 'font_size': 12, 'underline': True,
                    })
                    header_bg_color = '#000000'
                    header_bg_format = workbook.add_format({'bg_color': header_bg_color})

                    for col_name, width in column_widths.items():
                        col_idx = col_indices[col_name]
                        worksheet.set_column(col_idx, col_idx, width)

                    for r in range(0, 9):
                        for c in range(0, 5):
                            worksheet.write(r, c, None, header_bg_format)
                    for c in range(0, 5):
                        worksheet.write(9, c, None, header_bg_format)

                    worksheet.set_row(0, 30)
                    worksheet.set_row(1, 30)
                    worksheet.set_row(2, 25)
                    worksheet.set_row(3, 25)
                    worksheet.set_row(4, 25)
                    worksheet.set_row(5, 25)
                    worksheet.set_row(6, 10)
                    worksheet.set_row(7, 10)
                    worksheet.set_row(8, 30)
                    worksheet.set_row(9, 10)

                    image_height_cm = 3.47
                    image_width_cm = 9.06
                    image_height_pixels = round((image_height_cm / 2.54) * 96)
                    image_width_pixels = round((image_width_cm / 2.54) * 96)

                    worksheet.insert_image(2, 0, logo_path, {
                        'x_offset': 5, 'y_offset': 5, 'width': image_width_pixels, 'height': image_height_pixels, 'object_position': 1
                    })

                    worksheet.merge_range(0, 2, 1, 4, 'CIMB Securities Sdn Bhd', workbook.add_format({'bold': True, 'font_size': 28, 'font_color': '#FFFFFF', 'bg_color': header_bg_color, 'align': 'left', 'valign': 'vcenter'}))
                    worksheet.merge_range(2, 2, 3, 4, 'Host Configuration Review Security Assessment Quick Result', workbook.add_format({'font_size': 20, 'font_color': '#FFFFFF', 'bg_color': header_bg_color, 'align': 'left', 'valign': 'vcenter'}))
                    worksheet.merge_range(4, 2, 5, 4, '(Initial Assessment - Windows Server 2022 Std)', workbook.add_format({'font_size': 20, 'font_color': '#FFFFFF', 'bg_color': header_bg_color, 'align': 'left', 'valign': 'vcenter'}))
                    worksheet.merge_range(6, 2, 7, 4, '', workbook.add_format({'bg_color': header_bg_color}))
                    worksheet.merge_range(8, 2, 8, 4, 'CONFIDENTIAL', workbook.add_format({'font_size': 24, 'font_color': '#FF0000', 'bg_color': header_bg_color, 'bold': True, 'align': 'left', 'valign': 'vcenter'}))

                    worksheet.write(10, 0, 'Results', results_header_format)
                    worksheet.write(11, 0, 'Target:', results_data_no_border_format2)
                    worksheet.write(11, 1, 'Windows Server 2022 Std', results_data_no_border_format)
                    worksheet.write(12, 0, 'Compliance Checklist:', results_data_no_border_format2)
                    worksheet.write(12, 1, 'CIMB Microsoft Windows Server Security Baseline v1.0', results_data_no_border_format)
                    worksheet.write(13, 0, 'Start Date:', results_data_no_border_format2)
                    worksheet.write(13, 1, '9 May 2025', results_data_no_border_format)
                    worksheet.write(14, 0, 'End Date:', results_data_no_border_format2)
                    worksheet.write(14, 1, 'To be determined', to_be_determined_no_border_format)

                    worksheet.merge_range(17, 0, 17, len(final_columns) - 1, 'Observations', observations_format)
                    for col_num, value in enumerate(final_columns):
                        worksheet.write(18, col_num, value, header_format)

                    data_start_row_excel = 19
                    for i in range(0, len(df), 2):
                        current_logical_row_data = df.iloc[i]
                        excel_data_row_start = data_start_row_excel + i
                        excel_data_row_end = data_start_row_excel + i + 1
                        for col_name in final_columns:
                            col_idx = col_indices[col_name]
                            cell_value = current_logical_row_data[col_name]
                            worksheet.merge_range(
                                excel_data_row_start, col_idx,
                                excel_data_row_end, col_idx,
                                cell_value,
                                default_text_format
                            )
            print(f"Consolidated report saved to {output_filename}")
        except Exception as e:
            print(f"Error saving Excel file for sheet '{sanitized_sheet_name}': {e}")
            traceback.print_exc()
    else:
        print("\nNo 'Not Configured' items found across all reports. No output file generated.")

# --- Main execution block for cisreport.py (modified to be a function) ---
def run_cis_report_parser():
    output_excel_file = "combined_cis_reports.xlsx"
    file_paths = []

    print("Starting CIS HTML Report Parser (Step 1/3)...")
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
        return None # Return None to indicate failure
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
            return output_excel_file # Return the path to the generated file

        except Exception as e:
            print(f"An error occurred while creating or writing to the Excel file: {e}.")
            return None # Return None to indicate failure

# --- Main execution block for reportdesigner.py (modified to be a function) ---
def run_report_designer(cimb_ha_report_excel_file):
    print("\nStarting Consolidated Report Designer (Step 3/3)...")
    try:
        xl = pd.ExcelFile(cimb_ha_report_excel_file, engine='openpyxl')
        cimb_ha_sheet_names_list = xl.sheet_names
    except Exception as e:
        print(f"Error reading sheet names from '{cimb_ha_report_excel_file}': {e}")
        sys.exit(1)

    host_template_excel = input("Please enter the full path to the Host Configuration Report Template.xlsx (e.g., C:\\path\\to\\Host Configuration Report Template.xlsx): ")
    host_template_excel = host_template_excel.strip('"')
    host_template_sheet_name = 'Sheet3'

    generate_consolidated_report_from_excel(
        cimb_ha_report_excel_file,
        cimb_ha_sheet_names_list,
        host_template_excel,
        host_template_sheet_name,
        "CIMB HA Report_Final.xlsx"
    )

# --- Main execution flow for the combined script ---
if __name__ == "__main__":
    # Step 1: Parse CIS HTML Reports
    combined_cis_reports_path = run_cis_report_parser()

    if combined_cis_reports_path:
        # Step 2: Generate CIMB HA Report
        cimb_ha_report_path = process_security_reports(combined_cis_reports_path)

        if cimb_ha_report_path:
            # Step 3: Design Consolidated Report
            run_report_designer(cimb_ha_report_path)
        else:
            print("\nSkipping report design due to an error in generating CIMB HA Report.")
    else:
        print("\nSkipping further steps due to an error in parsing CIS HTML Reports.")
