import pandas as pd
import numpy as np
import re
import os

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


def process_security_reports():
    """
    Main function to process security assessment reports from a 'Checklist'
    sheet within an Excel file and all IP sheets within a single
    'combined_cis_reports.xlsx' file, then export the combined results to a new Excel file.
    """
    print("Welcome to the Security Report Processor!")

    # --- USER CONFIGURATION: EDIT THESE THREE LINES WITH YOUR PATHS ---
    # 1. Full path to the single 'combined_cis_reports.xlsx' file.
    #    Example: r"C:\Users\Intern 15\Downloads\combined_cis_reports.xlsx"
    # Prompt user for logo path before starting Excel writing
    combined_cis_reports_file_path = input("Please enter the full path to the combined_cis_reports.xlsx (e.g., C:\\path\\to\\combined_cis_reports.xlsx): ")
    # Strip any leading/trailing double quotes from the path
    combined_cis_reports_file_path = combined_cis_reports_file_path.strip('"')

    # 2. Full path to the Excel file that contains the 'Checklist' sheet.
    checklist_excel_path = input("Please enter the full path to the excel file contain CIMB Checklist (e.g., C:\\path\\to\\Host Configuration Security Assessment-v1.0 (1).xlsx): ")
    # Strip any leading/trailing double quotes from the path
    checklist_excel_path = checklist_excel_path.strip('"')

    # Removed: ip_to_process, as we will iterate through all sheets
    # --- END OF USER CONFIGURATION ---


    # --- Script Logic (DO NOT MODIFY BELOW THIS LINE unless debugging) ---

    # Validate if the combined_cis_reports Excel file exists and is valid
    if not os.path.exists(combined_cis_reports_file_path) or not (combined_cis_reports_file_path.endswith('.xlsx') or combined_cis_reports_file_path.endswith('.xls')):
        print(f"Error: 'combined_cis_reports.xlsx' file not found or not a valid Excel file: '{combined_cis_reports_file_path}'. Please ensure the file exists and update 'combined_cis_reports_file_path' in the script.")
        return

    # Validate if the provided Checklist Excel file exists and is valid
    if not os.path.exists(checklist_excel_path) or not (checklist_excel_path.endswith('.xlsx') or checklist_excel_path.endswith('.xls')):
        print(f"Error: Checklist file not found or not a valid Excel file: '{checklist_excel_path}'. Please ensure the file exists and update 'checklist_excel_path' in the script.")
        return

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
            return

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
                return

        writer = pd.ExcelWriter(output_file_name, engine='xlsxwriter')

        # --- Get all sheet names from the combined_cis_reports.xlsx file ---
        try:
            xls = pd.ExcelFile(combined_cis_reports_file_path)
            all_ip_sheet_names = xls.sheet_names
            print(f"\nSheets found in '{combined_cis_reports_file_path}': {all_ip_sheet_names}")
        except Exception as e:
            print(f"Error reading sheet names from '{combined_cis_reports_file_path}': {e}")
            writer.close()
            return

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
                        if should_print_detailed_debug:
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
                            current_status = 'configured' if check_assessment_evidence(
                                final_cimb_value_for_output, assessment_evidence_ip, settings_checklist, title_ip, cis_rec_checklist_raw, should_print_detailed_debug
                            ) else 'not configured'

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
                        
                        current_status_no_match = 'not configured'
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

    except FileNotFoundError:
        print("Error: The Checklist Excel file was not found at the specified path. Please verify the path.")
    except KeyError:
        print(f"Error: The 'Checklist' sheet was not found in the Excel file '{checklist_excel_path}'. Please ensure the sheet exists and is named 'Checklist'.")
    except pd.errors.EmptyDataError:
        print(f"Error: The 'Checklist' sheet in '{checklist_excel_path}' is empty or malformed.")
    except Exception as e:
        print(f"An unexpected error occurred during the overall process: {e}")

# Call the main function to start the script
process_security_reports()
