import pandas as pd
import os
import re
import numpy as np
import traceback
import sys

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
    print(f"Loading host configuration template from: {host_config_template_excel}, Sheet: {host_config_template_sheet_name}")
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
            
            not_configured_df = cimb_df[
                cimb_df['Current'].astype(str).str.strip().str.lower() == 'not configured'
            ].copy()

            # DEBUG: Print initial 'not configured' items to verify presence at this stage
            print(f"DEBUG: 'Not Configured' items before specific type filtering for {ip_address}:\n{not_configured_df[['CIMB NO.', 'Settings', 'Current', 'Fuzzy_Text_Key_CIMB']].head(10)}")

            report_type = ""
            # Assuming 'Report Type' is a single value for the sheet, find it from a non-empty cell
            if 'Report Type' in cimb_df.columns and not cimb_df['Report Type'].empty:
                # Find the first non-NaN, non-empty string value in the 'Report Type' column
                report_type_series = cimb_df['Report Type'].dropna().astype(str)
                if not report_type_series.empty:
                    report_type = report_type_series.iloc[0].strip()
            print(f"Report Type for sheet '{ip_address}': '{report_type}'")

            if not not_configured_df.empty:
                print(f"DEBUG: Found {len(not_configured_df)} 'not configured' items in sheet '{ip_address}'.")

                current_sheet_two_row_data = []
                row_number = 1
                for index, row in not_configured_df.iterrows():
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
                    print(f"DEBUG: No relevant 'not configured' items found for sheet '{ip_address}' after filtering. This sheet will not be in the final report.")
            else:
                print(f"DEBUG: No 'not configured' items found in sheet '{ip_address}'. This sheet will not be in the final report.")

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
                    worksheet.write(12, 1, 'CIMB Microsoft Windows Server Security Baseline', results_data_no_border_format)
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
        print("\nNo 'not configured' items found across all reports. No output file generated.")

# --- How to call the modified function ---

cimb_ha_report_excel_file = input("Please enter the full path to the CIMB HA report.xlsx (e.g., C:\\path\\to\\CIMB HA report.xlsx): ")
cimb_ha_report_excel_file = cimb_ha_report_excel_file.strip('"')
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
