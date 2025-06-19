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
        # Replace _x000D_ with a newline character (\n)
        s = s.replace('_x000D_', '')
        s = s.strip() # Still strip overall leading/trailing whitespace
        return s
    except Exception as e:
        return ""

def create_standardized_key(text):
    """
    Standardizes text for matching by removing specific prefixes, suffixes, and normalizing.
    This aims to create a 'core' setting string for lookup.
    """
    if not isinstance(text, str):
        return ""

    s = str(text) # Ensure it's a string for initial processing
    if not s.strip() or s.lower() == 'nan' or s.lower() == 'none':
        return ""

    try:
        s = s.replace('\n', ' ').replace('\r', ' ').replace('_x000D_', ' ') # Still replace with space for key generation
        s = re.sub(r'\s{2,}', ' ', s)
        s = s.strip()
    except Exception as e:
        return "" # Return empty string on error

    cleaned_text = s # Use the aggressively cleaned string for key generation

    # Handle the middle dot '·' which acts as a separator in some template entries
    cleaned_text = cleaned_text.replace('·', ' ')

    # 1. Remove numbering like "1.1.1. ", "6.17 ", etc. at the beginning.
    cleaned_text = re.sub(r"^\s*(\d+(\.\d+)*(\.|\s|,|,|;|\-)*)+\s*", "", cleaned_text).strip()

    # 2. Extract content within quotes if present. If not, remove common leading verbs/phrases.
    match_quoted = re.search(r"['“‘](.*?)[’”']", cleaned_text)
    if match_quoted:
        cleaned_text = match_quoted.group(1).strip()
    else:
        # This list of leading phrases to remove is tuned based on observed CIMB key behavior.
        cleaned_text = re.sub(r"^(?:configure|ensure|set|enable|disable|turn on|check|verify)\s*", "", cleaned_text, flags=re.IGNORECASE).strip()

    # 3. Remove common state suffixes (e.g., ": Enabled", "to: Disabled", or just "Enabled")
    cleaned_text = re.sub(r'(?:\s*[:.]?\s*(?:enabled|disabled|not configured|configured|pass|fail|completed|installation|installed|true|false|yes|no))\s*$', '', cleaned_text, flags=re.IGNORECASE).strip()

    # 4. Remove 'to:' or 'is:' at the end if it's left over (common in "Set X to:" or "Ensure X is:")
    cleaned_text = re.sub(r'\s*(?:to|is):?\s*$', '', cleaned_text, flags=re.IGNORECASE).strip()

    # 5. Remove specific common phrases that are not part of the core setting (e.g., "(PAM)", "Installation")
    cleaned_text = re.sub(r'\s*\(pam\)\s*$', '', cleaned_text, flags=re.IGNORECASE).strip()
    cleaned_text = re.sub(r'\s*\(av/am\)\s*$', '', cleaned_text, flags=re.IGNORECASE).strip()
    cleaned_text = re.sub(r'\s*\(edr\)\s*$', '', cleaned_text, flags=re.IGNORECASE).strip()
    cleaned_text = re.sub(r'installation\s*$', '', cleaned_text, flags=re.IGNORECASE).strip()
    cleaned_text = re.sub(r'security baseline\s*$', '', cleaned_text, flags=re.IGNORECASE).strip()

    # 6. Aggressive punctuation removal (except for space) and final space/case normalization
    cleaned_text = re.sub(r'[^a-zA-Z0-9\s]', '', cleaned_text).strip()
    cleaned_text = re.sub(r'\s{2,}', ' ', cleaned_text).strip()

    return cleaned_text.lower()


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
            engine='openpyxl' # ADDED: Specify engine for template
        )
        template_df['Description_Clean'] = template_df['Description'].apply(clean_text)
        template_df['Original_Setting_Raw'] = template_df['Settings'].astype(str).replace(np.nan, "").apply(clean_text)
        template_df['Matching_Key'] = template_df['Settings'].apply(create_standardized_key)
        template_df['Recommended_Value_Template'] = template_df['Value'].apply(clean_text)

        template_map = {}
        for idx, row in template_df.iterrows():
            matching_key = row['Matching_Key']
            if not matching_key:
                continue
            description_for_map = row['Description_Clean'] if pd.notna(row['Description_Clean']) else ""
            original_setting_for_map = row['Original_Setting_Raw']
            recommended_value_for_map = row['Recommended_Value_Template']

            if matching_key not in template_map:
                template_map[matching_key] = {
                    'description': description_for_map,
                    'original_setting': original_setting_for_map,
                    'recommended_value': recommended_value_for_map
                }
            else:
                current_description = template_map[matching_key]['description']
                current_original_setting = template_map[matching_key]['original_setting']
                current_recommended_value = template_map[matching_key]['recommended_value']
                if original_setting_for_map and original_setting_for_map not in current_original_setting:
                     template_map[matching_key]['original_setting'] = current_original_setting + " | " + original_setting_for_map
                if description_for_map and description_for_map not in current_description:
                    template_map[matching_key]['description'] = current_description + " | " + description_for_map
                if recommended_value_for_map and recommended_value_for_map not in current_recommended_value:
                     template_map[matching_key]['recommended_value'] = current_recommended_value + " | " + recommended_value_for_map
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
                dtype={'Settings': str, 'Current': str, 'Recommended State': str},
                engine='openpyxl' # ADDED: Specify engine for CIMB HA report sheets
            )
            if 'Settings' not in cimb_df.columns or 'Current' not in cimb_df.columns:
                print(f"Warning: Sheet '{ip_address}' from '{cimb_ha_excel_file}' is missing 'Settings' or 'Current' column. Skipping.")
                continue
            if 'Recommended State' not in cimb_df.columns:
                cimb_df['Recommended State'] = ''

            cimb_df['Matching_Key'] = cimb_df['Settings'].apply(create_standardized_key)

            not_configured_df = cimb_df[
                cimb_df['Current'].astype(str).str.strip().str.lower() == 'not configured'
            ].copy()

            if not not_configured_df.empty:
                print(f"DEBUG: Found {len(not_configured_df)} 'not configured' items in sheet '{ip_address}'.")

                current_sheet_two_row_data = []
                row_number = 1
                for index, row in not_configured_df.iterrows():
                    matching_key = row['Matching_Key']
                    template_info = template_map.get(matching_key, {})

                    description = template_info.get('description', "Description not found in template")
                    output_setting = template_info.get('original_setting', row.get('Settings', ''))
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

                sheet_df = pd.DataFrame(current_sheet_two_row_data, columns=final_columns)
                results_by_sheet[ip_address] = sheet_df
            else:
                print(f"DEBUG: No 'not configured' items found in sheet '{ip_address}'. This sheet will not be in the final report.")

        except Exception as e:
            print(f"Error processing CIMB HA Excel sheet '{sheet_name}' in file '{cimb_ha_excel_file}': {e}")
            continue

    if results_by_sheet:
        # Prompt user for logo path before starting Excel writing
        logo_path = input("Please enter the full path to the LGMS logo image (e.g., C:\\path\\to\\logo.png): ")
        # Strip any leading/trailing double quotes from the path
        logo_path = logo_path.strip('"')

        if not os.path.exists(logo_path):
            print(f"Error: Logo image not found at '{logo_path}'. Exiting.")
            sys.exit(1) # Exit if logo not found

        print(f"\nSaving consolidated report to {output_filename} with multiple sheets...")
        try:
            with pd.ExcelWriter(output_filename, engine='xlsxwriter') as writer:
                for sheet_name, df in results_by_sheet.items():
                    sanitized_sheet_name = re.sub(r'[\\/?*\[\]:]', '_', sheet_name)
                    sanitized_sheet_name = sanitized_sheet_name[:31]

                    workbook  = writer.book
                    worksheet = workbook.add_worksheet(sanitized_sheet_name)

                    # Define formats
                    observations_format = workbook.add_format({
                        'bold': True,
                        'italic': True,
                        'align': 'center',
                        'valign': 'vcenter',
                        'bg_color': '#4F81BD',
                        'border': 1
                    })

                    # New format for "Results" data that should NOT have borders
                    to_be_determined_no_border_format = workbook.add_format({
                        'align': 'left',
                        'valign': 'top',
                        'font_size': 12,
                        'italic': True
                    })

                    results_data_no_border_format = workbook.add_format({
                        'align': 'left',
                        'valign': 'top',
                        'font_size': 12
                    })

                    results_data_no_border_format2 = workbook.add_format({
                        'align': 'right',
                        'valign': 'top',
                        'font_size': 12
                    })

                    # Original default text format, now correctly applied only to the main data table
                    default_text_format = workbook.add_format({
                        'align': 'left',
                        'valign': 'top',
                        'border': 1
                    })

                    header_format = workbook.add_format({
                        'bold': True,
                        'align': 'left',
                        'valign': 'top',
                        'bg_color': '#4F81BD',
                        'border': 1
                    })

                    results_header_format = workbook.add_format({
                        'bold': True,
                        'align': 'right',
                        'valign': 'top',
                        'font_size': 12,
                        'underline': True,
                    })

                    header_bg_color = '#000000'
                    header_bg_format = workbook.add_format({'bg_color': header_bg_color})


                    # Set column widths BEFORE writing content to ensure cells fit
                    for col_name, width in column_widths.items():
                        col_idx = col_indices[col_name]
                        worksheet.set_column(col_idx, col_idx, width)

                    # Explicitly fill cells with the header_bg_color (now from Excel row 1 to 10, Python 0 to 9)
                    for r in range(0, 9): # Rows 0 to 8 (Excel 1 to 9). Total 9 rows. CONFIDENTIAL is at Excel 9
                        for c in range(0, 5): # Columns 0 to 4 (Excel A to E)
                            worksheet.write(r, c, None, header_bg_format)

                    # Also fill row 9 (Excel 10) for the blank row below CONFIDENTIAL for consistency
                    for c in range(0, 5):
                        worksheet.write(9, c, None, header_bg_format)


                    # --- Set row heights for the header rows (now starting from Python row 0, Excel row 1) ---
                    worksheet.set_row(0, 30) # For CIMB Securities (part 1 of merge, Excel 1)
                    worksheet.set_row(1, 30) # For CIMB Securities (part 2 of merge, Excel 2)
                    worksheet.set_row(2, 25) # For Host Configuration (part 1 of merge, Excel 3)
                    worksheet.set_row(3, 25) # For Host Configuration (part 2 of merge, Excel 4)
                    worksheet.set_row(4, 25) # For Initial Assessment (part 1 of merge, Excel 5)
                    worksheet.set_row(5, 25) # For Initial Assessment (part 2 of merge, Excel 6)
                    worksheet.set_row(6, 10) # Empty row (Excel 7)
                    worksheet.set_row(7, 10) # Empty row (Excel 8)
                    worksheet.set_row(8, 30) # For CONFIDENTIAL (Excel 9)
                    worksheet.set_row(9, 10) # Empty row below CONFIDENTIAL (Excel 10)


                    # --- Add Header content (now starting from Python row 0, Excel row 1) ---
                    # Insert LGMS Logo (A1 equivalent)
                    image_height_cm = 3.47
                    image_width_cm = 9.06
                    image_height_pixels = round((image_height_cm / 2.54) * 96)
                    image_width_pixels = round((image_width_cm / 2.54) * 96)

                    worksheet.insert_image(2, 0, logo_path, { # Now at row index 0 (Excel row 1)
                        'x_offset': 5,
                        'y_offset': 5,
                        'width': image_width_pixels,
                        'height': image_height_pixels,
                        'object_position': 1
                    })

                    # Text content using merged cells with CENTER alignment - Adjusted merge ranges
                    worksheet.merge_range(0, 2, 1, 4, 'CIMB Securities Sdn Bhd', workbook.add_format({'bold': True, 'font_size': 28, 'font_color': '#FFFFFF', 'bg_color': header_bg_color, 'align': 'left', 'valign': 'vcenter'})) # Merged Excel rows 1 and 2
                    worksheet.merge_range(2, 2, 3, 4, 'Host Configuration Review Security Assessment Quick Result', workbook.add_format({'font_size': 20, 'font_color': '#FFFFFF', 'bg_color': header_bg_color, 'align': 'left', 'valign': 'vcenter'})) # Merged Excel rows 3 and 4
                    worksheet.merge_range(4, 2, 5, 4, '(Initial Assessment - Windows Server 2022 Std)', workbook.add_format({'font_size': 20, 'font_color': '#FFFFFF', 'bg_color': header_bg_color, 'align': 'left', 'valign': 'vcenter'})) # Merged Excel rows 5 and 6
                    worksheet.merge_range(6, 2, 7, 4, '', workbook.add_format({'bg_color': header_bg_color})) # Merged Excel rows 7 and 8 (blank lines)
                    worksheet.merge_range(8, 2, 8, 4, 'CONFIDENTIAL', workbook.add_format({'font_size': 24, 'font_color': '#FF0000', 'bg_color': header_bg_color, 'bold': True, 'align': 'left', 'valign': 'vcenter'})) # Now in Excel row 9


                    # --- Add content from row 11 to 15 (Excel rows 11-15) ---
                    # Row 11: "Results" (merged across A and B)
                    worksheet.write(10, 0, 'Results', results_header_format) # Excel row 11

                    # Row 12: Target
                    worksheet.write(11, 0, 'Target:', results_data_no_border_format2) # Excel row 12, Column A
                    worksheet.write(11, 1, 'Windows Server 2022 Std', results_data_no_border_format) # Excel row 12, Column B

                    # Row 13: Compliance Checklist
                    worksheet.write(12, 0, 'Compliance Checklist:', results_data_no_border_format2) # Excel row 13, Column A
                    worksheet.write(12, 1, 'CIMB Microsoft Windows Server Security Baseline', results_data_no_border_format) # Excel row 13, Column B

                    # Row 14: Start Date
                    worksheet.write(13, 0, 'Start Date:', results_data_no_border_format2) # Excel row 14, Column A
                    worksheet.write(13, 1, '9 May 2025', results_data_no_border_format) # Excel row 14, Column B

                    # Row 15: End Date
                    worksheet.write(14, 0, 'End Date:', results_data_no_border_format2) # Excel row 15, Column A
                    worksheet.write(14, 1, 'To be determined', to_be_determined_no_border_format) # Excel row 15, Column B
                    # --- End of new content ---


                    # Merge and center 'Observations' (Excel row 18) - Now with border
                    worksheet.merge_range(17, 0, 17, len(final_columns) - 1, 'Observations', observations_format)

                    # Write column headers in row 19 (Excel row 19) - Now with border
                    for col_num, value in enumerate(final_columns):
                        worksheet.write(18, col_num, value, header_format)

                    # START: Explicitly write data and apply merges
                    # Data now starts from Excel row 20 (index 19)
                    data_start_row_excel = 19

                    # Iterate through the DataFrame to write each logical entry (which spans 2 physical rows)
                    for i in range(0, len(df), 2):
                        current_logical_row_data = df.iloc[i] # This is the row containing the actual data

                        # Calculate actual Excel rows for this logical item
                        excel_data_row_start = data_start_row_excel + i
                        excel_data_row_end = data_start_row_excel + i + 1

                        # Loop through all final columns to merge and write data - Now using default_text_format with border
                        for col_name in final_columns:
                            col_idx = col_indices[col_name]
                            cell_value = current_logical_row_data[col_name]

                            worksheet.merge_range(
                                excel_data_row_start, col_idx,
                                excel_data_row_end, col_idx,
                                cell_value, # Pass the actual value from the first row of the logical entry
                                default_text_format
                            )
                    # END: Explicitly write data and apply merges

            print(f"Consolidated report saved to {output_filename}")
        except Exception as e:
            print(f"Error saving Excel file for sheet '{sanitized_sheet_name}': {e}")
            traceback.print_exc()
    else:
        print("\nNo 'not configured' items found across all reports. No output file generated.")

# --- How to call the modified function ---

cimb_ha_report_excel_file = input("Please enter the full path to the CIMB HA report.xlsx (e.g., C:\\path\\to\\CIMB HA report.xlsx): ")
# Strip any leading/trailing double quotes from the path
cimb_ha_report_excel_file = cimb_ha_report_excel_file.strip('"')
# Dynamically get all sheet names from the Excel file
try:
    # Explicitly specify the engine as 'openpyxl' for reading sheet names
    xl = pd.ExcelFile(cimb_ha_report_excel_file, engine='openpyxl')
    cimb_ha_sheet_names_list = xl.sheet_names
except Exception as e:
    print(f"Error reading sheet names from '{cimb_ha_report_excel_file}': {e}")
    sys.exit(1) # Exit if cannot read sheet names

host_template_excel = input("Please enter the full path to the Host Configuration Report Template.xlsx (e.g., C:\\path\\to\\Host Configuration Report Template.xlsx): ")
# Strip any leading/trailing double quotes from the path
host_template_excel = host_template_excel.strip('"')
host_template_sheet_name = 'Sheet3'

generate_consolidated_report_from_excel(
    cimb_ha_report_excel_file,
    cimb_ha_sheet_names_list, # Now passing the dynamically obtained list
    host_template_excel,
    host_template_sheet_name,
    "CIMB HA Report_Final.xlsx"
)