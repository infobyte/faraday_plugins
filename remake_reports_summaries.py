import os
from pathlib import Path

for plugin_folder in os.listdir('./report-collection/faraday_plugins_tests'):

    summaries_to_remake = []

    for filename in os.listdir(f'./report-collection/faraday_plugins_tests/{plugin_folder}'):
        if filename.endswith('_summary.json'):
            report_file_name = filename.replace('_summary.json', '')
            summaries_to_remake.append(report_file_name)

    for filename in os.listdir(f'./report-collection/faraday_plugins_tests/{plugin_folder}'):
        filename_no_ext = Path(filename).stem

        if filename_no_ext in summaries_to_remake:
            # execute os command
            print(f"Creating summary for {filename}")

            os.system(f'faraday-plugins process-report --summary -drh "./report-collection/faraday_plugins_tests/{plugin_folder}/{filename}" > "./report-collection/faraday_plugins_tests/{plugin_folder}/{filename_no_ext}_summary.json"')