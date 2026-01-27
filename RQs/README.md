- common_failure_patterns.json: Failure patterns analysis for `Figure 5 Classification and distribution of failure patterns.`
- cwe_mapping.json: CWE classification for `Table 7. Accuracy on Different CWE Categories`
- semantic_patterns.json: semantic classification of patches for `Table 6. Accuracy Across Different Semantic Complexity and Categories` 
- patch/function size.pkl: For `Figure 3. Accuracy Across Different Function and Patch Size`
    - Format of `function_size.pkl`
    ```json
    [
        {
            'project': 'curl',
            'cve_id': 'CVE-2019-5435',
            'commit': '5fc28510a466',
            'function': 'curl_url_set',
            'basic_blocks': 42,
            'binary_file': 'CVE-2019-5435-patch-5fc28510a466-curl'
        },
    ...
    ]
    ```
    - Format of `patch_size.pkl`
    ```json
    [
        {
            'project': 'curl',
            'cve_id': 'CVE-2019-5435',
            'commit': '5fc28510a466',
            'functions': 'curl_url_set,seturl',
            'c_files_count': 1,
            'total_added_lines': 5,
            'total_removed_lines': 2,
            'total_changed_lines': 7,
            'file_details': [
                {
                    'file_path': 'lib/url.c',
                    'added': 5,
                    'removed': 2,
                    'total': 7,
                    'is_added_file': False,
                    'is_removed_file': False,
                    'is_modified_file': True
                }
            ]
        },
        ...
    ]
    ```