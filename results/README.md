# pkl file format:
- Root: A dictionary where keys are project names (e.g., "binutils").
- Level 1 (CVE): Inside each project, keys are CVE IDs (e.g., "CVE-2014-8484").
- Level 2 (Version): Map version strings (e.g., "2.24") to analysis results.
- Level 3 (Function): Map function names (e.g., "srec_scan") to detailed results.
- Level 4 (Results): Contains result (detection output like "V", "P" or Failure Messgae), truth (ground truth "-1" or "1"), and status (classification like "TP", "TN", "FP", "FN", "fail test" or "fail gen").
Example:
```json
{
    "binutils": {
        "CVE-2014-8484": {
            "2.24": {
                "srec_scan": {
                    "result": "V",
                    "truth": "-1",
                    "status": "TN"
                }
            }
        }
    }
}
```