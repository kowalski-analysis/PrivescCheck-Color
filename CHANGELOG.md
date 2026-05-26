# Changelog

## 1.0.0 -- 2026-05-26

Initial release.

### Added

- ANSI severity-colored terminal output (Red / Yellow / Cyan / Green)
- Inline sensitive-string highlighting (Magenta) for exploitable privilege names,
  credential keywords, high-value identity strings, and writable system paths
- `-SeverityFilter` parameter: suppress output below a specified severity level
- Color-coded summary at end of scan with per-severity counts and named list of
  High and Medium findings
- `-NoColor` switch for plain-text output when redirecting or logging
- `-NoLogo` switch to suppress the header block
- `-SourceScript` parameter to load a specific local or remote PrivescCheck.ps1
- Auto-load fallback: checks session scope, local directory, then downloads from
  GitHub releases URL
- Full parameter pass-through to Invoke-PrivescCheck
- Auto-run when the script is executed directly rather than dot-sourced
- PowerShell 2.0 compatibility maintained throughout

### Notes

- All detection logic is unchanged from PrivescCheck by @itm4n
- Function override approach (global scope) means no source patching required;
  compatible with future PrivescCheck releases without modification
