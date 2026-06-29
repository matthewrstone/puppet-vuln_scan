# @summary Installs Trivy and provides the PVS vulnerability scan task.
#
# Apply this class to any node you want PVS to scan via the orchestrator. It
# installs the Trivy binary on Linux and Windows so the `vuln_scan::trivy` task
# can run. The module has no external module dependencies.
#
# @param version
#   Trivy version to install. Use 'latest' or a pinned version like '0.58.1'.
#   When pinned, the install is re-run if the installed version differs.
# @param manage_install
#   Whether this class manages the Trivy installation.
# @param linux_install_dir
#   Directory the trivy binary is placed in on Linux (should be on PATH).
# @param windows_install_dir
#   Directory trivy.exe is installed to on Windows (added to the system PATH).
# @param manage_dependencies
#   On Linux, install the prerequisite (curl) used to fetch Trivy.
# @param linux_install_script_url
#   URL of the Trivy install script. Override for air-gapped/mirrored installs.
# @param windows_download_base
#   Base URL for Windows release zips. Override for an internal mirror.
#
# @example Install the latest Trivy
#   include vuln_scan
#
# @example Pin a version
#   class { 'vuln_scan': version => '0.58.1' }
class vuln_scan (
  String[1] $version                  = 'latest',
  Boolean   $manage_install           = true,
  String[1] $linux_install_dir        = '/usr/local/bin',
  String[1] $windows_install_dir      = 'C:\\Program Files\\trivy',
  Boolean   $manage_dependencies      = false,
  String[1] $linux_install_script_url = 'https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh',
  String[1] $windows_download_base    = 'https://github.com/aquasecurity/trivy/releases/download',
) {
  if $manage_install {
    contain vuln_scan::install
  }
}
