# @summary Installs the Trivy binary (Linux and Windows).
#
# Private class — managed via the main `vuln_scan` class. Idempotent: when
# `version` is 'latest' the binary is installed only if missing; when pinned,
# the install re-runs only if the installed version differs.
class vuln_scan::install {
  assert_private()

  $version    = $vuln_scan::version
  $is_latest  = $version == 'latest'

  case $facts['kernel'] {
    'Linux': {
      $dir = $vuln_scan::linux_install_dir
      $bin = "${dir}/trivy"

      if $vuln_scan::manage_dependencies {
        package { 'curl':
          ensure => present,
          before => Exec['vuln_scan install trivy'],
        }
      }

      # `latest` -> guard on the binary existing; pinned -> guard on version.
      $creates = $is_latest ? { true => $bin, default => undef }
      $unless  = $is_latest ? {
        true    => undef,
        default => "${bin} --version 2>/dev/null | grep -qF '${version}'",
      }

      exec { 'vuln_scan install trivy':
        command  => "curl -sfL '${vuln_scan::linux_install_script_url}' | sh -s -- -b '${dir}' ${version}",
        path     => ['/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'],
        provider => 'shell',
        creates  => $creates,
        unless   => $unless,
        timeout  => 600,
      }
    }

    'windows': {
      $dir = $vuln_scan::windows_install_dir
      $bin = "${dir}\\trivy.exe"

      file { 'C:/ProgramData/vuln_scan':
        ensure => directory,
      }

      # Render the install script with the chosen version + target dir.
      file { 'C:/ProgramData/vuln_scan/install_trivy.ps1':
        ensure  => file,
        content => epp('vuln_scan/install_trivy.ps1.epp', {
          'version'      => $version,
          'install_dir'  => $dir,
          'download_base'=> $vuln_scan::windows_download_base,
        }),
        require => File['C:/ProgramData/vuln_scan'],
      }

      $creates = $is_latest ? { true => $bin, default => undef }
      $unless  = $is_latest ? {
        true    => undef,
        default => "cmd.exe /c \"\"${bin}\" --version | findstr /C:\"${version}\"\"",
      }

      exec { 'vuln_scan install trivy':
        command => 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\ProgramData\\vuln_scan\\install_trivy.ps1"',
        creates => $creates,
        unless  => $unless,
        timeout => 600,
        require => File['C:/ProgramData/vuln_scan/install_trivy.ps1'],
      }
    }

    default: {
      fail("vuln_scan: unsupported kernel '${facts['kernel']}'. Supported: Linux, windows.")
    }
  }
}
