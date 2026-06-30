# @summary Ensure the OpenSCAP toolchain + SCAP Security Guide content on nodes
#   scanned by vuln_scan::oscap (OVAL CVEs) or vuln_scan::oscap_xccdf (CIS/STIG).
#
# Classify your OpenSCAP target nodes with this class so the scans "just work":
# the oscap scanner, decompression tools (bzip2 / xz, for compressed OVAL feeds),
# and the SCAP Security Guide content (datastreams under
# /usr/share/xml/scap/ssg/content) are all present. Defaults are chosen per OS
# family; override the package lists for distros that name them differently.
#
# @param manage_content    Install the SCAP Security Guide content packages.
# @param scanner_packages  Override the scanner package list (per-OS default otherwise).
# @param content_packages  Override the SSG content package list.
# @param package_ensure    Ensure value applied to every package.
#
# @example Classify OpenSCAP targets
#   include vuln_scan::oscap_prereqs
class vuln_scan::oscap_prereqs (
  Boolean                 $manage_content   = true,
  Optional[Array[String]] $scanner_packages = undef,
  Optional[Array[String]] $content_packages = undef,
  String                  $package_ensure   = 'installed',
) {
  $defaults = $facts['os']['family'] ? {
    'Debian' => {
      'scanner'  => ['libopenscap8'],
      'compress' => ['bzip2', 'xz-utils'],
      'content'  => ['ssg-base', 'ssg-debderived'],
    },
    'RedHat' => {
      'scanner'  => ['openscap-scanner'],
      'compress' => ['bzip2', 'xz'],
      'content'  => ['scap-security-guide'],
    },
    default => { 'scanner' => [], 'compress' => [], 'content' => [] },
  }

  $scanner = $scanner_packages ? { undef => $defaults['scanner'], default => $scanner_packages }
  $content = $manage_content ? {
    true    => ($content_packages ? { undef => $defaults['content'], default => $content_packages }),
    default => [],
  }
  $packages = $scanner + $defaults['compress'] + $content

  if $packages == [] {
    notify { "vuln_scan::oscap_prereqs: unsupported OS family '${facts['os']['family']}' — set scanner_packages/content_packages explicitly": }
  } else {
    package { $packages:
      ensure => $package_ensure,
    }
  }
}
