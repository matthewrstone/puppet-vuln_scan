# DEPRECATED — not an active task implementation.
#
# The orchestrator executed this file via its shebang and failed with
# "/usr/bin/env: 'ruby': No such file or directory" because there is no `ruby`
# on the target PATH. The task now uses trivy.sh / trivy.ps1 (see metadata
# "implementations"), which call the Puppet agent's bundled Ruby at its known
# absolute path to run files/trim.rb. This file is intentionally left as a stub.
