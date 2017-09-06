Audit AVC Facter
================

This is a small utility to translate Audit AVC logs into a YAML
file of puppet facts that can be queried via the puppet dashboard
or via an orchestration tool (like MCO).

Requirements
------------
Requires the following packages to be installed:

- audit-libs-python
- PyYAML

Example usage
-------------
When run with --help::

    usage: audit-avc-facter.py [-h] [--factfile FACTFILE] [--logfile LOGFILE]
                               [--sleep SLEEP] [--quiet]

    Find AVCs since last policy load and record as facter facts

    optional arguments:
      -h, --help           show this help message and exit
      --factfile FACTFILE  where to write the resulting yaml
                           (/etc/puppetlabs/facter/facts.d/avcs.yaml)
      --logfile LOGFILE    log things into this logfile (/var/log/audit-avc-
                           facter.log)
      --sleep SLEEP        randomly sleep up to this many seconds
      --quiet              only output critical errors


Example cron invocation::

  /usr/local/bin/audit-avc-facter.py \
    --factfile /etc/puppetlabs/facter/facts.d/avcs.yaml \
    --quiet --sleep 300


You will probably be running this from cron, so we add a `--sleep`
parameter to help make sure not all VMs on your hypervisor are parsing
their audit.log at the same time, plus suppress output with `--quiet`.

Output
------
A single toplevel entry called 'avcs'::

    ---
    avcs:
    - some_misbehaving_domain_t self:tcp_socket { connect create getattr setopt }
    - some_misbehaving_domain_t net_conf_t:file { getattr open read }
    - some_misbehaving_domain_t unreserved_port_t:tcp_socket { name_connect }
    - some_misbehaving_domain_t admin_home_t:file { ioctl open read }
    - some_misbehaving_domain_t http_cache_port_t:tcp_socket { name_connect }

