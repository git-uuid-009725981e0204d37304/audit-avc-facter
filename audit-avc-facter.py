#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Looks at the list of AVCs since last policy load and writes them
# as facter facts.
#
# Copyright (C) 2017 by The Linux Foundation and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)
import os
import sys
import yaml
import logging

from argparse import ArgumentParser

import sepolgen.audit as audit

logger = logging.getLogger(__name__)


def get_audit_msgs():
    # override audit's get_audit_msgs method because running from cron
    # requires passing --input-logs parameter.
    import subprocess
    output = subprocess.Popen(["/sbin/ausearch", "--input-logs", "-m",
                               "AVC,USER_AVC,MAC_POLICY_LOAD,DAEMON_START"],
                              stdout=subprocess.PIPE).communicate()[0]
    return output


def main(factfile):
    logger.info('Parsing audit messages')
    try:
        messages = get_audit_msgs()
        parser = audit.AuditParser(last_load_only=True)
        parser.parse_string(messages)

        avs = parser.to_access()
    except Exception as ex:
        logger.critical('Was not able to access/parse audit messages' % ex)
        sys.exit(1)

    avslist = avs.to_list()

    if len(avslist) == 0:
        logger.info('No AVCs found')
        sys.exit(0)

    logger.info('Found %s type violations since last policy load' % len(avslist))

    avcs = []
    for x in avslist:
        if x[0] == x[1]:
            x[1] = 'self'

        avcline = '%s %s:%s { %s }' % (x[0], x[1], x[2], ' '.join(x[3:]))
        logger.debug('Found: %s' % avcline)
        avcs.append(avcline)

    try:
        logger.info('Writing %s' % factfile)
        fout = open(factfile, 'w')
        yaml.safe_dump({'avcs': avcs}, fout, default_flow_style=False, explicit_start=True)
        fout.close()
        # set perms on that file to 0600 just in case it's not already
        os.chmod(factfile, 0o600)
    except Exception as ex:
        logger.critical('Was not able to write to %s' % factfile)
        sys.exit(1)


if __name__ == '__main__':
    parser = ArgumentParser(description='Find AVCs since last policy load and record as facter facts')
    parser.add_argument('--factfile', default='/etc/puppetlabs/facter/facts.d/avcs.yaml',
        help='where to write the resulting yaml (%(default)s)')
    parser.add_argument('--logfile', default='/var/log/audit-avc-facter.log',
        help='log things into this logfile (%(default)s)')
    parser.add_argument('--sleep', type=int, help='randomly sleep up to this many seconds')
    parser.add_argument('--quiet', action='store_true', help='only output critical errors')

    args = parser.parse_args()

    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(args.logfile)
    formatter = logging.Formatter("[%(process)d] %(asctime)s - %(message)s")
    ch.setFormatter(formatter)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    loglevel = logging.INFO
    if args.quiet:
        loglevel = logging.CRITICAL

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    ch.setLevel(loglevel)
    logger.addHandler(ch)

    if args.sleep:
        import time, random
        logger.info('Sleeping up to %s seconds' % args.sleep)
        time.sleep(random.randint(0, args.sleep))

    main(args.factfile)