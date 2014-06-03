#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-------------------------------------------------------------------------------

This code intends to provide a quick solution for generating IOC Files to be
used with Mandiant Intelligent Response, using input data provided by the user.

IOC writing is provided by William Gibb's 'sample_ioc_writer.py' found below:

https://github.com/mandiant/ioc_writer/tree/master/examples/simple_ioc_writer

Since the writer outputs IOC 1.1 files, I'm implementing another one of the
examples which converts IOC 1.1 to IOC 1.0:

https://github.com/mandiant/ioc_writer/blob/master/examples/11_to_10_downgrade
"""

__program__ = "ioc_creator.py"
__author__ = "Johnny C. Wachter"
__license__ = "Apache License 2.0"
__version__ = "0.0.1"
__status__ = "Development"

from ioc_writer import ioc_api
from classes.Data import CleanData
from classes.Domains import ExtractDomains
from classes.IPAddresses import ExtractIPs
from classes.FileHashes import ExtractHashes

import argparse
import uuid
import os
import sys


def create_ioc_object(ioc_name,items,and_or=True):
    """This comes from William Gibb's 'sample_ioc_writer.py' mentioned in the
    program's Docstring. Note: Writing IOC 1.1 files.
    """

    IOC = ioc_api.IOC(name=ioc_name)

    top_level_or_node = IOC.top_level_indicator

    # build the definition
    if and_or:

        second_level_and_node = ioc_api.make_Indicator_node('AND')

        top_level_or_node.append(second_level_and_node)

    for item in items:

        condition, document, search, content_type, content = tuple(item)

        #print condition, document, search, content_type, content
        IndicatorItem_node = ioc_api.make_IndicatorItem_node(
            condition, document, search, content_type, content
        )
        if and_or:

            second_level_and_node.append(IndicatorItem_node)

        else:

            top_level_or_node.append(IndicatorItem_node)

    # update the last modified time
    IOC.set_lastmodified_date()

    return IOC


def input_file(user_input):
    """Returns file path if the file exists."""

    if not os.path.isfile(user_input):

        sys.exit(
            """
            Invalid File Path: %s
            """ % user_input
        )

    return user_input


def output_directory(user_input):
    """Returns valid directory path."""

    if not os.path.isdir(user_input):

        sys.exit(
            """
            Invalid Directory Path: %s
            """ % user_input
        )

    return user_input


def main():
    """Where the automagic happens."""

    # For Argparse, see: http://docs.python.org/dev/library/argparse.html
    parser = argparse.ArgumentParser(
        prog="ioc_creator.py",
        description="Write IOC file using input data.",
        epilog="Thanks for using this program!\n--3LINE",
        formatter_class=lambda prog: argparse.RawTextHelpFormatter(
            prog, max_help_position=100)
    )

    parser.add_argument(
        "-i", "--input", type=input_file, required=True,
        metavar="FILE PATH", help="Full Path to Input File."
    )

    parser.add_argument(
        "-or", "--or_only", action="store_true",
        help="Optionally, Write the IOC Using 'OR' Logic Only."
    )

    parser.add_argument(
        "-n", "--name", type=str, required=False, default=str(uuid.uuid4()),
        help="Optionally, Select a Different IOC Name (Default is UUID).",
        metavar="IOC NAME"
    )

    parser.add_argument(
        "-o", "--output_dir", type=output_directory, required=False,
        help="Optionally, specify output directory (Default is CWD).",
        metavar="DIRECTORY PATH", default=None
    )

    args = parser.parse_args()

    input_data = CleanData(args.input).to_list()

    # Extract Indicators... All of the following return a dictionary:
    hashes = ExtractHashes(input_data).get_valid_hashes()
    ips = ExtractIPs(input_data).get_valid_ips()
    domains = ExtractDomains(input_data).get_valid_domains()

    indicator_items = []

    if hashes['md5_hashes']:

        for md5_hash in hashes['md5_hashes']:

            indicator_items.append(
                ['is', 'FileItem', 'FileItem/Md5sum', 'md5', md5_hash]
            )

    if ips['public_ips']:

        for ip in ips['public_ips']:

            indicator_items.append(
                ['contains', 'ArpEntryItem', 'ArpEntryItem/IPv4Address',
                    'IP', ip
                ]
            )

            indicator_items.append(
                ['contains', 'DnsEntryItem',
                    'DnsEntryItem/RecordData/IPv4Address', 'IP', ip
                ]
            )

            indicator_items.append(
                ['contains', 'Network', 'Network/DNS', 'string', ip]
            )

            indicator_items.append(
                ['contains', 'PortItem', 'PortItem/remoteIP', 'IP', ip]
            )

    if domains['domain_list']:

        for domain in domains['domain_list']:

            indicator_items.append(
                ['contains', 'UrlHistoryItem', 'UrlHistoryItem/URL',
                    'string', domain
                ]
            )

            indicator_items.append(
                ['contains', 'Network', 'Network/URI', 'string', domain]
            )

            indicator_items.append(
                ['contains', 'FileDownloadHistoryItem',
                    'FileDownloadHistoryItem/SourceUR', 'string', domain]
            )

    IOC = create_ioc_object(args.name, indicator_items, and_or=False)

    ioc_api.write_ioc(IOC.root, args.output_dir)


if __name__ == "__main__":

    main()
