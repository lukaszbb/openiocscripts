#!/usr/bin/env python

"""Format the Input Data."""

import os  # A portable way of using operating system dependent functionality.
import re  # For Regular Expressions.
import StringIO  # Write strings to buffer.
import sys  # Interact with the interpreter.

try:
    import lxml
    from lxml.html.clean import Cleaner

except ImportError:
    sys.exit(
        """
        You're missing the lxml module.  Please download it here:
        http://lxml.de/installation.html
        """)


class CleanData(object):

    """Clean Up the Input Data."""

    def __init__(self, input_data):
        """Instantiate the Class."""

        self.input_data = input_data

    def to_list(self):
        """Return a List of Unique Elements."""

        if os.path.isfile(self.input_data):

            with open(self.input_data, 'rb') as infile:

                read_data = infile.read()

        elif isinstance(self.input_data, str):

            read_data = self.input_data

        # Define delimiters for the final list.
        data = re.compile(
            r"""


            [\`\~\!\#\$\%\^\&\*\(\)\_\=\+]|

            [\t\r\n\;\:\'\"\,\<\>\/\?]|

            [ \\]

            """, re.VERBOSE)

        data_list = data.split(read_data)  # Create the list.

        clean_list = []  # List to store the cleaned up input.

        for entry in data_list:

            clean_entry = entry.strip(' .,<>?/[]\\{}"\'|`~!@#$%^&*()_+-=')

            clean_list.append(clean_entry)  # Add the entry to the clean list.

        clean_unique_list = list(set(clean_list))  # Remove duplicates in list.

        return clean_unique_list


class GetData(object):

    """Get and Classify the Input Data."""

    def __init__(self, data_path):
        """Instantiate the Class."""

        self.data_path = data_path

    def get_url(self):
        """Get the HTML body of a web page."""

        # Create file-like object.
        outfile = StringIO.StringIO()

        cleaner = Cleaner()
        cleaner.javascript = True  # Remove JavaScript code from HTML.
        cleaner.scripts = True  # Remove other code from HTML.
        cleaner.style = True  # Remove CSS and styles from HTML.
        cleaner.links = True  # Remove Links from HTML.
        cleaner.kill_tags = ['a', 'img', 'li']  # Remove these tags.

        # Store the cleaned up HTML.
        page_html = lxml.html.tostring(
            cleaner.clean_html(
                lxml.html.parse(self.data_path)
            )
        )

        outfile.write(page_html)  # Write the results to this file in memory.

        return outfile
