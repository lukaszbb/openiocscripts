#!/usr/bin/env python

"""Work With File Hashes"""


import re  # Use Regular Expressions.


class ExtractHashes(object):

    """Extract MD5 and SHA-256 Hashes From Input Data."""

    def __init__(self, input_data):
        """Instantiate the class."""

        # Because we access attributes of an object by reference.
        self.input_data = input_data

    def get_valid_hashes(self):
        """Returns a dictionary of lists containing the hashes."""

        data = self.input_data  # Type 'list' is suggested for your input.

        # This dictionary will be return at the end.
        hash_results = {
            'md5_hashes': [],  # List to House MD5 Hashes.
            'sha256_hashes': []  # List to House SHA-256 Hashes.
        }

        # Pattern for identifying MD5 Hashes.
        md5_pattern = re.finditer(

            r"""  # Use Raw Mode

            # Match MD5 Hash (32 Hex Characters).
            (\b[A-Fa-f0-9]{32}\b)

            # VERBOSE for a clean look of this RegEx.
            """, str(data), re.VERBOSE
        )

        # Pattern for identifying SHA-256 Hashes.
        sha256_pattern = re.finditer(

            r"""  # Use Raw Mode

            # Match SHA-256 Hash (64 Hex Characters).
            (\b[A-Fa-f0-9]{64}\b)

            # VERBOSE for a clean look of this RegEx.
            """, str(data), re.VERBOSE
        )

        # Add matches for 'md5_pattern' to the 'md5_hashes' list.
        md5_hashes = [match.group(1) for match in md5_pattern]

        # Add matches for 'sha2_pattern' to the 'sha2_hashes' list.
        sha256_hashes = [match.group(1) for match in sha256_pattern]

        """Update the keys in our previously created dictionary with these
        new lists containing the desired data. Casting to 'set' then back
        to 'list' in order to uniquify the results.
        """
        hash_results["md5_hashes"] = list(set(md5_hashes))
        hash_results["sha256_hashes"] = list(set(sha256_hashes))

        return hash_results  # Self explanatory.
