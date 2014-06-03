#!/usr/bin/env python

"""Extract and Classify IP Addresses."""

import re  # Use Regular Expressions.


class ExtractIPs(object):

    """Extract and Classify IP Addresses From Input Data."""

    def __init__(self, input_data):
        """Instantiate the Class."""

        # Because we access attributes of an object by reference.
        self.input_data = input_data

    def get_valid_ips(self):
        """Extract IP Addresses"""

        data = self.input_data

        ip_like_group = []  # Store IP-Address Look-alikes.

        # Dictionary that will store above lists as keys.
        ip_results = {
            'valid_ips': [],  # Stroe all valid IP Addresses.
            'invalid_ips': [],  # Store all invalid IP Addresses.
            'private_ips': [],  # Store all Private IP Addresses.
            'public_ips': []  # Store all Public IP Addresses.
        }

        ip_like_pattern = re.finditer(

            r"""  # Use Raw Mode

            # Very loose "ip-like" pattern
            (\b[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}\b)

            # VERBOSE for a clean look of this RegEx.
            """, str(data), re.VERBOSE
        )

        # List which houses all of the matches for 'ip_like_pattern'
        ip_like_group = [match.group(1) for match in ip_like_pattern]

        # We're gonna want to ignore the below two addresses.
        broadcast_address = '255.255.255.255'
        non_routable = '0.0.0.0'

        # Separate the Valid from Invalid IP Addresses.
        for ip_like in ip_like_group:

            # Split the 'IP' into parts so each part can be validated.
            parts = ip_like.split('.')

            # All part values should be between 0 and 255.
            if (all(0 <= int(part) < 256 for part in parts)):
                if not (
                    ip_like == broadcast_address or
                    ip_like == non_routable
                ):
                    ip_results['valid_ips'].append(ip_like)

            else:
                ip_results['invalid_ips'].append(ip_like)

        # Now we will classify the Valid IP Addresses.
        for valid_ip in ip_results['valid_ips']:

            private_ip_pattern = re.findall(

                r"""  # Use Raw Mode

                (^127\.0\.0\.1)|  # Loopback

                (^10\.\d{1,3}\.\d{1,3}\.\d{1,3})|  # 10/8 Range

                # Matching the 172.16/12 Range takes several matches
                (^172\.1[6-9]\.\d{1,3}\.\d{1,3})|
                (^172\.2[0-9]\.\d{1,3}\.\d{1,3})|
                (^172\.3[0-1]\.\d{1,3}\.\d{1,3})|

                (^192\.168\.\d{1,3}\.\d{1,3})|  # 192.168/16 Range

                # Match APIPA Range.
                (^169\.254\.\d{1,3}\.\d{1,3})

                # VERBOSE for a clean look of this RegEx.
                """, valid_ip, re.VERBOSE
            )

            if private_ip_pattern:

                ip_results['private_ips'].append(valid_ip)

            else:
                ip_results['public_ips'].append(valid_ip)

        return ip_results  # Self explanatory.
