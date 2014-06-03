#!/usr/bin/env python

"""Identify and extract valid domains from input data."""


import urllib2  # Make HTTP Requests.
import re  # Use Regular Expressions.


class ExtractDomains(object):

    """Identify valid domains."""

    def __init__(self, input_data):
        """Instantiate the class."""

        # Because we access attributes of an object by reference.
        self.input_data = input_data

    def get_public_suffix_list(self):
        """Reach out to the Public Suffix List and grab the TLDs."""

        url = ("http://mxr.mozilla.org/mozilla-"
               "central/source/netwerk/dns/effective_tld_names.dat?raw=1"
               )

        public_suffix_list = unicode(urllib2.urlopen(url).read(), 'utf-8')

        tld_pattern = re.finditer(

            r"""

                ^(?P<tld>[.*!]*\w[\S]*)""", unicode(public_suffix_list),

            re.UNICODE | re.MULTILINE | re.VERBOSE

        )

        tld_list = [match.group('tld') for match in tld_pattern]

        return tld_list

    def get_valid_domains(self):
        """Use the Public Suffix List to identify valid domains."""

        public_suffix_list = self.get_public_suffix_list()

        results = {
            'tld_list': [],
            'domain_list': []
        }

        """This is a TEMPORARY FIX.  When matching for domains, those in
        an email address are returned as well... I'll get a working solution
        soon hopefully... Need to get my regex on.

        Previously, the domain_like_pattern RegEx below would return
        "gmail.com" for user@gmail.com  - That's not cool.
        """

        # This bit sucks... Shouldn't have to do this to exclude email matches.
        clean_list = [x for x in self.input_data if not "@" or not '(at)' in x]

        # Find strings which 'look' like domains. We'll validate later.
        domain_like_pattern = re.finditer(

            r"""  # Use Raw Mode

                (

                # All of the below is magic.

                ([a-zA-Z\d-]{1,63}[.]){1,126}  # Covering all subdomains

                [a-zA-Z\d-]{1,63}  # Exclude the 'dot' from the last part

                )

            # VERBOSE for a clean look of this RegEx.
            """, str(clean_list), re.VERBOSE
        )

        # List which houses all of the matches for 'domain_like_pattern'
        domain_like_list = [match.group(1) for match in domain_like_pattern]

        domain_like_list = list(set(domain_like_list))

        for tld in public_suffix_list:
            for entry in domain_like_list:
                if entry.endswith('.' + tld):
                    results['domain_list'].append(entry)

                elif entry == tld:
                    results['tld_list'].append(entry)

        """This will help prevent the listing of domains multiple times
        in the event that the TLD matches multiple times.  For example:
        'shacknet.nu' and 'nu' are both on the Public Suffix List, so any
        domain ending in 'shacknet.nu' would be returned twice; once for
        'shacknet.nu' and the other time for 'nu' - so let's dedupe.
        """
        results['domain_list'] = list(set(results['domain_list']))
        results['tld_list'] = list(set(results['tld_list']))

        return results
