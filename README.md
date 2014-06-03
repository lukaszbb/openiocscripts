ioc_creator
=====

Extract Indicators of Compromise from both formatted and unformatted input data, and generate an OpenIOC file from them.

The following indicators can be extracted at this time:

* MD5 Hashes
* IP Addresses
* Domain Names

-----

### Requirements

* Python 2.7  —  tested on version *2.7.6*

* lxml (library for processing XML and HTML)  —  http://lxml.de/

-----

### Usage

```
usage: ioc_creator.py [-h] -i FILE PATH [-or] [-n IOC NAME] [-o DIRECTORY PATH]

Generate OpenIOC 1.1 File From Input Data.

optional arguments:
  -h, --help                                      show this help message and exit
  -i FILE PATH, --input FILE PATH                 Full Path to Input File.
  -or, --or_only                                  Optionally, Write the IOC Using 'OR' Logic Only.
  -n IOC NAME, --name IOC NAME                    Optionally, Select a Different IOC Name (Default is UUID).
  -o DIRECTORY PATH, --output_dir DIRECTORY PATH  Optionally, specify output directory (Default is CWD).
```

----

### To Do

* Option to Output OpenIOC 1.0 File
* Identification and extraction of File Names
* Identification and extraction of Registry Paths/Keys
* Identification and extraction of other Indicator Types

----

### Examples

* [This article](http://www.bluecoat.com/security-blog/2013-11-25/plugx-used-against-mongolian-targets) has good info about PlugX (Chinese backdoor trojan), and how it was used against Mongolia.

 * I used a different program I wrote to extract the data from the blog post ([intel.py](https://github.com/JohnnyWachter/intel))

 ```
python intel.py --extract -input "http://normanshark.com/blog/plugx-used-mongolian-targets/" -output "/Users/Johnny/Desktop/osint_intel.txt"
 ```

 **Results**

 ```
606a3279d855f122ea3b34b0eb40c33f
d0d2079e1ab0e93c68da9c293918a376
6ab333c2bf6809b7bdc37c1484c771c5
73b6df33cf24889a03ecd75cf5a699b3
576aa3655294516fac3c55a364dd21d8
198fd054105ad89a93e401d8f59320d1
021babf0f0b8e5df2e5dbd7b379bd3b1
cc7b091b94c4f0641b180417b017fec2
cc1a806d25982acdb35dd196ab8171bc
yahoomesseges.com
yahoo.com
centralasia.regionfocus.com
Yahoomesseges.com
mseupdate.strangled.net
bodologetee.com
ppt.bodologetee.com
ssupdate.regionfocus.com
peaceful.swordwind.net
peaceful003.linkpc.net
peaceful.linkpc.net
mongolia.regionfocus.com
usa.regionfocus.com
 ```
 * We can see that there are a few legitimate domains that need to be excluded (e.g. yahoo.com), but removing those is much simpler than having to copy/paste each of the indicators from the blog.

* After removing the entries we don't want included in the OpenIOC File, I'll pass this file to *ioc_creator.py*

 ```
python ioc_creator.py -i "/Users/Johnny/Desktop/osint_intel.txt" -o "/Users/Johnny/Desktop/"
 ```

 * An OpenIOC File named "fd06e1ec-cef4-4cd3-b8c3-1daa7f51f222.ioc" can now be found on my desktop.
