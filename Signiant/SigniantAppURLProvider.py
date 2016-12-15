#!/usr/bin/python

#
# Copyright 2016 Brian D. Wells
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""See docstring for SigniantAppURLProvider class"""

import urllib2, argparse, sys
from xml.etree import ElementTree
from distutils.version import LooseVersion
from autopkglib import Processor, ProcessorError

UPDATE_XML_URL = "https://updates.signiant.com/signiant_app/signiant-app-info-mac.xml"
FILE_TEMPLATE = "Signiant_App_%s.dmg"
URL_TEMPLATE = "https://updates.signiant.com/%s/%s"

class SigniantAppURLProvider(Processor):
    """Provides URL to the latest Signiant App release."""
    description = __doc__
    input_variables = {
        "version": {
            "required": False,
            "description": ("Specific version to download. If not defined, "
                            "defaults to latest version.")
        },
    }
    output_variables = {
        "version": {
            "description": "The version of the update as extracted from the signiant website.",
        },
        "url": {
            "description": "URL to the latest Signiant App release.",
        },
    }

    def get_installer_info(self):
        """Gets info about an installer from Signiant website."""
        version = self.env.get("version")
        filename = None
        md5_checksum = None
        location = "signiant_app"
        if version and version != "latest":
            self.output("Using provided version %s" % version)
        else:
            # Read update xml
            try:
                fref = urllib2.urlopen(UPDATE_XML_URL)
                xml_data = fref.read()
                fref.close()
            except BaseException as err:
                raise ProcessorError(
                    "Can't download %s: %s" % (UPDATE_XML_URL, err))

            # parse XML data
            try:
                root = ElementTree.fromstring(xml_data)
            except (OSError, IOError, ElementTree.ParseError), err:
                raise Exception("Can't read %s: %s" % (xml_data, err))

            # extract version number from the XML
            version = None
            if root.tag == "signiant-app":
                osx_tag = root.find("osx")
                if osx_tag is not None:
                    version_tag = osx_tag.find("version")
                    if version_tag is not None:
                        version = version_tag.text
                    file_tag = osx_tag.find("file")
                    if file_tag is not None:
                        filename = file_tag.text
                    location_tag = osx_tag.find("location")
                    if location_tag is not None:
                        location = location_tag.text
                    md5_tag = osx_tag.find("md5")
                    if md5_tag is not None:
                        md5_checksum = md5_tag.text
            if version:
                version = ".".join(str(x) for x in LooseVersion(version).version[0:3])
            else:
                raise ProcessorError("Update XML in unexpected format.")

        # build filename, URL
        if filename is None:
            filename = FILE_TEMPLATE % version
        url = URL_TEMPLATE % (location, filename)

        # if no checksum, then get one from the server
        if md5_checksum is None:
            request = urllib2.Request(url)
            request.get_method = lambda : 'HEAD'
            response = urllib2.urlopen(request)
            md5_checksum = response.info().getheader('eTag').split('"')[1]

        self.env["url"] = url
        self.env["version"] = version
        if md5_checksum is not None:
            self.env["checksum"] = md5_checksum
        self.output("Found URL %s for version %s" % (self.env["url"], self.env["version"]))

    def main(self):
        """Get information about an update"""
        self.get_installer_info()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_plist")
    parser.add_argument("output_plist")
    parser.add_argument('vars', nargs='*')
    args = parser.parse_args()
    sys.argv = args.vars
    PROCESSOR = SigniantAppURLProvider(None,open(args.input_plist),args.output_plist)
    PROCESSOR.execute_shell()
