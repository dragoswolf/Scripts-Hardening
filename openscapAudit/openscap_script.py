#!/usr/bin/env python3

import subprocess

mod = input("Nombre del módulo: ").strip()
fichero=f"openscap_{mod}.html"

subprocess.run(["sudo", "oscap", "xccdf", "eval", "--report", fichero, "--profile", "xccdf_org.ssgproject.content_profile_cis_level1_server", "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml"])

