import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


class wizParser(object):
    """
    CVE and Secret scans for Container and VMs
    """

    def get_scan_types(self):
        return ["Wiz Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wiz Scan"

    def get_description_for_scan_types(self, scan_type):
        return "wiz report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        
        try:
            data = file.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")


        items = {}
        if tree['result']:
            resultTree = tree['result']
            # Retrieves vulnerabilities found in libraries from json
            if resultTree['osPackages']:
                osPackagesTree = resultTree['osPackages']
                for package in osPackagesTree:
                    for vulnerability in package['vulnerabilities']: 
                        item = get_item(vulnerability, package["name"], package["version"], test)
                        unique_key = str("osPackages" + str(package['name']  + str(
                            package['version']) +str(item.cve + str(item.severity))))
                        items[unique_key] = item

            # Retrieves vulnerabilities found in libraries from json
            if resultTree['libraries']:
                librariesTree = resultTree['libraries']
                for package in librariesTree:
                    for vulnerability in package['vulnerabilities']: 
                        item = get_item(vulnerability, package["name"], package["version"], test)
                        unique_key = str("libraries" + str(package['name']  + str(
                            package['version']) +str(item.cve + str(item.severity))))
                        items[unique_key] = item

            # Retrieves secrets from json
            if resultTree['secrets']:
                secretsTree = resultTree['secrets']
                for secret in secretsTree:
                    item = get_secret(secret, test)
                    unique_key = str("secrets" + str(secret['type']  + str(
                        secret['description']) + str(item.severity)))
                    items[unique_key] = item

        return list(items.values())




def get_item(vulnerability, package, version, test):

    fixedVersion = vulnerability['fixedVersion'] if vulnerability['fixedVersion'] else 'No available Fix found.'

    # create the finding object
    finding = Finding(
        title=vulnerability['name'] + ' in: ' + package + ' - ' + version,
        cve=vulnerability['name'],
        test=test,
        severity=convert_severity(vulnerability['severity']),
        description= vulnerability['name'] + 'found in' + package +' on version '+version +'.',
        mitigation=fixedVersion,
        references=vulnerability['source'],
        component_name=package,
        component_version=version,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        severity_justification="",
        impact=convert_severity(vulnerability['severity'])
        )

    return finding 


def get_secret(secret, test):

    # create the finding object
    finding = Finding(
        title='Secret found in: ' + str(secret['path']) + ' of type ' + str(secret['type']).lower(),
        test=test,
        severity="Critical",
        description= 'Wiz found a secret in Ln '+str(secret['lineNumber']) + 
            ", Col: "+str(secret['offset']) +". Path: "+str(secret['path']) + 
            ".\nDescription: "+ secret['description'] +
            ".\nType: "+ secret['type'] + 
            ".\nSnippet: "+ secret['snippet']+
            ".\nIsLongTerm: "+str(secret['details']['isLongTerm'])+".",
        mitigation='Verify and delete critical key material.',
        references=None,
        component_name=str(secret['path']),
        component_version="",
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        severity_justification="",
        impact="Critical"
        )

    return finding 


def convert_severity(severity):
    if severity.lower() == 'critical':
        return "Critical"
    elif severity.lower() == 'high':
        return "High"
    elif severity.lower() == 'medium':
        return "Medium"
    elif severity.lower() == 'low':
        return "Low"
    elif severity.lower() == 'informational':
        return "Info"
    else:
        return "Info"

