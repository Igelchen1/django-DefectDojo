__author__ = 'aaronweaver'

import logging
import ntpath

from dateutil import parser
from defusedxml import ElementTree

from dojo.models import Finding
from dojo.utils import add_language

logger = logging.getLogger(__name__)


class CheckmarxParser(object):
    """
    ----------------------------------------
    Structure of the checkmarx xml report:
    ----------------------------------------
    - Query:
    the kind of vulnerabilities. Contains for example cweId
    - Result: One vulnerability in checkmarx = 1 pathId
    Includes filename and linenumber from source of vulnerability (start of the attack vector)
    - Path: There should be only one.Parent tag of Pathnodes
    - Pathnode: all the calls from the source (start) to the sink (end) of the attack vector
    """

    def get_scan_types(self):
        return ["Checkmarx Scan", "Checkmarx Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        if scan_type == "Checkmarx Scan":
            return "Detailed XML Report. Aggregates vulnerabilities per categories, cwe, name, sinkFilename"
        else:
            return "Detailed XML Report. Import all vulnerabilities from checkmarx without aggregation"

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    # FIXME get rid of local variables
    language_list = []
    mitigation = 'N/A'
    impact = 'N/A'
    references = ''

    def get_findings(self, filename, test):
        cxscan = ElementTree.parse(filename)
        self.test = test
        root = cxscan.getroot()

        # Dictonary to hold the aggregated findings with:
        #  - key: the concatenated aggregate keys
        #  - value: the finding
        dupes = dict()
        for query in root.findall('Query'):
            name, cwe, categories, queryId = self.getQueryElements(query)
            language = ''
            findingdetail = ''
            group = ''
            find_date = parser.parse(root.get("ScanStart"))

            if query.get('Language') is not None:
                language = query.get('Language')

            if query.get('group') is not None:
                group = query.get('group').replace('_', ' ')

            for result in query.findall('Result'):
                if categories is not None:
                    findingdetail = "{}**Category:** {}\n".format(findingdetail, categories)

                if language is not None:
                    findingdetail = "{}**Language:** {}\n".format(findingdetail, language)
                    if language not in self.language_list:
                        self.language_list.append(language)

                if group is not None:
                    findingdetail = "{}**Group:** {}\n".format(findingdetail, group)

                if result.get('Status') is not None:
                    findingdetail = "{}**Status:** {}\n".format(findingdetail, result.get('Status'))

                deeplink = "[{}]({})".format(result.get('DeepLink'), result.get('DeepLink'))
                findingdetail = "{}**Finding Link:** {}\n".format(findingdetail, deeplink)

                if self.mode == 'detailed':
                    self.process_result_detailed(dupes, findingdetail, query, result, find_date)
                else:
                    self.process_result_file_name_aggregated(dupes, findingdetail, query, result, find_date)
                findingdetail = ''

        for lang in self.language_list:
            add_language(test.engagement.product, lang)

        return list(dupes.values())

    # Process one result = one pathId for default "Checkmarx Scan"
    # Create the finding and add it into the dupes list
    # If a vuln with the same file_path was found before, updates the description
    def process_result_file_name_aggregated(self, dupes, findingdetail, query, result, find_date):
        name, cwe, categories, queryId = self.getQueryElements(query)
        titleStart = query.get('name').replace('_', ' ')
        description, lastPathnode = self.get_description_file_name_aggregated(query, result)
        sinkFilename = lastPathnode.find('FileName').text
        title = "{} ({})".format(titleStart, ntpath.basename(sinkFilename))
        false_p = result.get('FalsePositive')
        sev = result.get('Severity')
        aggregateKeys = "{}{}{}".format(cwe, sev, sinkFilename)
        state = result.get('state')
        active = self.isActive(state)
        verified = self.isVerified(state)

        if not(aggregateKeys in dupes):
            find = Finding(title=title,
                           cwe=int(cwe),
                           test=self.test,
                           # active, verified and false_p may be overwritten later by another member of the aggregate, see "else" below
                           active=active,
                           verified=verified,
                           false_p=(false_p == "True"),
                           # Concatenates the query information with this specific finding information
                           description=findingdetail + description,
                           severity=sev,
                           mitigation=self.mitigation,
                           impact=self.impact,
                           references=self.references,
                           file_path=sinkFilename,
                           # No line number because we have aggregated different vulnerabilities that may have different line numbers
                           url='N/A',
                           date=find_date,
                           static_finding=True,
                           nb_occurences=1,
                           vuln_id_from_tool=queryId)
            dupes[aggregateKeys] = find
        else:
            # We have already created a finding for this aggregate: updates the description and the nb_occurences
            find = dupes[aggregateKeys]
            find.nb_occurences = find.nb_occurences + 1
            if find.nb_occurences == 2:
                find.description = "### 1. {}\n{}".format(find.title, find.description)
            find.description = "{}\n\n-----\n### {}. {}\n{}\n{}".format(find.description, find.nb_occurences, title, findingdetail, description)
            find.vuln_id_from_tool = "{},{}".format(find.vuln_id_from_tool, queryId)
            # If at least one of the findings in the aggregate is exploitable, the defectdojo finding should not be "false positive"
            if(false_p == "False"):
                dupes[aggregateKeys].false_p = False
            # If at least one of the findings in the aggregate is active, the defectdojo finding should be active
            if(active):
                dupes[aggregateKeys].active = True
            # If at least one of the findings in the aggregate is verified, the defectdojo finding should be verified
            if(verified):
                dupes[aggregateKeys].verified = True

    # Iterate over function calls / assignments to extract finding description and last pathnode
    def get_description_file_name_aggregated(self, query, result):
        description = ""

        # Loop over <Path> (there should be only one)
        for path in result.findall('Path'):
            firstPathnode = True
            for pathnode in path.findall('PathNode'):
                if(firstPathnode):
                    sourceFilename, sourceLineNumber, sourceObject = self.get_pathnode_elements(pathnode)
                    firstPathnode = False
        # At this point we have iterated over all path nodes (function calls) and pathnode is at the sink of the vulnerability
        sinkFilename, sinkLineNumber, sinkObject = self.get_pathnode_elements(pathnode)
        description = "<b>Source file: </b>{} (line {})\n<b>Source object: </b> {}".format(sourceFilename, sourceLineNumber, sourceObject)
        description = "{}\n<b>Sink file: </b>{} (line {})\n<b>Sink object: </b> {}".format(description, sinkFilename, sinkLineNumber, sinkObject)
        return description, pathnode

    # Process one result = one pathId for scanner "Checkmarx Scan detailed"
    # Create the finding and add it into the dupes list
    def process_result_detailed(self, dupes, findingdetail, query, result, find_date):
        name, cwe, categories, queryId = self.getQueryElements(query)
        title = ''
        sev = result.get('Severity')
        title = query.get('name').replace('_', ' ')
        state = result.get('state')
        # Loop over <Path> (there should be only one)
        paths = result.findall('Path')
        if(len(paths)) > 1:
            logger.warning("Checkmarx scan: more than one path found: " + str(len(paths)) + ". Only the last one will be used")

        for path in paths:
            sourceFilename = ''
            sinkFilename = ''
            sourceLineNumber = None
            sinkLineNumber = None
            sourceObject = ''
            sinkObject = ''
            similarityId = str(path.get("SimilarityId"))
            path_id = str(path.get("PathId"))
            pathId = similarityId + path_id
            findingdetail = '{}-----\n'.format(findingdetail)
            # Loop over function calls / assignments in the data flow graph
            for pathnode in path.findall('PathNode'):
                findingdetail = self.get_description_detailed(pathnode, findingdetail)
                nodeId = pathnode.find('NodeId').text
                if(nodeId == "1"):
                    sourceFilename, sourceLineNumber, sourceObject = self.get_pathnode_elements(pathnode)
            # the last pathnode is the sink
            sinkFilename, sinkLineNumber, sinkObject = self.get_pathnode_elements(pathnode)
            # pathId is the unique id from tool which means that there is basically no aggregation except real duplicates
            aggregateKeys = "{}{}{}{}{}".format(categories, cwe, name, sinkFilename, pathId)
            if title and sinkFilename:
                title = "{} ({})".format(title, ntpath.basename(sinkFilename))

            find = Finding(title=title,
                       cwe=int(cwe),
                       test=self.test,
                       active=self.isActive(state),
                       verified=self.isVerified(state),
                       false_p=result.get('FalsePositive') == "True",
                       description=findingdetail,
                       severity=sev,
                       mitigation=self.mitigation,
                       impact=self.impact,
                       references=self.references,
                       file_path=sinkFilename,
                       line=sinkLineNumber,
                       url='N/A',
                       date=find_date,
                       static_finding=True,
                       unique_id_from_tool=pathId,
                       sast_source_object=sourceObject,
                       sast_sink_object=sinkObject,
                       sast_source_line=sourceLineNumber,
                       sast_source_file_path=sourceFilename,
                       vuln_id_from_tool=queryId)
        dupes[aggregateKeys] = find

    # Return filename, lineNumber and object (function/parameter...) for a given pathnode
    def get_pathnode_elements(self, pathnode):
        return pathnode.find('FileName').text, pathnode.find('Line').text, pathnode.find('Name').text

    # Builds the finding description for scanner "Checkmarx Scan detailed"
    def get_description_detailed(self, pathnode, findingdetail):
        if pathnode.find('Line').text is not None:
            findingdetail = "{}**Line Number:** {}\n".format(findingdetail, pathnode.find('Line').text)

        if pathnode.find('Column').text is not None:
            findingdetail = "{}**Column:** {}\n".format(findingdetail, pathnode.find('Column').text)

        if pathnode.find('Name').text is not None:
            findingdetail = "{}**Source Object:** {}\n".format(findingdetail, pathnode.find('Name').text)

        for codefragment in pathnode.findall('Snippet/Line'):
            findingdetail = "{}**Number:** {}\n**Code:** {}\n".format(findingdetail, codefragment.find('Number').text, codefragment.find('Code').text.strip())

        findingdetail = '{}-----\n'.format(findingdetail)
        return findingdetail

    # Get name, cwe and categories from the global query tag (1 query = 1 type of vulnerability)
    def getQueryElements(self, query):
        categories = ''
        name = query.get('name')
        cwe = query.get('cweId')
        queryId = query.get('id')
        if query.get('categories') is not None:
            categories = query.get('categories')
        return name, cwe, categories, queryId

    # Map checkmarx report state to active/inactive status
    def isActive(self, state):
        # To verify, Confirmed, Urgent, Proposed not exploitable
        activeStates = ["0", "2", "3", "4"]
        return state in activeStates

    # Map checkmarx report state to verified/unverified status
    def isVerified(self, state):
        # Confirmed, urgent
        verifiedStates = ["2", "3"]
        return state in verifiedStates
