import xml.etree.ElementTree as ET
from openpyxl import Workbook
import argparse
import os
wb = Workbook()
ws = wb.active


class ReportHostItem:
    def __init__(self, plugin_name, plugin_output, description,cve,severity,severityID):
        self.plugin_name = plugin_name
        self.plugin_output = plugin_output
        self.description = description
        self.cve = cve
        self.severity = severity
        self.severityID = severityID
    def print(self):
        print(f"{self.plugin_name}")
class ReportHost:
    def __init__(self, ip, reportHostItems ):
        self.ip = ip
        self.reportHostItems = reportHostItems
    def print(self):
        print(f"{self.ip}")
        for item in self.reportHostItems:
            item.print()
def GetSeverity(intVal):
    if intVal == "0":
        return "Informational"
    elif intVal == "1":
        return "Low"
    elif intVal == "2":
        return "Medium"
    elif intVal == "3":
        return "High"
    elif intVal == "4":
        return "Critical"


def ParseReportHostItem(reportHostItem):
    severityID = reportHostItem.get("severity")
    plugin_name = ""
    plugin_output = ""
    description = ""
    cve = ""
    for Item in reportHostItem:
        if Item.tag == "plugin_name":
            plugin_name = Item.text
        if Item.tag == "plugin_output":
            plugin_output = Item.text
        if Item.tag == "description":
            description = Item.text
        if Item.tag == "cve":
            cve= Item.text
    if plugin_name =="" and plugin_output=="" and description == "" and cve =="":
        return None
    return ReportHostItem(plugin_name,plugin_output,description,cve,GetSeverity(severityID),int(severityID))
def ParseReportHost(reportHost):
    if reportHost.tag != "ReportHost":
        return

    ip = reportHost.get("name")
    reportItemArray = []
    for ReportItem in reportHost.findall("ReportItem"):
        item = ParseReportHostItem(ReportItem) 
        if item == None:
            continue
        reportItemArray.append(item)
    if len(reportItemArray) == 0:
        return
    return ReportHost(ip,reportItemArray)
def ParseReport(xml_content):
    root = ET.fromstring(xml_content).find("Report")
    reportHostArray = []
    for reportHost in root.findall("ReportHost"):
        reportHost = ParseReportHost(reportHost)
        if reportHost == None:
                continue 
        reportHostArray.append(reportHost) 
    return reportHostArray

    

def check_severity(value):
    ivalue = int(value)
    if ivalue < 0 or ivalue > 4:
        raise argparse.ArgumentTypeError(f"Severity must be between 0 and 4, got {ivalue}")
    return ivalue
def check_input_file(value):
    if not os.path.exists(value):
        raise argparse.ArgumentTypeError(f"Input file '{value}' does not exist")
    return value
def main(input_file, output_file, severity, cve):
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Severity: {severity}")
    print(f"CVE flag: {cve}")
    with open(input_file, 'r', encoding='utf-8') as file:
        xml_content = file.read()
        report = ParseReport(xml_content)
        row = 2
        for reportHostsIdx, reportHosts in enumerate(report):
            for hostItemIdx,hostItem in enumerate(reportHosts.reportHostItems):
                if hostItem.severityID < severity:
                    continue
                if cve and hostItem.cve == "":
                    continue
                
                ws.cell(row=row, column=1, value=reportHosts.ip)
                ws.cell(row=row, column=2, value=hostItem.plugin_name)
                ws.cell(row=row, column=3, value=hostItem.plugin_output)
                ws.cell(row=row, column=4, value=hostItem.description)
                ws.cell(row=row, column=5, value=hostItem.cve)
                ws.cell(row=row, column=6, value=hostItem.severity)
                row = row + 1

    wb.save(output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enjoy brother !!")
    parser.add_argument("-i", dest="input_file", type=check_input_file, default="scan.nessus", help="Path to the input file")
    parser.add_argument("-o", dest="output_file", default="output.txt", help="Path to the output file")
    parser.add_argument("-s", dest="severity", type=check_severity, default=2, choices=[0, 1, 2, 3, 4], 
                        help="(Default 2) Minimum severity level: 0 (informational), 1 (low), 2 (medium), 3 (high), 4 (critical)")
    parser.add_argument("--cve", action="store_true", help="Just Include if has CVE information")


    args = parser.parse_args()

    main(args.input_file, args.output_file, args.severity, args.cve)
