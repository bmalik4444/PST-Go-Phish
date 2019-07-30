from __future__ import print_function
import argparse
import os
import re
import sys
import requests
import json
import safebrowsing
import csv
from utility.csv_writer import csv_writer

try:
    import pypff
except ImportError:
    print("[+] Install the libpff Python bindings to use this script")
    sys.exit(1)

try:
    import tldextract
except ImportError:
    print("[+] Install the tldextract module to use this script")
    sys.exit(2)

try:
    import tqdm
except ImportError:
    print("[+] Install the tqdm module to use this script")
    sys.exit(3)

"""
    PST-Go-Phish - Automatically find suspicious emails.
    Copyright (C) 2017  Preston Miller

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
apikey='<INSERT YOUR API KEY>'
sb = safebrowsing.LookupAPI(apikey)
safebrowsing.UpdateAPI(apikey)
threaturls=[]


message_list = []
senders_dict = {}
links_dict = {}
urls_dict = {}
lookupURLS = False
messages = 0
compared_messages = 0
suspicious_messages = 0
ignored_messages = 0
no_body_messages = 0


def main(pst_file, output_dir, ig, threshold, links):
	print("[+] Accessing {} PST file..".format(pst_file))
	pst = pypff.open(pst_file)
	root = pst.get_root_folder()
	print("[+] Traversing PST folder structure..")
	if ig is not None:
		ignore = [x.strip().lower() for x in ig.split(',')]
	else:
		ignore = []
	recursePST(root, ignore)
	print("[+] Identified {} messages..".format(messages))
	print("[+] Compared {} messages. Messages not compared were missing a FROM header or both Reply-To and Return-Path".format(compared_messages))
	print("[+] Ignored {} comparable messages".format(ignored_messages))
	print("[+] {} Messages without bodies to check for links".format(no_body_messages))
	print("[+] Identified {} suspicious messages..".format(suspicious_messages))

	print("[+] Identifying emails complying with sender threshold limit of {}".format(threshold))
	senderThreshold(threshold)

	print("[+] Identifying emails complying with link threshold limit of {}".format(links))
	linkThreshold(links)

        global message_list
        headers = ["Folder", "Subject", "Sender", "Attachments", "From Email", "Return-Path", "Reply-To", "Flag"]
        print("[+] Writing {} results to CSV in {}".format(len(message_list), output_dir))
	csv_writer(message_list, headers, output_dir)
	if lookupURLS:
		print("[+] Writing {} results to TXT in {}".format(len(urls_dict), output_dir))
		with open(os.path.join(output_dir,'Go_Phish_Unique_URLS_Found.txt'), 'w') as f:
			for url in urls_dict.keys():
				if "http" in url:
					f.write("{}\n".format(url))
			f.close()
		lookupURLs(urls_dict.keys())
		writeThreatURLsToCSV(threaturls, output_dir, "Go-Phish-Threat-URLS")
		
def lookupURLs(urls):
	urls=[url for url in urls if "http" in url]
	for i in tqdm.tqdm(xrange(0,len(urls),500), desc="Processing URLs against Google Safe Browsing", unit="URLs"):
		batchURLs=urls[i:i+500]
		resp=sb.threat_matches_find(*batchURLs)
		if(resp != {}):
			for match in resp['matches']:
				threaturls.append(match['threat']['url'].rstrip('\n')+','+ match['threatType']+','+ match['platformType'])
				print(threaturls[-1])

def writeThreatURLsToCSV(threaturls, output_dir, outputfile):
	csv_header= ['URL', 'Threat Type', 'Platform']
	try:
		with open(os.path.join(output_dir, outputfile+'.csv'), 'w') as f:
			f.write("URL, Threat Type, Platform \n")
			for item in threaturls:
				f.write(item+"\n")
	except IOError:
		print("I/O error")

def recursePST(base, ignore):
	for folder in base.sub_folders:
		if folder.number_of_sub_folders:
			recursePST(folder, ignore)
		processMessages(folder, ignore)


def processMessages(folder, ignore):
	global messages
	if folder.name == "DiscoveryHolds":
		return
	print("[+] Processing {} Folder with {} messages".format(folder.name, folder.number_of_sub_messages))
	if folder.number_of_sub_messages == 0:
		return
	for message in tqdm.tqdm(folder.sub_messages, desc="Processing", unit="emails"):
		eml_from, replyto, returnpath = ("", "", "")
		messages += 1
		try:
			headers = message.get_transport_headers().splitlines()
		except AttributeError:
			# No email header
			continue
		for header in headers:
			if header.strip().lower().startswith("from:"):
				eml_from = header.strip().lower()
			elif header.strip().lower().startswith("reply-to:"):
				replyto = header.strip().lower()
			elif header.strip().lower().startswith("return-path:"):
				returnpath = header.strip().lower()
		if eml_from == "" or (replyto == "" and returnpath == ""):
			# No FROM value or no Reply-To / Return-Path value
			continue

		compareMessage(folder, message, eml_from, replyto, returnpath, ignore)  



def compareMessage(folder, msg, eml_from, reply, return_path, ignore):
	global message_list, senders_dict, links_dict, compared_messages, suspicious_messages, ignored_messages, no_body_messages, urls_dict
	compared_messages += 1
	reply_email = ''
	return_email = ''
	reply_bool = False
	return_bool = False
	suspicious = False
	found_suspicious = ""
	links = []
	from_email, from_domain = emailExtractor(eml_from)
	if reply != "":
		reply_bool = True
		reply_email, reply_domain = emailExtractor(reply)
	if return_path != "":
		return_bool = True
		return_email, return_domain = emailExtractor(return_path)
	if return_bool is True:
		if from_domain != False and return_domain != False:
			for igno in ignore:
				if igno in return_email:
					ignored_messages += 1
					return
			if from_domain != return_domain:
				suspicious = True
				found_suspicious = "Return-Path"

	if reply_bool is True:
		if from_domain != False and reply_domain != False:
			for igno in ignore:
				if igno in reply_email:
					ignored_messages += 1
					return
			if from_domain != reply_domain:
				suspicious = True
				if found_suspicious == "Return-Path":
					found_suspicious = "Both"
				else:
					found_suspicious = "Reply-To"
	if from_email in senders_dict:
		senders_dict[from_email][0] += 1
	else:
		senders_dict[from_email] = [1, folder.name, msg.get_subject(), msg.get_sender_name(), msg.number_of_attachments, from_email, return_email, reply_email]

	if msg.html_body is None:
		if msg.plain_text_body is None:
			if msg.rtf_body is None:
				no_body_messages += 1
			else:
				links, urls = linkExtractor(msg.rtf_body, "rtf")
		else:
			links, urls = linkExtractor(msg.plain_text_body, "text")
	else:
		links, urls = linkExtractor(msg.html_body, "html")
	for link in links:
		if link in links_dict:
			links_dict[link][0] += 1
		else:
			links_dict[link] = [1, folder.name, msg.get_subject(), msg.get_sender_name(), msg.number_of_attachments, from_email, return_email, reply_email]

	for url in urls:
		if url in urls_dict:
			urls_dict[url][0] +=1
		else:
			urls_dict[url] = [1, folder.name, msg.get_subject(), msg.get_sender_name(), msg.number_of_attachments, from_email, return_email, reply_email]
	if suspicious is True:
		suspicious_messages += 1
		message_list.append([folder.name, msg.get_subject(), msg.get_sender_name(), msg.number_of_attachments, from_email, return_email, reply_email, found_suspicious])


def emailExtractor(item):
	if "<" in item:
		start = item.find("<") + 1
		stop = item.find(">")
		email = item[start:stop]
	else:
		email = item.split(":")[1].strip().replace('"', "")
	if "@" not in email:
		domain = False
	else:
		domain = email.split("@")[1].replace('"', "")
	return email, domain


def linkExtractor(body, body_type):
	links = []
	if body_type == "html":
		urls = re.findall(r'href=[\'"]?([^\'" >]+)', body)
	elif body_type == "text":
		urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
	else:
		urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
	return set(tldextract.extract(x).registered_domain for x in urls), set(urls)


def senderThreshold(threshold):
	global message_list, senders_dict
	sender_count = 0
	for sender in senders_dict:
		if not senders_dict[sender][0] > threshold:
			sender_count += 1
			tmp_list = senders_dict[sender][1:]
			tmp_list.append("Sender Threshold")
			message_list.append(tmp_list)
	print("[+] Identified {} senders less than or equal to the threshold".format(sender_count))


def linkThreshold(threshold):
	global message_list, links_dict
	link_count = 0
	for link in links_dict:
		if not links_dict[link][0] > threshold:
			link_count += 1
			tmp_list = links_dict[link][1:]
			tmp_list.append("Link Threshold")
			message_list.append(tmp_list)
	print("[+] Identified {} domains less than or equal to the threshold".format(link_count))


if __name__ == '__main__':
	# Command-line Argument Parser
	parser = argparse.ArgumentParser(description="PST Go Phishing..")
	parser.add_argument("PST_FILE", help="File path to input PST file")
	parser.add_argument("OUTPUT_DIR", help="Output Dir for CSV")
	parser.add_argument("-i", "--ignore", help="Comma-delimited acceptable emails to ignore e.g. (bounce lists, etc.)")
	parser.add_argument("-t", "--threshold", type=int, default=1, help="Flag emails where sender has only sent N email to the mailbox (default 1)")
	parser.add_argument("-l", "--links", type=int, default=1, help="Flag emails where the link has only sent/received N times (default 1)")
	parser.add_argument("-L", "--lookupURLS", action='store_true', help="Lookup URLS in PST/OST against Google Safe Browsing List and output to CSV")
	args = parser.parse_args()
	
	if not os.path.exists(args.OUTPUT_DIR):
		os.makedirs(args.OUTPUT_DIR)
	
	if args.lookupURLS:
		lookupURLS = True
	
	if os.path.exists(args.PST_FILE) and os.path.isfile(args.PST_FILE):
		main(args.PST_FILE, args.OUTPUT_DIR, args.ignore, args.threshold, args.links)
	else:
		print("[-] Input PST {} does not exist or is not a file".format(args.PST_FILE))
		sys.exit(4)