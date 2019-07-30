# PST Go Phish
This is a Python 2.X script forked from DPMForensics.com. The original script interacts with PSTs and OSTs and identifies emails with mismatched sender / reply-to or return-path headers. It can also be used to identify messages from throwaway email accounts and unique links. 

The forked version includes additional capabilities to scan links within the PST/OST to identify known phishing, social engineering, or malware links by checking against Google's Safe Browsing Check API. Additional details on the API can be found here: https://transparencyreport.google.com/safe-browsing/overview?hl=en

## Use case
E-mail is often the initial attack vector to target an organization because everyone organization uses e-mails everyday. Business Email Comrpomise is one the rise. Most attacks begin with an unsuspecting phishing link in an e-mail usually from someone you know prompting users to login in excahnge to view a critical document that you were expecting. Attackers use these credentials to monitor sensitive communications and often divert payments to different accounts causing financial damage to a company. APT actors and other targeted attacks often begin with an initial phishing email as well. Finding the initial phishing e-mail through a large mailbox is critical in forensic investigations and can be like finding a needle in the haystack. 

There are some approaches you can take to appraoch this problem. The original "PST-Go-Phish.py" script does an amazing job to identify potential phishes by highlighting emails that are likely spoofed because the "FROM" address does not match the "Reply-To" or "Return-Path" headers. That's a great start to highlight spoofed emails. Phishing e-mails can be spoofed, but not every spoofed email is a phishing email. Some marketing emails also have mismatched headers "FROM" and "Reply-To"/"Return-Path" headers. A DFIR analyst would have to review the output for spoofed emails to distinguish between legitimate marketing emails and potential phishing emails. I say potential phishing emails because not every phishing e-mail is always a spoofed e-mail and the original script relies on highlighting spoofed emails. Some phishing e-mails could be from legitimate users that are not spoofed which won't be detected by the original script. 

Attackers are effective in phishing because they use new domain names that are recently registered to mass spam targets, or they use compromised accounts from someone you trust to send a malicious link. Since these links are new, they are not blacklisted yet which gives them enough time to successfully attack a few users before their new campaign domain names are reported and blacklisted by the community. While Google constantly scans the web for deceptive sites, not every URL is immediately blacklisted since new URLs are created everyday for legitimate and malicious use. Google, or any other blacklisting provider, may not be able to block every phishing site all the time until its reported or analyzed and that's where attackers have an opportunity to strike. However, Google and other blacklisting providers can certainly aid a Forensic Investigation because spam campaign links which were considered "safe" when visiting by an unsuspecting user are eventually blacklisted over a couple of hours or days when analyzed or reported by the community. That's usually the same amount of time it takes for an affected organization to detect that there is a problem and makes arrangements to conduct forensic investigation. A DFIR analyst could rely on this script to increase their odds of finding the initial phishing e-mail assuming Google had enough time to scan and update their Safe Browsing Check lists. If you are still not able to find the phishing e-mail, run the script again at a later day because the internet is constantly being scanned and blacklists are constantly updated. Time is your friend and eventually the "zero-day" link will be picked up by Google or reported by someone to Google to assist in your investigation. Time is your friend in this case :)



## Installation Instructions: 



## Usage
This script takes a PST or OST file as its input and an output directory. You can also supply a comma-delimited list of items to ignore (for example, you may want to ignore bounce lists or emails from known good senders). Alternatively, if the threshold switch is applied it will also flag potential throwaway emails (which could be related to phishing). The script creates a CSV file with a row for each potentially suspicious email found.
~~~
python pst_go_phish.py -h
usage: pst_go_phish.py [-h] [-i IGNORE] [-t THRESHOLD] [-l LINKS]
                       PST_FILE OUTPUT_DIR

PST Go Phishing..

positional arguments:
  PST_FILE              File path to input PST file
  OUTPUT_DIR            Output Dir for CSV

optional arguments:
  -h, --help            show this help message and exit
  -i IGNORE, --ignore IGNORE
                        Comma-delimited acceptable emails to ignore e.g.
                        (bounce lists, etc.)
  -t THRESHOLD, --threshold THRESHOLD
                        Flag emails where sender has only sent N email to the
                        mailbox (default 1)
  -l LINKS, --links LINKS
                        Flag emails where the link has only sent/received N
                        times (default 1)

~~~
