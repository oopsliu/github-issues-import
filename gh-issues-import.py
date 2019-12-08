#!/usr/bin/env python3

from __future__ import print_function

import urllib.request, urllib.error, urllib.parse
import json
import base64
import sys, os
import time
import datetime
import argparse, configparser
import functools

import query

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
default_config_file = os.path.join(__location__, 'config.ini')
config = configparser.RawConfigParser()
	
# Convert accounts in github to devtopia, for example: convert oopsliu in github to zhen9978 in devtopia	
assigneeDict = {
	'survey123bj': 'zhen9978',
	'back-references': 'zhen9978',
	'callable': 'zhen9978'
	}

class state:
	current = ""
	INITIALIZING         = "script-initializing"
	LOADING_CONFIG       = "loading-config"
	FETCHING_ISSUES      = "fetching-issues"
	GENERATING           = "generating"
	IMPORT_CONFIRMATION  = "import-confirmation"
	IMPORTING            = "importing"
	IMPORT_COMPLETE      = "import-complete"
	COMPLETE             = "script-complete"
	
state.current = state.INITIALIZING

log_file = open(os.path.join(__location__, '{0}.log'.format(datetime.datetime.now().strftime('%Y-%m-%d__%H-%M-%S'))), 'w')

def progress_msg(*msgs):
	now = datetime.datetime.now()
	print('[{0}]'.format(now), *msgs)
	print('[{0}]'.format(now), *msgs, file=log_file)

def error_msg(*msgs):
	now = datetime.datetime.now()
	print('[{0}]'.format(now), *msgs, file=sys.stderr)
	print('[{0}]'.format(now), *msgs, file=log_file)

def init_config():
	progress_msg('Loading configuration')
	config.add_section('login')
	config.add_section('source')
	config.add_section('target')
	config.add_section('format')
	config.add_section('settings')
	
	arg_parser = argparse.ArgumentParser(description="Import issues from one GitHub repository into another.")
	
	arg_parser.add_argument('-n', '--dry_run', default=False, action='store_true', help="Do not send any requests that generate content")
	arg_parser.add_argument('-D', '--dump', default=False, action='store_true', help="Dump issues data (useful in dry run)")
	arg_parser.add_argument('-l', '--lock-after-migrate', default=False, action='store_true', help="Lock the original issues after successful migration")
	arg_parser.add_argument('-y', '--yes', default=False, action='store_true', help="Answer 'yes' for all questions")
	
	config_group = arg_parser.add_mutually_exclusive_group(required=False)
	config_group.add_argument('--config', help="The location of the config file (either absolute, or relative to the current working directory). Defaults to `config.ini` found in the same folder as this script.")
	config_group.add_argument('--no-config', dest='no_config',  action='store_true', help="No config file will be used, and the default `config.ini` will be ignored. Instead, all settings are either passed as arguments, or (where possible) requested from the user as a prompt.")
	
	arg_parser.add_argument('-u', '--username', help="The username of the account that will create the new issues. The username will not be stored anywhere if passed in as an argument.")
	arg_parser.add_argument('-tk', '--token', help="The token (in plaintext) of the account that will create the new issues. The token will not be stored anywhere if passed in as an argument.")
	arg_parser.add_argument('-s', '--source', help="The source repository which the issues should be copied from. Should be in the format `user/repository`.")
	arg_parser.add_argument('-t', '--target', help="The destination repository which the issues should be copied to. Should be in the format `user/repository`.")
	
	arg_parser.add_argument('--ignore-comments',  dest='ignore_comments',  action='store_true', help="Do not import comments in the issue.")		
	arg_parser.add_argument('--ignore-events',    dest='ignore_events',    action='store_true', help="Do not import events in the issue.")
	arg_parser.add_argument('--ignore-milestone', dest='ignore_milestone', action='store_true', help="Do not import the milestone attached to the issue.")
	arg_parser.add_argument('--ignore-labels',    dest='ignore_labels',    action='store_true', help="Do not import labels attached to the issue.")
	
	arg_parser.add_argument('--issue-template', help="Specify a template file for use with issues.")
	arg_parser.add_argument('--comment-template', help="Specify a template file for use with comments.")
	arg_parser.add_argument('--pull-request-template', help="Specify a template file for use with pull requests.")
	# ALEXL-TODO add event templates
	
	include_group = arg_parser.add_mutually_exclusive_group(required=True)
	include_group.add_argument("--all", dest='import_all', action='store_true', help="Import all issues, regardless of state.")
	include_group.add_argument("--open", dest='import_open', action='store_true', help="Import only open issues.")
	include_group.add_argument("--closed", dest='import_closed', action='store_true', help="Import only closed issues.")
	include_group.add_argument("-i", "--issues", type=int, nargs='+', help="The list of issues to import.");
	include_group.add_argument("-R", "--issues_range", help="Range of issues to import in the form of <X>-<Y>")

	args = arg_parser.parse_args()
	
	def load_config_file(config_file_name):
		try:
			config_file = open(config_file_name)
			config.read_file(config_file)
			return True
		except (IOError):
			return False
	
	if args.no_config:
		progress_msg("Ignoring default config file. You may be prompted for some missing settings.")
	elif args.config:
		config_file_name = args.config
		if load_config_file(config_file_name):
			progress_msg("Loaded config options from '%s'" % config_file_name)
		else:
			sys.exit("ERROR: Unable to find or open config file '%s'" % config_file_name)
	else:
		config_file_name = default_config_file
		if load_config_file(config_file_name):
			progress_msg("Loaded options from default config file in '%s'" % config_file_name)
		else:
			progress_msg("Default config file not found in '%s'" % config_file_name)
			progress_msg("You may be prompted for some missing settings.")

	config.set('settings', 'dry_run', str(args.dry_run))
	config.set('settings', 'dump', str(args.dump))
	config.set('settings', 'lock_after_migrate', str(args.lock_after_migrate))
	config.set('settings', 'yes', str(args.yes))

	if args.username: config.set('login', 'username', args.username)
	if args.token: config.set('login', 'token', args.token)
	
	if args.source: config.set('source', 'repository', args.source)
	if args.target: config.set('target', 'repository', args.target)
	
	if args.issue_template: config.set('format', 'issue_template', args.issue_template)
	if args.comment_template: config.set('format', 'comment_template', args.comment_template)
	if args.pull_request_template: config.set('format', 'pull_request_template', args.pull_request_template)
	
	config.set('settings', 'import-comments',  str(not args.ignore_comments))
	config.set('settings', 'import-events',    str(not args.ignore_events))
	config.set('settings', 'import-milestone', str(not args.ignore_milestone))
	config.set('settings', 'import-labels',    str(not args.ignore_labels))
	
	config.set('settings', 'import-open-issues',   str(args.import_all or args.import_open));
	config.set('settings', 'import-closed-issues', str(args.import_all or args.import_closed));
	
	# If we got an issues range, convert it to issues numbers
	if args.issues_range:
		try:
			split_list = args.issues_range.split("-")
			if len(split_list) != 2:
				raise Exception
			start = int(split_list[0])
			end = int(split_list[1])
			if start <= 0 or end <= 0 or end < start:
				raise Exception
			args.issues = [issue for issue in range(start, end + 1)]
		except Exception as exc:
			error_msg('issues_range parameter \'{0}\' is invalid!'.format(args.issues_range))
			sys.exit(0);
	
	# Make sure no required config values are missing
	if not config.has_option('source', 'repository') :
		sys.exit("ERROR: There is no source repository specified either in the config file, or as an argument.")
	if not config.has_option('target', 'repository') :
		sys.exit("ERROR: There is no target repository specified either in the config file, or as an argument.")
	
	
	def get_server_for(which):
		# Default to 'github.com' if no server is specified
		if (not config.has_option(which, 'server')):
			config.set(which, 'server', "github.com")
		
		# if SOURCE server is not github.com, then assume ENTERPRISE github (yourdomain.com/api/v3...)
		if (config.get(which, 'server') == "github.com") :
			api_url = "https://api.github.com"
		else:
			api_url = "https://%s/api/v3" % config.get(which, 'server')
		
		config.set(which, 'url', "%s/repos/%s" % (api_url, config.get(which, 'repository')))
	
	get_server_for('source')
	get_server_for('target')
	
	
	# Prompt for username/token if none is provided in either the config or an argument
	def get_credentials_for(which):
		if not config.has_option(which, 'username'):
			if config.has_option('login', 'username'):
				config.set(which, 'username', config.get('login', 'username'))
			elif ( (which == 'target') and query.yes_no("Do you wish to use the same credentials for the target repository?") ):
				config.set('target', 'username', config.get('source', 'username'))
			else:
				query_str = "Enter your username for '%s' at '%s': " % (config.get(which, 'repository'), config.get(which, 'server'))
				config.set(which, 'username', query.username(query_str))
		
		if not config.has_option(which, 'token'):
			if config.has_option('login', 'token'):
				config.set(which, 'token', config.get('login', 'token'))
			elif ( (which == 'target') and config.get('source', 'username') == config.get('target', 'username') and config.get('source', 'server') == config.get('target', 'server') ):
				config.set('target', 'token', config.get('source', 'token'))
			else:
				query_str = "Enter your token for '%s' at '%s': " % (config.get(which, 'repository'), config.get(which, 'server'))
				config.set(which, 'token', query.token(query_str))
	
	get_credentials_for('source')
	get_credentials_for('target')
	
	# Everything is here! Continue on our merry way...
	return args.issues or []

def format_date(datestring):
	# The date comes from the API in ISO-8601 format
	# AlexL: note that in some cases, API returns the date as ""2016-06-07T11:55:57+03:00" and not "2016-06-07T11:55:57Z"
	# and the below code will crash in such cases. For now, I have seen this only for "cross-referenced" events.
	date = datetime.datetime.strptime(datestring, "%Y-%m-%dT%H:%M:%SZ")
	date_format = config.get('format', 'date', fallback='%A %b %d, %Y at %H:%M GMT', raw=True);
	return date.strftime(date_format)
	
def format_from_template(template_filename, template_data):
	from string import Template
	template_file = open(template_filename, 'r')
	template = Template(template_file.read())
	return template.substitute(template_data)

def format_issue(template_data):
	default_template = os.path.join(__location__, 'templates', 'issue.md')
	template = config.get('format', 'issue_template', fallback=default_template)
	return format_from_template(template, template_data)

def format_pull_request(template_data):
	default_template = os.path.join(__location__, 'templates', 'pull_request.md')
	template = config.get('format', 'pull_request_template', fallback=default_template)
	return format_from_template(template, template_data)

def format_comment(template_data):
	default_template = os.path.join(__location__, 'templates', 'comment.md')
	template = config.get('format', 'comment_template', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_assign(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['assignee_user_name'] = event['assignee']['login']
	template_data['action'] = event['event']
	template_data['assigner_user_name'] = event['actor']['login']
	
	default_template = os.path.join(__location__, 'templates', 'event_assign.md')
	template = config.get('format', 'event_assign', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_label(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['user_name'] = event['actor']['login']
	template_data['action'] = 'added' if event['event'] == 'labeled' else 'removed'
	template_data['label'] = event['label']['name']
	
	default_template = os.path.join(__location__, 'templates', 'event_label.md')
	template = config.get('format', 'event_label', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_milestone(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['user_name'] = event['actor']['login']
	template_data['action'] = 'added' if event['event'] == 'milestoned' else 'removed'
	template_data['milestone'] = event['milestone']['title']
	
	default_template = os.path.join(__location__, 'templates', 'event_milestone.md')
	template = config.get('format', 'event_milestone', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_closed(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['user_name'] = event['actor']['login']
	
	default_template = os.path.join(__location__, 'templates', 'event_closed.md')
	template = config.get('format', 'event_closed', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_reopened(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['user_name'] = event['actor']['login']
	
	default_template = os.path.join(__location__, 'templates', 'event_reopened.md')
	template = config.get('format', 'event_reopened', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_renamed(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['user_name'] = event['actor']['login']
	template_data['old_title'] = event['rename']['from'].strip()
	template_data['new_title'] = event['rename']['to'].strip()
	
	default_template = os.path.join(__location__, 'templates', 'event_renamed.md')
	template = config.get('format', 'event_renamed', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_referenced(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['user_name'] = event['actor']['login']
	template_data['commit_url'] = event['commit_url'].replace('api.github.com/repos', 'github.com').replace('commits', 'commit')
	template_data['commit_id'] = event['commit_id']
	
	default_template = os.path.join(__location__, 'templates', 'event_referenced.md')
	template = config.get('format', 'event_referenced', fallback=default_template)
	return format_from_template(template, template_data)

def format_event_cross_referenced(event):
	template_data = {}
	template_data['created_at'] = event['created_at']
	template_data['user_name'] = event['source']['actor']['login']
	template_data['orig_issue_number'] = event['source']['url'].split('/')[-1]
	template_data['orig_issue_url'] = event['source']['url'].replace('api.github.com/repos', 'github.com')
	
	default_template = os.path.join(__location__, 'templates', 'event_cross_referenced.md')
	template = config.get('format', 'event_cross_referenced', fallback=default_template)
	return format_from_template(template, template_data)

ISSUE_EVENTS = {
#	'assigned' :          format_event_assign,
#	'unassigned' :        format_event_assign,
#	'labeled' :           format_event_label,
#	'unlabeled' :         format_event_label,
#	'milestoned' :        format_event_milestone,
#	'demilestoned' :      format_event_milestone,
	'closed' :            format_event_closed,
	'reopened' :          format_event_reopened,
	'renamed' :           format_event_renamed,
	'referenced' :        format_event_referenced,
#	'cross-referenced' :  format_event_cross_referenced,
}

def send_request(which, url, post_data=None, method=None, content_length=None,
                 custom_media_type=None,
                 can_retry=True):
				 
	username = config.get(which, 'username')
	token = config.get(which, 'token')
	
	if post_data is not None:
		post_data = json.dumps(post_data).encode("utf-8")
	
	full_url = "%s/%s" % (config.get(which, 'url'), url)
	#full_url = str(username) + ":" + str(token) + " " + full_url

	req = urllib.request.Request(full_url, data=post_data, method=method)
	
	req.add_header("Authorization", b"Basic " + base64.urlsafe_b64encode(username.encode("utf-8") + b":" + token.encode("utf-8")))
	
	req.add_header("Content-Type", "application/json")
	if content_length is not None:
		req.add_header("Content-Length", content_length)
	req.add_header("Accept", "application/json")
	if custom_media_type is not None:
		req.add_header("Accept", custom_media_type)
	req.add_header("User-Agent", "zadarastorage")

	while True:
		try:
			response = urllib.request.urlopen(req)
			json_data = response.read()
			break
		except urllib.error.HTTPError as error:
			error_details = error.read();
			error_details = json.loads(error_details.decode("utf-8"))
			if 'message' in error_details and\
			   error_details['message'].startswith('You have triggered an abuse detection mechanism and have been temporarily blocked from content creation') or\
			   error_details['message'].startswith('API rate limit exceeded'):
				progress_msg('    .... GITHUB RATE LIMITING HIT, SLEEP ...')
				time.sleep(60)
				continue
			error_msg('HTTP ERROR: {0} {1}'.format(error.code, error.reason))
			error_msg('Request: {0}, data: {1}'.format(url, post_data))
			error_msg('ERROR DETAILS:')
			for detail in error_details:
				error_msg('==={0}===:'.format(detail))
				error_msg(error_details[detail])
			raise
		except Exception as exc:
		    error_msg('EXCEPTION: {0}'.format(str(exc)))
		    if can_retry:
		        progress_msg('   .... SLEEP AND RETRY ....')
		        time.sleep(60)
		        continue
		    raise
	
	if json_data is None or len(json_data.strip()) == 0:
		return None
	return json.loads(json_data.decode("utf-8"))

def get_milestones(which):
	progress_msg('Loading milestones from {0} repository'.format(which))
	milestones = []
	page = 1
	while True:
		# Note that we load here both closed and open milestones
		new_milestones = send_request(which, "milestones?state=all&direction=asc&page={0}".format(page))
		if not new_milestones:
			break
		milestones.extend(new_milestones)
		page += 1
	return milestones
	
	
def convert_assignee(oldAssignee):
	progress_msg('Loading collaborators from {0} repository'.format('source'))
	sourceCollaborators = []
	page = 1
	while True:
		new_collaborators = send_request('source', "collaborators?state=all&direction=asc&page={0}".format(page))
		if not new_collaborators:
			break
		sourceCollaborators.extend(new_collaborators)
		page+=1
		
	newAssignee = assigneeDict[oldAssignee]
	return newAssignee
	



def get_labels(which):
	progress_msg('Loading labels from {0} repository'.format(which))
	labels = []
	page = 1
	while True:
		new_labels = send_request(which, "labels?direction=asc&page={0}".format(page))
		if not new_labels:
			break
		labels.extend(new_labels)
		page += 1
	return labels

def get_issue_by_id(which, issue_id):
	progress_msg('Loading issue {0} from {1} repository'.format(issue_id, which))
	return send_request(which, "issues/%d" % issue_id)

def get_issues_by_id(which, issue_ids):
	# Populate issues based on issue IDs
	issues = []
	for issue_id in issue_ids:
		issues.append(get_issue_by_id(which, int(issue_id)))
	
	return issues

# Allowed values for state are 'open' and 'closed'
def get_issues_by_state(which, state):
	progress_msg('Loading all issues in state {0} from {1} repository'.format(state, which))
	issues = []
	page = 1
	while True:
		progress_msg('Loading page {0} of all issues in state {1} from {2} repository'.format(page, state, which))
		new_issues = send_request(which, "issues?state=%s&direction=asc&page=%d" % (state, page))
		if not new_issues:
			break
		issues.extend(new_issues)
		page += 1
	return issues

def get_comments_on_issue(which, issue):
	progress_msg('Loading comments on issue {0} from {1} repository'.format(issue['number'], which))
	num_comments = issue['comments']
	if num_comments == 0:
		return []
	
	comments = []
	page = 1
	while True:
		new_comments = send_request(which, "issues/{0}/comments?direction=asc&page={1}".format(issue['number'], page))
		if not new_comments:
			break
		comments.extend(new_comments)
		page += 1
	
	if len(comments) < num_comments:
		error_msg('ERROR: issue {0} should have {1} comments, but we were able to load only {2}'.format(issue['number'], num_comments, len(comments)))
		sys.exit()
	
	return comments

def get_events_on_issue(which, issue):
	progress_msg('Loading events on issue {0} from {1} repository'.format(issue['number'], which))
	events = []
	page = 1
	while True:
		# note that the timeline API is in 'developer-preview' status
		new_events = send_request(which, "issues/{0}/timeline?direction=asc&page={1}".format(issue['number'], page),
		                          custom_media_type='application/vnd.github.mockingbird-preview')
		if not new_events:
			break
		events.extend(new_events)
		page += 1
	
	# Preprocess the list, by doing two things:
	# - consolidating the events that happened on the same "created_at"
	# - filter out those events that we don't need
	by_created_at = {}
	for ev in events:
		if config.getboolean('settings', 'dump'):
			progress_msg('Event for source issue {0}:\n'.format(issue['number']), json.dumps(ev, sort_keys=True, indent=4))
		if ev['event'] not in ISSUE_EVENTS:
			continue
		if ev['event'] == 'referenced' and ev.get('commit_id') is None:
			continue
		# # Ignore references to test repositories that I created
		# if ev['event'] == 'cross-referenced' and 'alexl_sandbox' in ev['source']['url']:
			# continue
		# # Ignore back-references automatically created during migration of previous issues
		# if ev['event'] == 'cross-referenced' and 'zadara-issues' in ev['source']['url']:
			# continue
		created_at_list = by_created_at.get(ev['created_at'])
		if created_at_list is None:
			by_created_at[ev['created_at']] = [ev]
		else:
			created_at_list.append(ev)
	
	events = []
	for created_at in by_created_at:
		entry = {'created_at' : created_at, 'events' : by_created_at[created_at]}
		events.append(entry)
	
	return events

def import_milestone(source):
	progress_msg('Creating milestone \'{0}\' in target repository'.format(source['title']))
	data = {
		"title": source['title'],
		"state": source['state'],
		"description": source['description'],
		"due_on": source['due_on']
	}
	
	result_milestone = send_request('target', "milestones", data, can_retry=False)
	progress_msg("Successfully created milestone '{0}' in state '{1}'".format(result_milestone['title'], result_milestone['state']))
	return result_milestone
	
	

def import_label(source):
	progress_msg('Creating label \'{0}\' in target repository'.format(source['name']))
	data = {
		"name": source['name'],
		"color": source['color']
	}
	
	result_label = send_request('target', "labels", data, can_retry=False)
	progress_msg("Successfully created label '%s'" % result_label['name'])
	return result_label

def import_comment(comment, issue_number):
	template_data = {}
	template_data['user_name'] = comment['user']['login']
	template_data['user_url'] = comment['user']['html_url']
	template_data['user_avatar'] = comment['user']['avatar_url']
	template_data['date'] = format_date(comment['created_at'])
	template_data['url'] =  comment['html_url']
	template_data['body'] = comment['body']
	comment['body'] = format_comment(template_data)
	send_request('target', 'issues/{0}/comments'.format(issue_number), comment)

def import_event(event, issue_number):
	body = None
	events_list = event['events']
	for ev in events_list:
		format_func = ISSUE_EVENTS[ev['event']]
		more_body = format_func(ev)
		if body is None:
			body = more_body
		else:
			body = body + more_body
	
	comment = {'body' : body}
	send_request('target', 'issues/{0}/comments'.format(issue_number), comment)

TYPE_COMMENT=1
TYPE_EVENT=2
def import_comments_and_events(comments, events, issue_number):
	num_comments = 0
	num_events = 0
	
	# First of all, sort everything by 'created_at'
	# Also, tag each entry as "comment" or "event"
	all_entries = []
	if comments is not None and len(comments) > 0:
		num_comments = len(comments)
		for comment in comments:
			comment['__entry_type'] = TYPE_COMMENT
			all_entries.append(comment)
	if events is not None and len(events) > 0:
		num_events = len(events)
		for ev in events:
			ev['__entry_type'] = TYPE_EVENT
			all_entries.append(ev)
	
	def compare_entry(e1, e2):
		# 'created_at' come in ISO-8601 format, so these strings can be compared lexicographically
		created_at1 = e1['created_at']
		created_at2 = e2['created_at']
		if created_at1 < created_at2:
			return -1
		if created_at1 > created_at2:
			return 1
		
		# If timestamps are identical, put comments before events
		type1 = e1['__entry_type']
		type2 = e2['__entry_type']
		if type1 < type2:
			return -1
		if type1 > type2:
			return 1
		return 0
	
	all_entries.sort(key=functools.cmp_to_key(compare_entry))
	
	progress_msg('Creating {0} comments and {1} events for issue {2} in target repository'.format(num_comments, num_events, issue_number))
	for entry in all_entries:
		etype = entry['__entry_type']
		del entry['__entry_type']
		if etype == TYPE_COMMENT:
			import_comment(entry, issue_number)
		else:
			import_event(entry, issue_number)
			
			

# Will only import milestones and labels that are in use by the imported issues, and do not exist in the target repository
def import_issues(issues):

	state.current = state.GENERATING

	known_milestones = get_milestones('target')
	def get_milestone_by_title(title):
		for milestone in known_milestones:
			if milestone['title'] == title : return milestone
		return None
	
	known_labels = get_labels('target')
	def get_label_by_name(name):
		# Github labels are case-insensitive
		for label in known_labels:
			if label['name'].upper() == name.upper():
				return label
		return None
	
	new_issues = []
	num_new_comments = 0
	num_new_events = 0
	new_milestones = []
	new_labels = []
	
	for issue in issues:
		
		new_issue = {}
		new_issue['orig_issue_number'] = issue['number']
		new_issue['title'] = issue['title']
		new_assignees = []
		
		# Convert assignees to devtopia accout according to assigneeDict
		if issue.get('assignees') is not None:
			for assignee in issue.get('assignees'):			
				oldAssignee = assignee['login']

				if oldAssignee in assigneeDict:
					newAssignee = convert_assignee(oldAssignee)
					new_assignees.append(newAssignee)
				
			new_issue['assignees'] = new_assignees
		
		if issue['closed_at']:
			new_issue['orig_issue_closed'] = True
		
		if config.getboolean('settings', 'import-comments') and 'comments' in issue and issue['comments'] != 0:
			num_new_comments += int(issue['comments'])
			new_issue['comments'] = get_comments_on_issue('source', issue)
		
		if config.getboolean('settings', 'import-events'):
			new_issue['events'] = get_events_on_issue('source', issue)
			num_new_events += len(new_issue['events'])
		
		if config.getboolean('settings', 'import-milestone') and 'milestone' in issue and issue['milestone'] is not None:
			# Since the milestones' ids are going to differ, we will compare them by title instead
			found_milestone = get_milestone_by_title(issue['milestone']['title'])
			if found_milestone:
				new_issue['milestone_object'] = found_milestone
			else:
				new_milestone = issue['milestone']
				new_issue['milestone_object'] = new_milestone
				known_milestones.append(new_milestone) # Allow it to be found next time
				new_milestones.append(new_milestone)   # Put it in a queue to add it later
		
		if config.getboolean('settings', 'import-labels') and 'labels' in issue and issue['labels'] is not None:
			new_issue['label_objects'] = []
			for issue_label in issue['labels']:
				found_label = get_label_by_name(issue_label['name'])
				if found_label:
					new_issue['label_objects'].append(found_label)
				else:
					new_issue['label_objects'].append(issue_label)
					known_labels.append(issue_label) # Allow it to be found next time
					new_labels.append(issue_label)   # Put it in a queue to add it later
		
		template_data = {}
		template_data['user_name'] = issue['user']['login']
		template_data['user_url'] = issue['user']['html_url']
		template_data['user_avatar'] = issue['user']['avatar_url']
		template_data['date'] = format_date(issue['created_at'])
		template_data['url'] =  issue['html_url']
		template_data['body'] = issue['body']
		
		if "pull_request" in issue and issue['pull_request']['html_url'] is not None:
			new_issue['body'] = format_pull_request(template_data)
		else:
			new_issue['body'] = format_issue(template_data)
		
		new_issues.append(new_issue)

	if config.getboolean('settings', 'dry_run'):
		progress_msg('Dry run complete')
		state.current = state.COMPLETE
		sys.exit()
	
	state.current = state.IMPORT_CONFIRMATION
	
	print("You are about to add to '" + config.get('target', 'repository') + "':")
	print(" *", len(new_issues), "new issues") 
	print(" *", num_new_comments, "new comments") 
	print(" *", num_new_events, "new events") 
	print(" *", len(new_milestones), "new milestones") 
	print(" *", len(new_labels), "new labels") 
	if not config.getboolean('settings', 'yes'):
		if not query.yes_no("Are you sure you wish to continue?"):
			sys.exit()
	print()
	
	state.current = state.IMPORTING
	
	for milestone in new_milestones:
		result_milestone = import_milestone(milestone)
		milestone['number'] = result_milestone['number']
		milestone['url'] = result_milestone['url']
	
	for label in new_labels:
		result_label = import_label(label)
	
	result_issues = []
	for issue in new_issues:
		
		if 'milestone_object' in issue:
			issue['milestone'] = issue['milestone_object']['number']
			del issue['milestone_object']
		
		if 'label_objects' in issue:
			issue_labels = []
			for label in issue['label_objects']:
				issue_labels.append(label['name'])
			issue['labels'] = issue_labels
			del issue['label_objects']
		
		orig_issue_number = issue['orig_issue_number']
		del issue['orig_issue_number']
		orig_issue_closed = False
		if issue.get('orig_issue_closed') is not None:
			orig_issue_closed = True
			del issue['orig_issue_closed']

		issue_comments = None
		if 'comments' in issue:
			issue_comments = issue['comments']
			del issue['comments']
		issue_events = None
		if 'events' in issue:
			issue_events = issue['events']
			del issue['events']
		
		progress_msg('Creating new issue for original issue {0}, assignee: {1}'.format(orig_issue_number, issue.get('assignee')))
		progress_msg(' > {0}'.format(issue['title']))
		print()
		
		result_issue = send_request('target', "issues", issue, can_retry=False)
		progress_msg(' > Created issue {0} for original issue {1}'.format(result_issue['number'], orig_issue_number))
		
		if (issue_comments is not None and len(issue_comments) > 0) or (issue_events is not None and len(issue_events) > 0):
			import_comments_and_events(issue_comments, issue_events, result_issue['number'])
		
		if orig_issue_closed:
			progress_msg(' > Original issue {0} is CLOSED, closing the new issue {1}'.format(orig_issue_number, result_issue['number']))
			update_data = { 'state' : 'closed' }
			send_request('target', "issues/{0}".format(result_issue['number']), update_data)
		
		if config.getboolean('settings', 'lock_after_migrate'):
			progress_msg(' > Lock the original issue {0}'.format(orig_issue_number))
			send_request('source', "issues/{0}/lock".format(orig_issue_number), method="PUT", content_length=0, custom_media_type='application/vnd.github.the-key-preview+json')
			lock_comment_body = "**ISSUE HAS BEEN MIGRATED. PLEASE DO NOT ADD ANY UPDATES.**"
			lock_comment = {'body' : lock_comment_body}
			send_request('source', "issues/{0}/comments".format(orig_issue_number), lock_comment)
		
		result_issues.append(result_issue)
		
		progress_msg()
		time.sleep(5)
	
	state.current = state.IMPORT_COMPLETE
	
	return result_issues


if __name__ == '__main__':
	
	state.current = state.LOADING_CONFIG
	
	issue_ids = init_config()	
	issues = []
	
	state.current = state.FETCHING_ISSUES
	
	# Argparser will prevent us from getting both issue ids and specifying issue state, so no duplicates will be added
	if (len(issue_ids) > 0):
		issues += get_issues_by_id('source', issue_ids)
	
	if config.getboolean('settings', 'import-open-issues'):
		issues += get_issues_by_state('source', 'open')
	
	if config.getboolean('settings', 'import-closed-issues'):
		issues += get_issues_by_state('source', 'closed')
	
	# Sort issues based on their original `id` field
	# Confusing, but taken from http://stackoverflow.com/a/2878123/617937
	issues.sort(key=lambda x:x['number'])

	
	# Further states defined within the function
	# Finally, add these issues to the target repository
	import_issues(issues)
	
	state.current = state.COMPLETE


