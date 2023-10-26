import UIToolsP3
import mistapi
import json
import getopt
import sys

env_file = "~/.mist_env"
conf_file = None
org_id = None

problem_cases = []
junos_app_defs = {}
try:
    with open('JunosAppDefinitions.json', 'r') as jf:
        junos_app_defs = json.load(jf)
except FileNotFoundError:
    print('Could not find Junos App Definitions JSON file. If there are any Junos apps, they will be skipped')


def do_applications():
    print('Reading apps from '+conf_file+'...')
    junos_apps = read_apps_conf(conf_file)
    print('Reading adds from '+conf_file+'...')
    junos_adds = read_addresses_conf(conf_file)
    print('Reading policies from '+conf_file+'...')
    junos_policies = read_policies_conf(conf_file)
    mist_apps = {}
    for fztz in junos_policies.values():
        for policy in fztz["Policies"].values():
            for dapp_obj in policy.values():
                print(json.dumps(dapp_obj, indent=4))
                mist_app = {"name": dapp_obj["application"][0] + '-' + dapp_obj["destination-address"][0],
                            "type": "custom", "traffic_type": "default"}
                mist_app["specs"] = app_lookup(dapp_obj["application"], junos_apps)
                # for app in dapp_obj["application"]:
                #     if "specs" not in mist_app: mist_app["specs"] = []
                #     mist_app["specs"].append(app_lookup(app, junos_apps, return_list=False))

                for dadd in dapp_obj["destination-address"]:
                    if dadd in junos_adds:
                        dadd = junos_adds[dadd]
                    elif dadd == "any":
                        dadd = ["0.0.0.0/0"]
                    else:
                        problem_cases.append(dadd)

                if "wildcard-address" in dapp_obj["destination-address"]:
                    problem_cases.append(dapp_obj)
                else:
                    mist_app["addresses"] = dadd

                dapp_obj["mist_app"] = mist_app
                mist_apps[mist_app["name"]] = mist_app


    with open("final_policies_output.json", "w") as of:
        of.write(json.dumps(junos_policies, indent=4))
    with open('mist_apps.json', 'w+') as of:
        of.write(json.dumps(mist_apps, indent=4))

    if UIToolsP3.getBool(msg='Push to Mist? '):
        for mapp in mist_apps.values():
            response = mistapi.api.v1.orgs.services.createOrgService(apisession, org_id, mapp)
            print(response)
            if response.status_code != 200:
                problem_cases.append("Bad request for " + mapp["name"] + " response: " + str(response.data))
        mistapi.api.v1.orgs.services.createOrgService(apisession, org_id, mist_apps)

    with open("problem_cases_output.json", "w") as of:
        of.write(json.dumps(problem_cases, indent=4))

def read_apps_conf(conf_file):
    '''
    :param conf_file:
    :return: apps in the form of:
    apps = {
        '<Name>': {
            'protocol' = 'protocol'
            'destination-port' = 'port'
        }
        '<Group_Name>' = [
            {
                'protocol' = 'protocol'
                'destination-port' = 'port'
            }
        ]
    }
    '''
    apps = {}
    ofile = open(conf_file, 'r')
    for line in ofile:
        delimit = line.split(" ")
        if delimit[1] == "applications":
            if delimit[2] == "application":
                app_name = delimit[3]
                if app_name not in apps: apps[app_name] = {}
                apps[app_name][delimit[4]] = delimit[5].strip()
            elif delimit[2] == "application-set":
                app_set_name = delimit[3]
                app_name = delimit[5].strip()
                if app_name not in apps: print("Error: Can't find address "+app_name+" for address set "+app_set_name)
                if app_set_name not in apps:
                    apps[app_set_name] = [apps[app_name]]
                else:
                    apps[app_set_name].append(apps[app_name])
    return apps

def app_lookup(names, junos_apps):
    '''
    :param names: application names to lookup
    :param junos_apps: applications from conf file
    :return: built out application in form of:
    app = [
        {
            'protocol': 'protocol',
            'port_range': 'port_range'
        }
    ]
    '''
    ans = []
    for name in names:
        if name in junos_app_defs:
            ans.append(junos_app_defs[name])
        elif name in junos_apps:
            if type(junos_apps[name]) is list:
                for sub_app in junos_apps[name]:
                    ans.append({"protocol": sub_app["protocol"],
                             "port_range": sub_app["destination-port"]})
            else:
                ans.append({"protocol": junos_apps[name]["protocol"], "port_range": junos_apps[name]["destination-port"]})
        else:
            print("Could not find application for " + name)
            problem_cases.append("Application: "+name)

    #Mist seems to want single port apps to be "22-22" not just "22"
    #Not totally sure if required, better safe then sorry
    for app in ans:
        if "port_range" in app:
            if "-" not in app["port_range"]:
                app["port_range"] = app["port_range"]+"-"+app["port_range"]
    return ans

def read_addresses_conf(conf_file):
    '''
    :param conf_file:
    :return: dictionary of addresses in the form of:
    adds = {
        '<Name>': [list of adds]
    }
    '''
    ofile = open(conf_file, 'r')

    addresses = {}
    raw_address_sets = []
    for line in ofile:
        if line.startswith("set security address-book"):
            delimit = line.split(" ")
            if delimit[4] == "address-set":
                raw_address_sets.append(line)
            else:
                address_name = delimit[5]
                address_ip = delimit[6].strip()
                addresses[address_name] = [address_ip]

    for line in raw_address_sets:
        delimit = line.split(" ")
        set_name = delimit[5]
        add_name = delimit[7].strip()
        if add_name in addresses:
            add_ip = addresses[add_name]
        else:
            print("Error: Can't find address "+add_name+" for address set "+set_name)
            continue

        if set_name in addresses:
            for ip in add_ip:
                addresses[set_name].append(ip)
        else:
            for ip in add_ip:
                addresses[set_name] = [ip]

    return addresses

def read_policies_conf(conf_file):
    '''
    :param conf_file:
    :return: policy dict in form of:
    policies_dict: {
        'fromzone-tozone': {
            'FromZone': zone,
            'ToZone': zone,
            'Policies': {
                'policy': {
                    'source-address': [addresses]
                    'destination-address': [addresses]
                    'application': [applications]
                }
            }
        }
    }
    '''
    ofile = open(conf_file, 'r')

    policies_dict = {}
    cur_match_set = {}
    for line in ofile:
        if line.startswith("set security policies from-zone"):
            delimit = line.split(" ")
            from_zone = delimit[4]
            to_zone = delimit[6]
            policy_name = delimit[8]
            if delimit[9] == "match":
                match_type = delimit[10]
                match_criteria = delimit[11].strip()
                if match_type in cur_match_set:
                    cur_match_set[match_type].append(match_criteria)
                else:
                    cur_match_set[match_type] = [match_criteria]
            elif delimit[9] == "then":
                zone_name = from_zone + '-' + to_zone
                name_dadd = cur_match_set["destination-address"] if type(cur_match_set["destination-address"]) is not list else cur_match_set["destination-address"][0]
                name_app = cur_match_set["application"] if type(cur_match_set["application"]) is not list else cur_match_set["application"][0]
                application_name = name_dadd+'-'+name_app
                if zone_name not in policies_dict: policies_dict[zone_name] = {}
                policies_dict[zone_name]['FromZone'] = from_zone
                policies_dict[zone_name]['ToZone'] = to_zone
                if "Policies" in policies_dict[zone_name]:
                    policies_dict[zone_name]["Policies"][policy_name] = {application_name: cur_match_set}
                else:
                    policies_dict[zone_name]["Policies"] = {policy_name: {application_name: cur_match_set}}
                cur_match_set = {}

    return policies_dict

def usage():
    print('''
-------------------------------------------------------------------------------

    Written by Eli Wulff (ewulff@juniper.net)

    This script is licensed under the MIT License.

-------------------------------------------------------------------------------
Description:
Python script to convert SRX security to policy to Mist. 

-------
Requirements:
mistapi: https://pypi.org/project/mistapi/

-------
Usage:
This script can be run as is (without parameters), or with the options below.
If no options are defined, or if options are missing, the missing options will
be asked by the script or the default values will be used.

It is recomended to use an environment file to store the required information
to request the Mist Cloud (see https://pypi.org/project/mistapi/ for more 
information about the available parameters).

-------
Script Parameters:
-h, --help              display this help
-o, --org_id=           Set the org_id
-e, --env=              define the env file to use (see mistapi env file 
                        documentation here: https://pypi.org/project/mistapi/)
                        default is "~/.mist_env"

-------
Examples:
python3 ./org_conf_backup.py
python3 ./org_conf_backup.py --org_id=203d3d02-xxxx-xxxx-xxxx-76896a3330f4 

''')
    sys.exit(0)

main_menu = UIToolsP3.Menu('Main Menu')
main_menu.menuOptions = {'Push Applications': do_applications}

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ho:e:c:", [
                                   "help", "org_id=", "env=", "conf_file="])
    except getopt.GetoptError as err:
        usage()

    for o, a in opts:
        if o in ["-h", "--help"]:
            usage()
        elif o in ["-o", "--org_id"]:
            org_id = a
        elif o in ["-e", "--env"]:
            env_file = a
        elif o in ["-c", "--conf_file"]:
            conf_file = a
        else:
            assert False, "unhandled option"

    global apisession
    apisession = mistapi.APISession(env_file=env_file)
    apisession.login()
    if not org_id: org_id = mistapi.cli.select_org(apisession)[0]
    main_menu.show()
