from pyretic.lib.corelib import *
from pyretic.lib.std import *

# insert the name of the module and policy you want to import
from pyretic_switch import act_like_switch
import csv
import os
policy_file = "%s/pyretic/pyretic/examples/firewall-policies.csv" % os.environ[ 'HOME' ]

def main():
    # start with a policy that doesn't match any packets
    not_allowed = none
    csvFile = open("%s/pyretic/pyretic/examples/firewall_policies.csv"% os.environ[ 'HOME' ], 'r')
    csv_reader  = csv.DictReader(csvFile)
    # and add traffic that isn't allowed
    for item in csv_reader:
        not_allowed = not_allowed+(match(srcmac=MAC(item['mac_0']))&match(dstmac=MAC(item['mac_1'])))+(match(srcmac=MAC(item['mac_1']))&match(dstmac=MAC(item['mac_0'])))

    # express allowed traffic in terms of not_allowed - hint use '~'
    allowed = ~not_allowed

    # and only send allowed traffic to the mac learning (act_like_switch) logic
    return allowed >> act_like_switch()



