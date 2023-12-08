# FMC-policy-hits
in cisco FMC, evaluate policy hits across all appliances in inventory

in the FMC you can perform a hit count analysis for a policy against a singe FTD appliance.  to see if a rule is taking hits on any device
you need to manually run the hit count for each FTD.  this script will perform hitcount analysis for a policy against all devices in inventory
and then offer multiple options on how to report in the output.

Detailed Report: One line item for every device that hits on a rule.  this can become big quickly for large policies and device inventories
Most Recent Hit Only: One line item per rule, listing only the device/timestamp with the most recent hit
Zero Hits Only: List only rules that have no hits across all devices


 BASE_URL needs to be updated with IP of your FMC

 Developed and tested with the following environment
 - OS: windows
 - Python: version 3.11.5
 - Target platform:  FMC 7.0.4
 - Limitations: functions to get policies, devices and policy hits lazily assume paging is not required.  
               updates to implement paging will be required if the query excedes a single page in your environment
 - Other comments:  code coule be updated to only perform check against devices actually assigned the policy rather than all devices in inventory.  
                   this wasn't required for the environment this code was written for
