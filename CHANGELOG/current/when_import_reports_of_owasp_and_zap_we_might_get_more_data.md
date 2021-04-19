FIX a validation to get the info "method" from the .xml changing the function from find to findtext

ADD the info of "attack" and "param" into data to show more info

CHANGE the structure of the reference CWE from CWE-12 to CWE:12

REPAIR some pylint with static_method, removing the try and except

CHANGE the function to extract params from url with a regex

FIX service name was hardcoded, now is set by report information

FIX references are now added in the proper

FIX readability of the descriptions, remediation & reference by stripping html tags

ADD now data includes the affected URL, Evidence & Affected Parameter when possible

ADD new function to strip html tags 

ADD included information in reference for WASC

ADD ZAP pluginid into external_id

CHANGE external_id to the correct Structure ZAP-XXXX
