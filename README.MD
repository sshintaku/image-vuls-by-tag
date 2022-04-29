# Purpose of the Program
The purpose of this GOLANG based utility is create a report that will show all vulernabilities based on owner of the resource.  The owner of the resource is defined by tags on the resource.  For example, one client has a tag called "maintainer:".  This will display sort the output by maintainer.  If the client has 13 maintiners, it will create 13 sections and break down all the images that are owned by that mainatiner and display vulnerabilities based on each maintainer.  Customer's needed this type of report to determine which developers and or stakeholders they needed to discuss these vulnerabilities with.


## Requirements

First and fore most to utilize the application there are two environment variables that need to be set for the application to use API backends to do any RestAPI calls to the prisma backend.  The environment variables are the following:

APIKEY
PASSWORD

The APIKEY environment variable is the Key (sometimes referred to as Access Key Id) in the Access Keys and the PASSWORD (sometimes referred to as Secret Id) varible is the Value of the Access Keys.  If these environment variables are not set, the application will simply error out.  

## The Parameters

The parameters for the utility will be read from a file called ".parameter.json".  As the name implies, the program expects a JSON structure to instruct the program how to behave.  The program is designed to be as flexible as possible.  The following are the parameters that the application will use to process the image data.

### AlarmLevels

This is an array of alarm levels that you want the program to resport on.  For example, if only critical alarms are needed, simply have a .parameter.json file such as the following:

{
    "AlarmLevels" : ["critical"],
    "RegEx" : "^maintainer:",
    "FixDate" : 0
}

If the program needs to report on different vulerability levels such as "crictial" and "high", the array can be appeneded such as the following:

{
    "AlarmLevels" : ["critical", "high"],
    "RegEx" : "^maintainer:"
    "FixDate" : 0
}

## RegEx

The RegEx parameter is just as the name implies a regular expression.  This regular expression is used to find labes associated with the image to build a collection of images that match the regular expression.  For example, a customer has a label called "maintainer:devgroupA@digitalsystem.com".  This label is a tag used to let the IT staff know that the image belongs to devgroupA.  The report will use this label or tag to build a collection based on this group and display the images of that group.  The regular expression needed would be the following: "^maintainer:".  Note that the regular expression notation starting with a "^"symbol is to match from the begining of the string followed by the string "maintainer:".  Therefor the regular expression will match "maintainer:devOpsA@domainname.com" but will NOT match with the following:

"Maintainer:devOpsA@domainname.com"
"App_maintainer:devOpsA@domainname.com"
"maintainer=devOpsA@domainname.com"

## FixDate

The FixDate parameter is to filter out days prior to the number of day from today.  For example, if 90 is specified in the FixDate parameter, it will display the vulnerabilities that have fixes before 90 days of the current date.


