# t0xodile's CORS Check
More scan checks because Burp's scanner is good, but I want more. 

To use simply install the extention and run an active scan. 

The CORS check will take the domain from a valid origin header and use that as a "trusted" domain to test bypasses on. Therefore it is worth running the scan against different requests with different Origin header values.

## Ideas
- Should be able to provide a list of in-scope domains / possibly trusted domains
- From this list, run subdomain enumeration on each domain
- From that final list, check for CORS implementations i.e. "Trusted Domains"
- From THAT list, try to bypass each trusted domain to find exploits for permissive cors

## TO-DO
- [x] Trigger simple cors check to find trusted domains based off of subdomain list + user input
- [x] Using list of then trusted domains, we need to run the cors scan against them....
- [x] Implement global settings that will allow disabling the trusted domains lookup - given that it can leak parent domain to third-party service
- [x] Add option to enable / disable scan check
- [x] Code improvements regarding duplicated functions
- [x] Add default list of trusted domains
- [x] Default list of trusted domains should possibly go into the scan check too? Optional?
- [ ] Bulk mode?
  - This would need to take a selection of requestResponses and run the cors check against each of those requests....
  - We can't prompt the user with a box to enter additional domains here right?
    - We could in a regular pentest I guess....
    - add a check and warning for "Selected multiple hosts"?
