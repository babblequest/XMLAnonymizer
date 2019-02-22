# XMLAnonymizer
 * In a nutshell this program replaces requested values or attributes with random strings.
 * This replacement process can also be reversed using the -reverse flag.

## Usage:
* python3 is required
  * For Usage instructions use python3 XMLAnonymizer.py -h
* Anonymize file
  * python3 XMLAnonymizer.py -v -f sample.xml -anonymizedfile anonymized.xml
* Reverse file
  * python3 XMLAnonymizer.py -v -reverse -reversedfile reversed.xml -anonymizedfile anonymized.xml
* The values used to reverse the anonymization process are located in anonymized.txt.
* The value database and config file paths default to anonymized.txt and anonymized.cfg 

 Values can be specified as a path consisting of tags, attribute names, attribute values and text values.
 Attribute values and text values may also be replaced in whole or in part via regular expression.
 
 * Configuration File
   * The sample configuration file is named anonymizer.cfg and is used by default
   * There are two ways to specify values for replacement
     * Path 
       * Path:Report->ReportHost->name:Name_${A}
     * Value
       * Value:Nikto.*:Nikto-${U[0,Nikto]}
   * The typical rule
     * Path or Value:[Path or Value]:[String pattern to replace]:[String Generator]
        * Path or Value 
           * The Path specification
              * Path must start with a tag name
              * Follow on path elements may be attribute names, attribute values or text values
              * Any path elements may be specified with a regular expression following Pythons convention
              * Shorter paths are faster
              * Longer paths take precedence
           * The Value specification
              * Value may be any attribute value or text value
              * Values specified as regular expressions following python conventions         
     * String pattern to replace (optional)
          * You may specify a string pattern to replace a given substring in a value or path
          * If this is not specified the entire text value will be replaced
             * Value:here is the traceroute from\:from.*:RedactedTraceRoute-${U[0,iplist]}
                * Replace anything following from with RedactedTraceRoute-1
     * String Generator
        * Patterns can be made up of a combination of literal strings and generators
            * ${X}: hexadecimal - Create a hex value 
            * ${A}: alpha - Create a number using base 26 starting at a. ie. aaaa, aaab, aaac etc..
            * ${D}: decimal - Generate a decimal value
            * ${U}: oneup - Generate a oneup decimal value ie. 1, 2, 3, 4 etc...
            * Ranges may be given ie. 
               * ${X[0-F]} - will generate a value between 0 and F
               * ${D[100-200]} - will generate a value between 100 and 200
               * Alphabetic oneups start at the numeric value base 26 
                  * ${A[200, hostname]}
            * For oneup values you may specify a starting value and unique name
               * ${U[100, Hostnumber} - value starting at 100 and only incrementing for this value
       * Generators sequences look like this:
           * Name_${A} -> Name_aaaaa
           * No Date ${U[0,date]} -> No Date 0, No Date 1, No Date 2
           * ${X[0-F]}${X[0-F]}\:${X[0-F]}${X[0-F]}\:${X[0-F]}${X[0-F]}\: etc... -> mac address
           * ${D[192-223]}.${D[0-255]}.${D[0-255]}.${D[0-254]} -> Local IP Address
       * Non unique generators. If a generator can not create a unique value an error will occur, as it breaks reversability
* Any colons within the specification must be escaped using the backslash \:
* Builtin Patterns:
	* Builtin patterns can be found in the builtins.txt file
	* You may specify a pattern or generator to be used in your config file
	* Patterns are any legal regular expression
		* PATTERN:LOCAL_IP_ADDRESSC:192\.168\.[0-9]{1,3}\.[0-9]{1,3}
	* Generators can be any legal generator sequence
		* GENERATOR:EXTERNAL_IP_ADDRESSC:${D[192-223]}.${D[0-255]}.${D[0-255]}.${D[0-254]}     
    * Builtin values are used in the config file by escaping the name with ${}
        * Value:${MAC_ADDRESS}:${MAC_ADDRESS}
        * Path:tag->name->traceroute-hop-[0-9]+:${LOCAL_IP_ADDRESSC}
 
Rudementary sanity checking of the specification rules are done. All parsing is simply using regular expressions and not a grammar so all errors may not be caught. Use the -v flag to double check rules when creating a new config file.

Any values that are identified by path or value are double checked and replaced prior to program completion. Efforts are made to avoid replacing substrings by sorting by length prior to full replacement.

The original use case is to allow network and host scans to be shared or processed off-site without revealing potential infrastructure, cryptologic or other exploitable information

The original use case is to process Nessus scans and allow data sharing and analysis on a public cloud. However, Nessus scans are unstructured and potential data leaks were possible with about 100K existing plugins and almost 100 new ones developed per week, I recommend removing plugin output and double checking any new tags generated. Plugin output is typically free text. Follow-on research into using gaussian distributions, n-grams and compression distances did not significantly reduce the risk of data leakage for free form text output. The sample config file removes plugin output.

As this process can used on structured data sets, such as evaluating NLP models, and other ML data sets, I felt it was still useful to place this on github for use by others,

Special note on human trials and other data collection covered by HIPAA. While this process can be used to replace personal names and dates. Again the XML would have to be highly structured The system does not allow for any preservation of statistical distributions that would help in any meaningful population analysis.  If you have a requirement for this sort of processing please feel free to contact me as I have an interest in the area, specifically the injection of noise and other leakage mitigation techniques.

Data leakage may occur as the existing XML document stanzas are not randomized, which could lead to an order based attack. If this is a concern please let me know and I can add this feature.

Sample Nessus scan file is from DefectDojo/sample-scan-files by mtesauro
