# XMLAnonymizer
 In a nutshell this program replaces requested values or attributes with random strings.
   This replacement process can also be reversed by the program.

##Usage
 *python3 is required
    For Usage instructions use python3 XMLAnonymizer.py -h
   
 *Anonymize file
   python3 XMLAnonymizer.py -v -f sample.xml -anonymizedfile anonymized.xml
 
 *Reverse file
   python3 XMLAnonymizer.py -v -reverse -reversedfile reversed.xml -anonymizedfile anonymized.xml

 Values can be specified as a path consisting of tags, attribute names, attribute values and text values.
 Attribute values and text values may also be replaced in whole or in part via regular expression

 The original use case is to allow network and host scans to be shared or processed off-site
 without revealing potential identifiable, cryptologic or other exploitable information

 The intent was to process Nessus scans and allow data sharing and analysis on a public cloud.
 In reality the Nessus scans were highly unstructured and potential data leaks were likely.
 With about 100K existing plugins and almost 100 new ones developed per week, I could not recommend
 this or any anonymization process for this task. Module output is typically free text.
 Follow-on research into using gaussian distributions, n-grams and compression distances
 did not significantly reduce the risk of data leakage

 As this process can used on more structured data sets, such as evaluating NLP models, and other ML data sets
 I felt it was still useful to place this on github for use by others,

 Special note on human trials and other data collection covered by HIPAA. While this process can be used 
 to replace personal names and dates. Again the XML would have to be highly structured
 The system does not allow for any preservation of statistical distributions
 that would help in any meaningful population analysis. 
 If you have a requirement for this sort of processing please feel free to contact me as I have an 
 interest in the area, specifically the injection of noise and other leakage mitigation techniques.

 Data leakage may occur as the existing XML document stanzas are not randomized, which could lead
 to an order based attack. If this is a concern please let me know and I can add this feature.
