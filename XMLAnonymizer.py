## XMLAnonymizer.py

## In a nutshell this program replaces requested values or attributes with random strings.
##   This replacement process can also be reversed by the program.
##
##  python3 is required
##   For Usage instructions use python3 XMLAnonymizer.py -h

## Anonymize file
##   python3 XMLAnonymizer.py -v -f sample.xml -anonymizedfile anonymized.xml
## 
## Reverse file
##   python3 XMLAnonymizer.py -v -reverse -reversedfile reversed.xml -anonymizedfile anonymized.xml

## Values can be specified as a path consisting of tags, attribute names, attribute values and text values.
## Attribute values and text values may also be replaced in whole or in part via regular expression

## The original use case is to allow network and host scans to be shared or processed off-site
## without revealing potential identifiable, cryptologic or other exploitable information

## The intent was to process Nessus scans and allow data sharing and analysis on a public cloud.

## This process can used on more structured data sets, such as evaluating NLP models, and other ML data sets

## Special note on human trials and other data collection covered by HIPAA. While this process can be used 
## to replace personal names and dates. Again the XML would have to be highly structured
## The system does not allow for any preservation of statistical distributions
## that would help in any meaningful population analysis. 
## If you have a requirement for this sort of processing please feel free to contact me as I have an 
## interest in the area, specifically the injection of noise and other leakage mitigation techniques.

## Data leakage may occur as the existing XML document stanzas are not randomized, which could lead
## to an order based attack. If this is a concern please let me know and I can add this feature.

import argparse
import re
import random
import xml.etree.ElementTree as ET
import os
from pathlib import Path

from collections import defaultdict

replacements = defaultdict(list)

# Parse replacement rule file and populate replacements list
def parseConfigFile(configfile, replacements):
    # Set of allowed matcher names
    PATH = "Path"
    VALUE = "Value"

    matchers = { PATH, VALUE}     

    # Grab replacement parameters
    with open(configfile) as fp:
        line = fp.readline()
        lineno = 1
        generatorSequence = []
        while line:
            if (line[0:1] != '#' and len(line.strip()) != 0):
                noComments = line.split('#') # remove any appended comments
                # split parameters but allow colon delimiter to be escaped
                parameters = re.split(r'(?<!\\):', noComments[0], 3) # break into parameters
                deslash(parameters) # remove escapements for colons
                # parameters are [Path|Value]:pattern:replacement
                if (len(parameters) != 3) and (len(parameters) != 4):
                    print("Error: invalid format line %d: " % (lineno))
                    print("  Format should be [Path|Value]:pattern:replacement")
                    raise AnonymizerError("Error: Invalid format", "Invalid format on line %d: " % (lineno))
                else:
                    if (len(parameters) == 3):
                        node = parameters[0] # should standardize on path for search param
                        path = parameters[1] # use pattern just for sub string correction
                        generators = parameters[2]
                        pattern = None # if no pattern provided then replace entire string
                    else:
                        node = parameters[0]
                        path = parameters[1]
                        pattern = parameters[2]
                        generators = parameters[3]
                        
                    generatorSequence = parseGenerators(generators)
                    if (node == VALUE):
                        replacements[node].append(ValueReplacement(path, pattern, generatorSequence, lineno))
                    elif (node == PATH):
                        replacements[node].append(PathReplacement(path, pattern, generatorSequence, lineno))
                    else:
                        print("Error: node type " + node + " unknown allowed types are: " + str(matchers))
                        raise AnonymizerError("Error: Unknown type in replacement rule allowed types are: " + str(matchers)) #else:
            generatorSequence = []
            line = fp.readline()
            lineno += 1
    
    if verbose:
        print("Dumping rules: Please double check!!")
        for node, types in replacements.items():
            print("Replacement type " + node)
            for replacement in types: #         value = ''
                print("\t" + str(replacement))

builtinPatterns = dict()
builtinGenerators = dict()

def parseBuiltins(builtinPatterns, builtinGenerators):
    #Load builtin patterns and generators
    filepath = "./builtins.txt"
    with open(filepath) as fp:
        line = fp.readline()
        lineno = 1
        sequence = []
        while line:
            if (line[0:1] != '#' and len(line.strip()) != 0):
                line = line.strip()
                noComments = line.split('#') # remove any appended comments
                parameters = re.split(r'(?<!\\):', noComments[0], 2) # break into parameters
                deslash(parameters) # remove escapements for colons
                # parameters are [Path|Value]:pattern:replacement
                if (len(parameters) != 3):
                    print("Error: Invalid format line %d: " % (lineno))
                    print("  Format should be [PATTERN|GENERATOR]:name:[regex|anonymizer generator]")
                    raise AnonymizerError("Error: Invalid format", "Invalid format on line %d: " % (lineno))
                else:
                    operation = parameters[0]
                    name = parameters[1]
                    if (operation == "GENERATOR"):
                        generator = parameters[2]
                        sequence = parseGenerators(generator)
                        builtinGenerators[name] = sequence
                        sequence = []
                    elif operation == "PATTERN":
                        pattern = parameters[2]
                        builtinPatterns[name] = pattern
                    else:
                        raise AnonymizerError("Builtin file formating error", "Error in builtin file format line number: " + str(lineno))
            line = fp.readline()
            lineno += 1

# Check to see if this entry could specify a builtin pattern
#  builtins are of the form ${BUILTIN_NAME} builtins must be longer then 2 characters
def builtinCheck(generator):
    builtinName = None
    regexPattern2 = r'\$\{([A-Z0-9][A-Z0-9_-]+)\}'
    regex2 = re.compile(regexPattern2)
    possibleMatch = regex2.search(generator)
    if (possibleMatch != None):
        builtinName = possibleMatch.group(1)
    return builtinName

# Parse the generator specification
    # D - Random Digit with specified range
    # X - Random hex digit  with specified range
    # A - Onup digit made up of letters only
    # U - Oneup integer
    #  
    #  A, U - [starting value, label]
    #  D, X - [low value - high value]
def parseGenerators(generators):
    generators = generators.strip()

    lastEnd = 0
    generatorSequence = []
     
    builtinName = builtinCheck(generators)
    if builtinName != None:
        if (builtinName in builtinGenerators):
            generatorSequence = builtinGenerators[builtinName]
        else:
            print ("Error: Unknown builtin generators " + builtinName)
            raise AnonymizerError("Error: Builtin pattern not found", "Builtin pattern not found " + builtinName)
    else:                                                                    
        regexPattern = r'\$\{([DAXU])((\[[0-9]+\-[0-9]+\])|(\[[A-F0-9]+\-[A-F0-9]+\])|(\[[0-9]+\,[A-Za-z]+\]))?}'
        regex = re.compile(regexPattern)
        for match in regex.finditer(generators):
            if (match.group(2) != None):
                matchRange = match.group(2)
            else:
                matchRange = ''
            # append any literal data 
            generatorSequence.append(generators[lastEnd:match.start()])
            # create generators requested (we only get here is we have a valid generators requested)
            generatorSequence.append(Generator(match.group(1), matchRange))
            lastEnd = match.end()
        # append last bit of left over literal string to this generatorSequence
        generatorSequence.append(generators[lastEnd:])
    return generatorSequence

TEXT = "TEXT"  # text of XML tag

# Dictionary holding original and anonymized values
anonymizedSet = {}
reversalSet = {}

duplicateValueSet = set() #FIXME need to add all current xml values to this set
                            #  to ensure painless roundtripping
                          
oneupCounters     = {'default' : 1000} # if no counter label is supplied just start at 0
oneupAlphaCounter = {'default' : 475254}  # aaaaa - not starting at zero to avoid any overlaps
                                        #    ran into things like (host_a)ddress, where replacement was host_${A}

class Error(Exception):
    pass

# Generic exception for irrecoverable errors
class AnonymizerError(Error):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

# replace string with new value and store in lookup tables to avoid using it again         
def performStringReplace(originalString, replacement, newSubString): 
    pattern = replacement.getPattern()
    for originalSubMatch in pattern.finditer(originalString):
        originalSubString = originalSubMatch.group(0)  # text for entire regex
        if (len(originalSubString) > 0):
            replacement.trackRule(originalString, newSubString)
            anonymizedSet[originalSubString.upper()] = newSubString.upper() # all upper ala microsoft 
            anonymizedSet[originalSubString.lower()] = newSubString.lower() # all lower ala linux
            anonymizedSet[originalSubString] = newSubString # mixed case as user probably desired
            
            # add to full list of anonymized values to avoid generating duplicate replacements
            duplicateValueSet.add(newSubString.upper())
            duplicateValueSet.add(newSubString.lower())
            duplicateValueSet.add(newSubString)
    
    if (len(newSubString) == 0):
        print ("Error: replacement is of zero length for label " + originalString)
        raise AnonymizerError("Error: String Generation Error", "Using string generation rule " + repr(replacement) + " output string is of zero length")

    finalString = pattern.sub(originalString, newSubString)
    return(finalString) 

# Check to make sure text matches pattern then replace
def checkAndReplace(replacement, node, key):
    if (key == "TEXT"):
        if (node.text == None):
            node.text = "Empty String"

    if (key == "TEXT"):
        if (replacement.getPattern() == None) or (replacement.getPattern().search(node.text) != None):
            newString = getNewString(anonymizedSet,node.text, replacement)
            node.text = performStringReplace(node.text, replacement, newString)
    else:
        value = node.get(key)
        if (replacement.getPattern() == None) or (replacement.getPattern().search(value) != None):
            newString = getNewString(anonymizedSet, key, replacement)
            node.set(key,performStringReplace(value, replacement, newString))

# Dump all anonymized strings so far to allow anonymizing follow on results with more data
def dumpAnonymizationData(args, anonymizedSet):
    try:
        with open(args.values, 'wb') as csvfile:
            for original, anonymized in anonymizedSet.items():
                original = original.replace(",",'&#58;')
                csvfile.write(("R,%s," % (str(original))).encode('unicode_escape'))
                csvfile.write(anonymized.encode('unicode_escape'))
                csvfile.write(b"\n")
            
            for key, counter in oneupCounters.items():
                csvfile.write(bytes("U,%s,%s" % (key, str(counter)), "utf8"))
                csvfile.write(b'\n')
            
            for key, counter in oneupAlphaCounter.items():
                csvfile.write(bytes("A,%s,%s" % (key, str(counter)), "utf8"))
                csvfile.write(b'\n')
    except IOError:
        print("Error: Error reading in existing anonymized values")
        raise  # rethrow exception

treeIndex = dict() # hash table of node.tags to the list of nodes with that label

# Index tree to allow faster path lookup. Shorter paths are faster
def indexTree(tree):
    for node in tree.iter():
        if (not node.tag in treeIndex):
            newList = [node]
            treeIndex[node.tag] = newList
        else:
            existingList = treeIndex[node.tag]
            existingList.append(node)

# Path search operations. Can search through tags, attributes, attribute values and text values.
#   However, each step has differing follow on steps        
def addChildren(treeNode):
    childList = []
    for elem in list(treeNode):
        childList.append(PathItemTag(elem)) 
    return(childList)
def addAttributes(treeNode):
    attrList = []
    for key in treeNode.keys():
        attrList.append(PathItemAttribute(treeNode, key)) 
    return(attrList)                
def addText(treeNode):
    textList = []
    if (treeNode.text != None):
        textList.append(PathItemText(treeNode))
    return(textList)
def addValue(treeNode, key):
    valueList = []
    if (treeNode.get(key) != None):
        valueList.append(PathItemValue(treeNode,key))
    return(valueList)

class PathItem():
    def __init__(self, node):
        self.node = node

# Tag that is part of Path        
class PathItemTag(PathItem):
    def __init__(self, node):
        super(PathItemTag, self).__init__(node)
    def getNewList(self, pathStep):
        newList = []
        if (pathStep.match(self.node.tag)):
            newList.extend(addChildren(self.node))
            newList.extend(addAttributes(self.node))
            newList.extend(addText(self.node))
        return newList
    def __str__(self):
        return("TAG:" + self.node.tag)
    def __repr__(self):
        return("TAG:" + self.node.tag)
 
# Attribute key that is part of path           
class PathItemAttribute(PathItem):
    def __init__(self, node, key):
        super(PathItemAttribute, self).__init__(node) 
        self.key = key
    def getNewList(self, pathStep):
        newList = []
        if (pathStep.match(self.key)):
            newList.extend(addValue(self.node, self.key))
            newList.extend(addChildren(self.node))  # not sure this makes sense path would be tag id and attribute name not value 
                                                    # but for completeness we will add it here.
        return newList
    def __str__(self):
        return("Attribute:" + self.node.tag + "->" + self.key)
    def __repr__(self):
        return("Attribute:" + self.node.tag + "->" + self.key)

# Value that is part of path               
class PathItemValue(PathItem):
    def __init__(self, node, attribute):
        super(PathItemValue, self).__init__(node)
        self.attribute = attribute
    def getNewList(self, pathStep):
        newList = []
        if (pathStep.match(self.node.get(self.attribute))): # end of search path if still matching add children nodes
            newList.extend(addChildren(self.node))
            newList.extend(addText(self.node))
        return(newList)
    def replaceValue(self, pathReplacement):
        checkAndReplace(pathReplacement, self.node, self.attribute)
    def __str__(self):
        return("AttributeValue:" + self.node.tag + "->" + self.attribute + "->" + self.node.get(self.attribute))
    def __repr__(self):
        return("AttributeValue:" + self.node.tag + "->" + self.attribute + "->" + self.node.get(self.attribute))

# Text that is part of path   
class PathItemText(PathItem):
    def __init__(self, node):
        super(PathItemText, self).__init__(node)
    def getNewList(self, pathStep ):
        newList = []
        if (self.node.text != None):
            if pathStep.match(self.node.text): # end of search path if still matching add children nodes
                newList.extend(addChildren(self.node))
        return(newList)
    def replaceValue(self, pathReplacement):
        checkAndReplace(pathReplacement, self.node, TEXT)

    def __str__(self):
        return("Text:" + self.node.tag + "->" + str(self.node.items()) + "->" + self.node.text)
    def __repr__(self):
        return("Text:" + self.node.tag + "->" + str(self.node.items()) + "->" + self.node.text)

# The main anonymizer loop                  
def anonymize(tree, replacements):
    global TEXT, anonymizedSet
    # create node tree object
    loadAllCurrentValues(tree)
    root = tree.getroot()
    
    indexTree(tree)
    
# replace tags
    paths = replacements.get("Path")
    for pathReplacement in paths:
        initialTagId = pathReplacement.getFirstPathStep()
        if (initialTagId in treeIndex):
            nodeList = treeIndex[initialTagId]
            for initialNode in nodeList:
                scanList = [PathItemTag(initialNode)]
                for regex in pathReplacement.getRegexPath():  # step through out path comparing tags, attributes, values and text
                    nextScanList = []
                    for scanElement in scanList:
                        nextScanList.extend(scanElement.getNewList(regex))
                    scanList = nextScanList
                # ok if we have any matchers left we can update them with generateor values
                for scanElement in nextScanList:
                    if (isinstance(scanElement, PathItemText) or isinstance(scanElement, PathItemValue)):
                        scanElement.replaceValue(pathReplacement)

# Replace any values that match an expression provided
    paths = replacements.get("Value")
    for node in root.iter():
        for pathReplacement in paths:
            if (node.text != None):
                if (pathReplacement.getPath().match(node.text)):
                    checkAndReplace(pathReplacement, node, TEXT)
            for key in node.keys(): # attribute values
                if (pathReplacement.getPath().search(node.get(key))):
                    checkAndReplace(pathReplacement, node, key)
    
    if verbose:
        # Dump tracking information if verbose flag set
        print ("Replacements used:")
        for paths in replacements.values():
            for replacement in paths:    
                ruleTriggers = replacement.getRuleTracking()
                for original, anonymized in ruleTriggers.items():
                    print ("\t Line number: " + str(replacement.getLineNo()) + " (triggered " + str(replacement.getReplacementCount(original)) + " times) " + str(original) + "->" + str(anonymized))

# Sort keys by length to avoid any matches or replacements that affect a substring.
#   Example Number_1 and Number_11 - need to replace Number_11 first
def sortByStringLength(stringSet):
    keysByLength = list()
    # sort current values by length
    for nextString in stringSet:
        i = 0
        inserted = False
        while i < len(keysByLength) and not inserted:
            if len(nextString) > len(keysByLength[i]):
                keysByLength.insert(i, nextString)
                inserted = True
            i = i + 1
        
        if (not inserted):
            keysByLength.append(nextString)
    
    return keysByLength

# Got through and replace all values with new replacement value
def literalReplace2(tree, replacementSet, ignoreCase):   # used to reverse anonymize operation and double checking replacements
    if (ignoreCase):
        caseFlag = '(?i)'
    else:
        caseFlag = ''
    
    # sort keys by length to avoid inadvertantly replacing substrings     
    keysByLength = sortByStringLength(replacementSet.keys())

    # apply in order 
    # search for entry in set first then 
    #    Replace any values that match an expression provided
    root = tree.getroot()

    for node in root.iter():
        for anonymized in keysByLength:
            original = replacementSet[anonymized]
            if (node.text != None):
                anonText = node.text
                node.text = re.sub(caseFlag+re.escape(anonymized), original, anonText)
            for key,value in node.items(): # attribute values
                    anonText = value
                    node.set(key, re.sub(caseFlag+re.escape(anonymized),original, anonText))

# Once we replace a value then go through and make sure all occurances are replaced. 
#   First iteration replaces values with equivelent case 
#   Second iteration replaces using case insensitive matches                                     
def literalReplace(tree, replacementSet):
    literalReplace2(tree, replacementSet, False)
    literalReplace2(tree, replacementSet, True)
    
# Go through entire XML document and save all string values to avoid replacing values
# with duplicate entries              
def loadAllCurrentValues(tree):
    global duplicateValueSet
    root = tree.getroot() 
    for node in root.iter():
        if (node.text != None):
            duplicateValueSet.add(node.text)
        for key, value in node.items():  # attribute values
            duplicateValueSet.add(str(value))

# Grab existing list of replacement values also grab any oneup values to carry on where we left off            
def loadAnonymizedItems(csv_file):
    with open(csv_file) as f:
        for line in f:
            items = line.strip().rsplit(',',3)
            if (items[0] == "R"): # R = replacement 
                replacementValue = items[1]
                anonymizedItem = bytearray(items[2].replace("&#58;",","), 'utf8').decode('unicode_escape')
                reversalSet[anonymizedItem] = replacementValue
                anonymizedSet[replacementValue] = anonymizedItem
            elif items[0] == "U":   # "U = oneup counter
                oneupCounters[items[1]] = int(items[2])
            elif items[0] == "A":   # alpha oneup counter
                oneupAlphaCounter[items[1]] = int(items[2])

# Look for values that first matching case exactly then using case insensitive comparison
#  Have seen a lot of values being duplicated but with a mixture of casing varients
def checkSet(wordDict, word):   
    for key, value in wordDict.items():  # match case exactly first
        if (re.fullmatch(re.escape(key), word) != None):
            return(value) 
    for key, value in wordDict.items(): # if not a match use case insenstive matching
        if (re.fullmatch('(?i)'+re.escape(key), word) != None):
            return(value)
    return(None)

# Exhaustive search through all existing strings to avoid any unforeseen substring replacements
#   during reversal process
def isDuplicateSubString(substring):  
    global duplicateValueSet    
    for entry in duplicateValueSet: 
        if (substring in entry):
            return(True)
    return(False)

# Generate a new string using generation sequence. If a new string fails to be generated after 20 iterations then
# the generation rule probably does not produce a unique string value and is not going to work. 
def getNewString(anonymizedSet, label, replacement):
    tries = 0
    if (checkSet(anonymizedSet, label) != None):
        newString = checkSet(anonymizedSet, label)
    else:
        newString = replacement.generateNewString()
        #FIXME need to check substrings for only limit to complete value replacement no substrings
        # example "n" generated will replace all n's in xml doc (not good)
        while (newString in anonymizedSet or newString in duplicateValueSet or isDuplicateSubString(newString)) and tries < 20:
            newString = replacement.generateNewString()
            tries = tries + 1
            
    if (tries == 20):
        print ("Error: generation rule for value " + repr(replacement) + " can not generate a unique entry (can not de-anonymize)")
        raise AnonymizerError("Error: String Generation Error", "Using string generation rule " + repr(replacement) + " created non unique value " + newString + " we can not reverse anonymization")
    
    return newString

# need to convert string or int to definite int value
def ensureInt(unknownVar, base): 
    if type(unknownVar) is int:
        return(unknownVar)
    else:
        return(int(unknownVar,base))

# increment oneup value. Each value can have a unique key string     
def incrementOneup(counterDict, startingValue, counterName):
    if (counterDict[counterName] == None):
        counterDict[counterName] = startingValue
    else:
        counterDict[counterName] = counterDict[counterName] + 1
    return(counterDict[counterName])

# generate oneup value using lower case letters. 
def alpha(low, high):
    #  algorithm by Ben Taitelbaum
    result = ''
    num = incrementOneup(oneupAlphaCounter, low, high)
    while num > 0:
        num = num - 1       # 1 => a, not 0 => a
        remainder = num % 26
        remainder = int(remainder)  # odd math behavior generates float in some instances
        digit = chr(remainder+ord('a'))
        result = digit + result
        num = (num - remainder) / 26
    return(result) 

# generate random hex value within range                
def hexadecimal(low, high):
    value = random.randint(ensureInt(low,16), ensureInt(high,16))
    return('{:x}'.format(value))

# generate random int value within range
def decimal(low, high):
    value = random.randint(low, high)
    return('{:d}'.format(value))

# generate onup digit value within range
def oneup(low, high):
    global oneupCounters
    return(str(incrementOneup(oneupCounters, low, high)))

# NOTE: No dates can create regex replacement rules as needed there are many varients (too many)  

# lookup table of functions   
methods = {
        "X": hexadecimal,
        "A": alpha,
        "D": decimal,
        "U": oneup
        }  

# Generator of new values parse specification and store needed parameters
class Generator:         
    def __init__(self, method, params):
        self.methodID = method
        self.method = methods[method]
        pattern = r'\[([0-9]+)\-([0-9]+)\]|\[0x([A-F0-9]+)\-(0x[A-F0-9]+)\]|\[([0-9]+)\-([A-Za-z]+)\]'
        regex = re.compile(pattern)
        match = regex.search(params)
        if (match != None and match.group(1) != None):
            low = int(match.group(1))
            high = int(match.group(2))
        if (method == 'D'):
            low = 0
            high= 9
        if (match != None and match.group(3) != None):
            low = int(match.group(3),16)
            high= int(match.group(4), 16)
        if (method == 'X'):
            low = 0x0
            high = 0xF
        if (match != None and match.group(5) != None):
            low = int(match.group(5))
            high = match.group(6)
            
        if (method == 'A'):
            low = 475254  ## aaaaa
            high = "default"  
        if (method == "U"):
            low = 0
            high = "default"
            
        self.lowValue = low
        self.highValue = high
                 
    def __str__(self):
        return(self.method(self.lowValue, self.highValue))
    def __repr__(self):
        return(self.methodID + "[" + str(self.lowValue) + "-" + str(self.highValue) + "]")

# Replacement specification holds all parameters for this particular replacement operation
class Replacement:
    def __init__(self, path, pattern, generators, lineno): 
        ## Pattern controls string replace within the specified string.
        ##   If pattern is not defined then use regex .* to replace entire string  
        self.rawPattern= pattern
        if (pattern != None):
            builtinName = builtinCheck(pattern)
            if (builtinName != None):
                if builtinName in builtinPatterns:
                    pattern = builtinPatterns[builtinName]
                else:
                    print ("Error: Requested builtin pattern is not in list " + builtinName)
                    raise AnonymizerError("Error: Builtin pattern does not exist", "Builtin pattern does not exist for this rule line number: " + str(lineno))
            self.pattern = re.compile(pattern, flags=re.DOTALL)
        else:
            self.pattern = re.compile(".*", flags=re.DOTALL)  # replace entire string
        
        # Path to the string that we want to replace.
            # Note actual path following logic is below in sub classes
            #  you can replace a tag path or a attribute or text value that matches a regex
        self.rawPath = path
        self.path = None
        
        builtinName = builtinCheck(path)
        if (builtinName != None):
            if builtinName in builtinPatterns:
                path = builtinPatterns[builtinName]
            else:
                print ("Error: Requested builtin pattern is not in list " + builtinName)
                raise AnonymizerError("Error: Builtin pattern does not exist", "Builtin pattern does not exist for this rule line number: " + str(lineno))

        self.generators = generators
        self.triggerCount = 0
        self.lineno = lineno
        self.ruleTracking = dict()
        self.triggerCounts = dict()
    def getPath(self):
        return self.path
    def getPattern(self):   #pattern is compiled regex
        return self.pattern
    def getGenerators(self):
        return self.generators
    def generateNewString(self):
        newString = ''
        for part in self.getGenerators():
            newString = newString + str(part)
        return newString
    def getLineNo(self):
        return(self.lineno)
    def trackRule(self, original, anonymized):
        self.ruleTracking[original] = anonymized
        if (not original in self.triggerCounts):
            self.triggerCounts[original] = 1
        else:
            self.triggerCounts[original] += 1
    def getRuleTracking(self):
        return(self.ruleTracking)
    def getReplacementCount(self, original):
        return(self.triggerCounts[original])
    def __str__(self):
        return("Line " + str(self.lineno) + ": " + self.rawPath + " " +
               str(self.rawPattern) + " " + str(self.generators))
    def __repr__(self):
        return("Line " + str(self.lineno) + ":" + self.rawPath + " " +
               str(self.rawPattern) + " " + str(self.generators))

# Replacement of attribute or text value matching a regular expression
class ValueReplacement(Replacement):
    def __init__(self, path, pattern, generators, lineno): 
        super(ValueReplacement, self).__init__(path, pattern, generators, lineno)
        self.rawPattern= pattern
        
        if (self.path == None):
            self.rawPath = path            
            self.path = re.compile(path)
    def __str__(self):
        return("Line " + str(self.lineno) + ": " + self.rawPath +  " " +
               str(self.rawPattern) + " " + str(self.generators))
    def __repr__(self):
        return("Line " + str(self.lineno) + ":" + self.rawPath + " " +
               str(self.rawPattern) + " " + str(self.generators))

# Replacement of attribute or text value that follows a path made up of tags, attributes, attribute values, and texts            
class PathReplacement(Replacement):    
    def __init__(self, path, pattern, generators, lineno):  
        super(PathReplacement, self).__init__(path, pattern, generators, lineno)
        if (self.path == None):
            # path specified as (tag/attribute/attribute value or text value)->(etc...)
            pathElements = re.split(r'\->',self.rawPath)
            self.pathRegexs = []
            self.rawPathSteps = []
            for node in pathElements:
                self.pathRegexs.append(re.compile(node))
                self.rawPathSteps.append(node)
    def getFirstPathStep(self):
        return(self.rawPathSteps[0])
    def getRegexPath(self):
        return(self.pathRegexs)
    def __str__(self):
        return("Line " + str(self.lineno) + ": " + self.rawPath + " " + 
               str(self.rawPattern) + " " + str(self.generators))
    def __repr__(self):
        return("Line " + str(self.lineno) + ":" + self.rawPath + " " +
               str(self.rawPattern) + " " + str(self.generators))
        
def checkReplacementRules():    
    genChars = re.compile("[\[\]\${}]+")
    for paths in replacements.values():
        for replacement in paths:    
            generators = replacement.getGenerators()
            for generator in generators:
                if not isinstance(generator, Generator):  # should be a string 
                    if genChars.match(generator):
                        print ("Warning: possible syntax error in generator line: " + replacement.getLineNo())     
  
# anonymizer config uses colons as delimiters. So allow user to delimit if needed using backslash              
def deslash(arr):
    for index in range(0,len(arr)):
        value = arr[index]
        value = value.replace('\\:',':')
        arr[index] = value
            
parser = argparse.ArgumentParser()
parser = argparse.ArgumentParser(description="Anonymize an XML file.")

parser.add_argument("-v", help="verbose", action="store_true")
parser.add_argument("-file", help="XML file to anonymize")
parser.add_argument("-anonymizedfile", help="XML anonymized output file")
parser.add_argument("-reversedfile", help="XML anonymized output file")
parser.add_argument("-reverse", help="Reverse anonymized values", action="store_true")
parser.add_argument("-values", help="Anonymized values DB", default="anonymized.txt")
parser.add_argument("-config", help="Anonymizer configuration", default="anonymizer.cfg")
parser.add_argument("-clean", help="Clear anonymized values", action="store_true")


args = parser.parse_args()
verbose = False
if (args.v):
    verbose = True

if (not args.clean):
    print ("Loading existing anonymization values " + args.values)
    if (args.values != None):
        values_file = Path(args.values)
        if values_file.is_file():
            loadAnonymizedItems(args.values)
else:
    print ("Removing existing anonymized values" + args.values)
    values_file = Path(args.values)
    if values_file.is_file():
        os.remove(args.values)  
    
if (args.file != None):
    print ("Anonymizing file " + args.file + " using config " + args.config)
    parseBuiltins(builtinPatterns, builtinGenerators)

    parseConfigFile(args.config, replacements)
    checkReplacementRules()

    tree = ET.parse(args.file) 
    
    loadAllCurrentValues(tree);
    
    anonymize(tree, replacements)
    literalReplace(tree, anonymizedSet)  # make sure we replace any items identified by anonymization rules
    
    print ("Writing anonymized file to " + args.anonymizedfile)
    tree.write(args.anonymizedfile)
    
    # Dump any values that were replaced along with any oneup counts for followon processing
    dumpAnonymizationData(args, anonymizedSet)

if (args.reverse):
    print ("Reversing anonymized file " + args.anonymizedfile )
    loadAnonymizedItems(args.values)
    tree = ET.parse(args.anonymizedfile)
    literalReplace(tree, reversalSet)
    print ('Writing reversed file to ' + args.reversedfile)
    tree.write(args.reversedfile)
