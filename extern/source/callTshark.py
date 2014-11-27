import subprocess

class callTsharkClass():
    """
    Python Class to call Tshark commands for filtering a saved network traffic.
    The filterarguments are given by the user, which should be valid tshark
    display-filters.

    .. note::
       There must be at least one valid filterargument.

    """
    def __init__(self, params):
        """Initializes Object with params.

        :param params: Includes filter and fieldarguments for tshark.
        :type name: list.

        """
        self.dictLis = params
        self.fillup = []
        self.filters = []


    def setPathToFile(self, path):
        """
        Sets the Path to the Capture File which should be filtered.

        :param path: Path to the Capture File.
        :type path: str.

        """
        self.__captureFile = path


    def getPathToFile(self):
        """
        Returns the Path to the Capture File which should be filtered

        :returns: str -- Path to the Capture File

        """
        return self.__captureFile

    #@profile
    def iter_nested_dict(self, d):
        """
        Loops through nested dictionary and saves needed filters to create a
        valid tshark command.
        Basic code from: http://stackoverflow.com/questions/10756427/loop-through-all-nested-dictionary-values

        :param d: The dictionary through which should be looped.
        :type d: dict.

        """
        for k, v in d.iteritems():
            if isinstance(v, dict):
                self.iter_nested_dict(v)
            else:
                # checks if the field should be filled up or should be
                # a filter criteria
                if v == None:
                    self.fillup.append(k)
                else:
                    self.fillup.append(k)
                    self.filters.append(str(k) + ' {} '.format(v[0]) + str(v[1])) 


    #@profile
    def call_tshark(self):
        """
        Runs through each dictionary and calls the iter_nested_dict(d) to 
        get filterarguments for tshark. Calls tshark for filtering and creates
        a new list of dictionaries within the results.

        :returns: list -- The filled Dictionaries in a List
        
        """
        filedir = self.__captureFile
        length = len(self.dictLis)
        completeDictLis = [[None] for _ in range(length)]

        # Loop through each dictionary in the list and get the filterarguments
        # and fieldarguments
        i = 0
        while i < length:
            # First part of the tshark command, which is always the same
            tsharkCommand = ['tshark', '-r', str(filedir),
                            '-E' ,'separator=,', '-R']
            tsharkFilter = ''
            tsharkFields = []
            
            currDict = self.dictLis[i]
            completeDictLis[i][0] = currDict
            self.iter_nested_dict(currDict)

            # Generate tshark filter command
            for d in self.filters:
                tsharkFilter += d 
                if (d != self.filters[-1]):
                    tsharkFilter += ' and '

            # Generate tshark fields command
            for d in self.fillup:
                tsharkFields.append('-e')
                tsharkFields.append(d)

            # Fill up tshark-command-list with before generated filter and field
            # arguments
            tsharkCommand.append(str(tsharkFilter))
            tsharkCommand.append('-T')
            tsharkCommand.append('fields')
            for d in tsharkFields:
                tsharkCommand.append(str(d))
            
            print " ".join(tsharkCommand)

            # Run tshark and safe line seperated output in a variable
            tsharkProc = subprocess.check_output(tsharkCommand).splitlines()
            
            # Create new dictionary for each line in the output and append
            # the dictionary to the return-argument.
            for line in tsharkProc:
                value = line.split(',')
                createDict = {}
                j = 0
                for key in self.fillup:
                    createDict[str(key)] = value[j]
                    j += 1
                completeDictLis[i].append(createDict.copy())
                createDict.clear()

            # Clean up Lists for the next call
            self.filters[:] = []
            self.fillup[:] = []
            
            i += 1

        return completeDictLis


if __name__ == '__main__':
    
    def main():
        # imports only needed for measurement
        import timeit
        import psutil, os
        from memory_profiler import profile, memory_usage
        from pprint import pprint

        # List of dictionarys wich must contain valid tshark filtersarguments 
        # and at least one specific filter value
        params = [{"ip.dst": None, "tcp" : {"tcp.dstport": ("eq", 80), "tcp.len": ("neq", "0"), "tcp.len": None,
                  "http" : {"http.request.method": None,
                  "http.content_type": None, "http.request.full_uri": None, "http.host": None}}}]#,
                  {"tcp" : {"tcp.srcport": None, "tcp.dstport": 80, "http" : 
                  {"http.request.method": None,"http.content_type": None}}},
                  {"tcp" : {"tcp.srcport": "1024", "tcp.dstport": 80, "http" : 
				  {"http.request.method": None,"http.content-type": None}}},
				  {"udp": {"dns" : {"dns.qry.type": None,"dns.qry.name": None, 
				  "dns.flags.response": 1}}}]


        # Create instance of callTsharkClass
        ct = callTsharkClass(params)

        # Set the Path to the Capture File
        ct.setPathToFile("/home/icecold/Desktop/traffic.pcap")

        # let the magic happen
        result = ct.call_tshark()
        print "RESULT:\n"
        pprint (result)

        #memory_usage((ct.call_tshark))     # Measures Memory Usage per function

    # Following lines are used for time-measurements
    #time = timeit.Timer('main()', "from __main__ import main")
    #print "Minimal Durationtime out 100 repeatiions: " 
    #        + str(min(time.repeat(100, 1)))
    
    main()