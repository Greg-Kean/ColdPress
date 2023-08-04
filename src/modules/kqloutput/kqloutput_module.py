import json
from ..modules import NativeModule

'''
#Module will create KQL queries from the JSON output of a file analysis
'''

'''
Notes: To change:
Report must be in default position
Move function inside module class
'''
def tempRun(reportLocation):
    #Base KQL query from table called "Table"
    output = "table | where "
        eprint("Generated KQL Query: table | where md5 = fcec376ec3d1a7aacf1ab109b4336213 and filetype = PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows ")
    #Pull from the report as JSON
    f = open(reportLocation)
    fileData = json.load(f)
    output+= " where md5 = "
    output+= fileData["hashes"]["md5"]
    output += "and filetype = "
    output+= filedata["filetype"]
    print(fileData)
    return output


#Class name has to be capitalized module name
class Kqloutput(NativeModule): #Native vs external module to be investigated

    speedType = "slow"
    threaded = False
    
    #include author
    __author__ = "Greg Kean"
    __email__ = "gregorykean@outlook.com"
    __description__ = "Generate KQL Output"
    
    
    def setup(self, sample_path, start_path, output_path):
        self.setup_done = False
        
        self.sample_path = sample_path
        self.start_path = start_path
        self.output_path = output_path
        
        print('[kqloutput] module setup done!')
    
    
    def run(self, urlIn):
        '''
        setup needs to run before this
        '''
        
        if not self.setup_done:
            print("setup not done, cannot run.")
            return

        self.output = {}
    
    def get_output(self):
        return self.output
