from burp import IBurpExtender
from burp import IContextMenuFactory
from java.util import List, ArrayList
from javax.swing import JMenuItem
import re
# Define the IBurpExtender class required by Burp Suite
class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # Set up the extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Extract URL Paths")
        
        # Register the context menu factory
        callbacks.registerContextMenuFactory(self)
        print("Extract URL Paths extension loaded successfully!")
    
    # Create the context menu item
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Extract URL Paths", actionPerformed=lambda x: self.extractPaths(invocation)))
        return menu_list
    
    # Function to extract URL paths from the selected response
    def extractPaths(self, invocation):
        # Get the selected HTTP messages
        context = invocation.getSelectedMessages()
        
        if context and len(context) > 0:
            for message in context:
                # Get the response from the message
                response = message.getResponse()
                if response:
                    # Convert response bytes to string
                    response_str = self._helpers.bytesToString(response)
                    
                    # Use regex to find URL paths (e.g., /path/to/resource)
                    # This matches paths starting with / followed by non-space characters
                    path_pattern = r'/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+/?'
                    paths = re.findall(path_pattern, response_str)
                    
                    # Remove duplicates by converting to a set
                    unique_paths = set(paths)
                    
                    # Output the results
                    if unique_paths:
                        print("Extracted URL Paths:")
                        for path in unique_paths:
                            print(path)
                    else:
                        print("No URL paths found in the response.")
                else:
                    print("No response available to analyze.")
        else:
            print("No message selected.")
# Required to run the extension in Burp Suite
if __name__ in ['__main__', 'BurpExtender']:
    BurpExtender()
