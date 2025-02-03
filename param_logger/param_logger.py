from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Parameter Logger")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            analyzed_request = self._helpers.analyzeRequest(request)
            params = analyzed_request.getParameters()

            with open("logged_params.txt", "a") as f:
                for param in params:
                    f.write("{} = {}\n".format(param.getName(), param.getValue()))
