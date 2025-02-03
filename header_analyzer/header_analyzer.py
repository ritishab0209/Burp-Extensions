from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Header Analyzer")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            analyzed_response = self._helpers.analyzeResponse(response)
            headers = analyzed_response.getHeaders()
            
            # Check for missing security headers
            security_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
            missing_headers = [h for h in security_headers if not any(h in header for header in headers)]
            
            if missing_headers:
                print("[*] Missing security headers: " + ", ".join(missing_headers))
